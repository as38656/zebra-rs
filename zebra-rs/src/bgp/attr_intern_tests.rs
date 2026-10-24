//! Received path attributes are shared through the attribute store: the
//! prefixes of one UPDATE, and of later UPDATEs with the same attributes,
//! point at one `Arc<BgpAttr>` in the Adj-RIB-In and the Loc-RIB, and the
//! store forgets a set once no route uses it any more.

use super::*;
use crate::bgp::peer::{Peer, PeerType, State};
use crate::bgp::route::{route_clean, route_from_peer};
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, CapMultiProtocol, Ipv4Nlri, Origin, Safi,
    UpdatePacket,
};
use ipnet::Ipv4Net;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const V4: AfiSafi = AfiSafi {
    afi: Afi::Ip,
    safi: Safi::Unicast,
};

fn fresh_bgp() -> Bgp {
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let (_rib_rx_tx, rib_rx) = mpsc::unbounded_channel();
    let client =
        crate::rib::client::RibClient::new(inbound_tx, crate::rib::client::ProtoId::from_raw(0));
    Box::leak(Box::new(inbound_rx));
    let ctx = crate::context::ProtoContext::default_table(client);
    let (rib_tx, rib_out_rx) = mpsc::unbounded_channel();
    let (rib_inbound_tx, sub_inbound_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(rib_out_rx));
    Box::leak(Box::new(sub_inbound_rx));
    let subscriber = crate::config::RibSubscriber::for_test(
        rib_tx,
        rib_inbound_tx,
        std::sync::Arc::new(std::sync::atomic::AtomicU32::new(1)),
    );
    let (policy_tx, policy_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(policy_rx));
    let mut bgp = Bgp::new(
        ctx,
        rib_rx,
        subscriber,
        policy_tx,
        None,
        None,
        mpsc::channel(1).0,
    );
    bgp.router_id = ROUTER_ID;
    bgp
}

/// An Established peer with IPv4 unicast, in its update group: iBGP when
/// `asn` is our AS 65000, eBGP otherwise.
fn add_peer(bgp: &mut Bgp, addr: &str, asn: u32) -> usize {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = addr.parse().unwrap();
    let mut peer = Peer::new(
        0,
        65000,
        ROUTER_ID,
        asn,
        ip,
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = State::Established;
    peer.peer_type = if asn == 65000 {
        PeerType::IBGP
    } else {
        PeerType::EBGP
    };
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&V4.afi, &V4.safi))
        .or_default();
    entry.send = true;
    entry.recv = true;
    peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
    let (ptx, prx) = mpsc::unbounded_channel();
    Box::leak(Box::new(prx));
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    let id = bgp.peers.get(&ip).unwrap().ident;
    bgp.peers.membership_enroll(id);
    crate::bgp::update_group::attach(&mut bgp.update_groups, &mut bgp.peers, id, ROUTER_ID, false);
    id
}

fn split(bgp: &mut Bgp) -> (BgpTop<'_>, &mut PeerMap) {
    (
        BgpTop {
            router_id: &bgp.router_id,
            srv6_ipv6_export: None,
            local_rib: &mut bgp.local_rib,
            shard: &mut bgp.shard,
            tx: &bgp.tx,
            rib_client: &bgp.ctx.rib,
            attr_store: &mut bgp.attr_store,
            update_groups: &mut bgp.update_groups,
            interface_addrs: &bgp.interface_addrs,
            vrf_export: None,
            color_policy: None,
            flex_algo_routes: None,
            flex_algo_srv6_routes: None,
            vrf_import: None,
            nexthop_cache: None,
            vrf_transport_v4: None,
            vrf_transport_v6: None,
            as_sets_withdraw: bgp.as_sets_withdraw,
        },
        &mut bgp.peers,
    )
}

fn attr(first_as: &str, nexthop: &str) -> BgpAttr {
    BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from_str(first_as).unwrap()),
        nexthop: Some(BgpNexthop::Ipv4(nexthop.parse().unwrap())),
        ..Default::default()
    }
}

fn receive(bgp: &mut Bgp, ident: usize, attr: &BgpAttr, prefixes: &[&str]) {
    let mut packet = UpdatePacket::new();
    packet.bgp_attr = Some(attr.clone());
    packet.ipv4_update = prefixes
        .iter()
        .map(|p| Ipv4Nlri {
            id: 0,
            prefix: p.parse().unwrap(),
        })
        .collect();
    let (mut top, peers) = split(bgp);
    route_from_peer(ident, packet, &mut top, peers, None);
}

fn peer_down(bgp: &mut Bgp, ident: usize) {
    let (mut top, peers) = split(bgp);
    route_clean(ident, &mut top, peers, None);
}

fn adj_in_attr(bgp: &Bgp, ident: usize, prefix: &str) -> Arc<BgpAttr> {
    let prefix: Ipv4Net = prefix.parse().unwrap();
    bgp.shard.adj_in(ident).unwrap().v4.0[&prefix][0]
        .attr
        .clone()
}

fn loc_rib_attr(bgp: &Bgp, ident: usize, prefix: &str) -> Arc<BgpAttr> {
    let prefix: Ipv4Net = prefix.parse().unwrap();
    bgp.shard
        .v4
        .candidates(prefix)
        .iter()
        .find(|rib| rib.ident == ident)
        .unwrap()
        .attr
        .clone()
}

#[tokio::test]
async fn one_update_shares_one_attr_in_adj_rib_in_and_loc_rib() {
    let mut bgp = fresh_bgp();
    let a = add_peer(&mut bgp, "10.0.0.2", 65002);
    let sent = attr("65002 65100", "10.0.0.2");
    receive(&mut bgp, a, &sent, &["10.1.0.0/24", "10.1.1.0/24"]);

    let first = adj_in_attr(&bgp, a, "10.1.0.0/24");
    assert!(Arc::ptr_eq(&first, &adj_in_attr(&bgp, a, "10.1.1.0/24")));
    assert!(Arc::ptr_eq(&first, &loc_rib_attr(&bgp, a, "10.1.0.0/24")));
    assert!(Arc::ptr_eq(&first, &loc_rib_attr(&bgp, a, "10.1.1.0/24")));
    assert_eq!(bgp.shard.attr_store.len(), 1);

    // A later UPDATE with the same attributes shares the same set.
    receive(&mut bgp, a, &sent, &["10.1.2.0/24"]);
    assert!(Arc::ptr_eq(&first, &adj_in_attr(&bgp, a, "10.1.2.0/24")));
    assert_eq!(bgp.shard.attr_store.len(), 1);
}

#[tokio::test]
async fn peer_down_empties_the_attr_stores() {
    let mut bgp = fresh_bgp();
    let a = add_peer(&mut bgp, "10.0.0.2", 65002);
    let b = add_peer(&mut bgp, "10.0.0.3", 65003);
    receive(
        &mut bgp,
        a,
        &attr("65002 65100", "10.0.0.2"),
        &["10.1.0.0/24", "10.1.1.0/24"],
    );
    receive(
        &mut bgp,
        a,
        &attr("65002 65200", "10.0.0.2"),
        &["10.2.0.0/24"],
    );
    assert_eq!(bgp.shard.attr_store.len(), 2);

    peer_down(&mut bgp, a);
    assert_eq!(bgp.shard.attr_store.len(), 0);
    assert_eq!(bgp.attr_store.len(), 0);
    assert!(bgp.peers.get_by_idx(b).is_some());
}

#[tokio::test]
async fn peer_down_keeps_the_sets_other_peers_use() {
    let mut bgp = fresh_bgp();
    let a = add_peer(&mut bgp, "10.0.0.2", 65000);
    let b = add_peer(&mut bgp, "10.0.0.3", 65000);
    let shared = attr("65100", "10.0.0.100");
    receive(&mut bgp, a, &shared, &["10.1.0.0/24"]);
    receive(&mut bgp, b, &shared, &["10.1.0.0/24"]);
    receive(&mut bgp, a, &attr("65200", "10.0.0.2"), &["10.2.0.0/24"]);
    let kept = adj_in_attr(&bgp, b, "10.1.0.0/24");
    assert!(Arc::ptr_eq(&kept, &adj_in_attr(&bgp, a, "10.1.0.0/24")));

    peer_down(&mut bgp, a);
    assert_eq!(bgp.shard.attr_store.len(), 1);
    assert!(Arc::ptr_eq(&kept, &loc_rib_attr(&bgp, b, "10.1.0.0/24")));
    let again = attr("65100", "10.0.0.100");
    receive(&mut bgp, a, &again, &["10.3.0.0/24"]);
    assert!(Arc::ptr_eq(&kept, &adj_in_attr(&bgp, a, "10.3.0.0/24")));
}
