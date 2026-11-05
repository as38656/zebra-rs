//! `maximum-prefix` on the CE peer of a VRF task: the session closes over
//! the limit, `clear bgp vrf` brings the peer back, and a lower limit
//! from a runtime reconfigure closes the session at once.

use std::collections::BTreeMap;
use std::net::IpAddr;

use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpType, CapMultiProtocol, Ipv4Nlri,
    NotificationPacket, NotifyCode, Origin, Safi, UpdatePacket,
};
use bytes::BytesMut;
use tokio::sync::mpsc::unbounded_channel;

use super::*;
use crate::bgp::peer::{BgpClearOp, Event, PeerDownReason, State};
use crate::bgp::prefix_limit::PrefixLimitConfig;
use crate::bgp::vrf_config::BgpVrfNeighborConfig;
use crate::rib::client::{ProtoId, RibClient, RibInbound};

const CE: &str = "10.0.0.2";

type Rx = tokio::sync::mpsc::UnboundedReceiver<BytesMut>;

fn v4u() -> AfiSafi {
    AfiSafi::new(Afi::Ip, Safi::Unicast)
}

fn ctx() -> ProtoContext {
    let (inbound_tx, inbound_rx) = unbounded_channel::<RibInbound>();
    Box::leak(Box::new(inbound_rx));
    let rib = RibClient::new(inbound_tx, ProtoId::from_raw(0));
    ProtoContext::for_vrf(rib, 60, "vrf-pfxlimit".to_string())
}

/// The CE neighbor's config as the global task resolves it for the VRF
/// task, with `limit` on IPv4 unicast.
fn resolved(
    limit: Option<PrefixLimitConfig>,
) -> (u32, crate::bgp::peer::PeerConfig, InheritableKnobs) {
    let mut nbr = BgpVrfNeighborConfig {
        remote_as: Some(65001),
        ..Default::default()
    };
    if let Some(limit) = limit {
        nbr.config.sub.entry(v4u()).or_default().prefix_limit = limit;
    }
    let addr: IpAddr = CE.parse().unwrap();
    super::super::spawn::resolve_vrf_peer_config(&addr, &nbr, &BTreeMap::new()).unwrap()
}

/// A VRF task with one Established eBGP CE peer at [`CE`]. What the CE
/// is sent comes out of the receiver.
fn vrf_with_ce(limit: Option<PrefixLimitConfig>) -> (BgpVrf, usize, Rx) {
    let (global_tx, global_rx) = unbounded_channel::<BgpGlobalMsg>();
    Box::leak(Box::new(global_rx));
    let (rib_tx, rib_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(rib_tx));
    let (mut vrf, inbox) = BgpVrf::new(
        "vrf-pfxlimit".to_string(),
        ctx(),
        Ipv4Addr::new(10, 0, 0, 1),
        65000,
        16,
        global_tx,
        rib_rx,
    );
    Box::leak(Box::new(inbox));
    let (remote_as, config, knobs) = resolved(limit);
    let addr: IpAddr = CE.parse().unwrap();
    vrf.process_global_msg(BgpVrfMsg::AddPeer {
        addr,
        remote_as,
        config: Box::new(config),
        knobs: Box::new(knobs),
        policy_refs: BTreeMap::new(),
    });
    let (ptx, prx) = unbounded_channel();
    let peer = vrf.peers.get_mut(&addr).expect("CE added");
    peer.state = State::Established;
    peer.param.local_addr = Some("10.0.0.1:179".parse().unwrap());
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&Afi::Ip, &Safi::Unicast))
        .or_default();
    entry.send = true;
    entry.recv = true;
    peer.packet_tx = Some(ptx);
    let ident = peer.ident;
    vrf.peers.membership_enroll(ident);
    (vrf, ident, prx)
}

fn receive_v4(vrf: &mut BgpVrf, ident: usize, prefixes: &[&str]) {
    let mut update = UpdatePacket::new();
    update.bgp_attr = Some(BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from(vec![65001])),
        nexthop: Some(BgpNexthop::Ipv4(CE.parse().unwrap())),
        ..Default::default()
    });
    update.ipv4_update = prefixes
        .iter()
        .map(|p| Ipv4Nlri {
            id: 0,
            prefix: p.parse().unwrap(),
        })
        .collect();
    vrf.process_msg(Message::Event(ident, Event::UpdateMsg(update)));
}

fn state(vrf: &BgpVrf, ident: usize) -> State {
    vrf.peers.get_by_idx(ident).unwrap().state
}

/// The CE session was closed with Cease / Maximum Number of Prefixes
/// Reached for IPv4 unicast and `max`, and the peer is kept down.
fn assert_tripped(vrf: &BgpVrf, rx: &mut Rx, ident: usize, max: u32) {
    let peer = vrf.peers.get_by_idx(ident).unwrap();
    assert_eq!(peer.state, State::Idle);
    let mut sent = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        if bytes.get(18) == Some(&(BgpType::Notification as u8)) {
            sent.push(NotificationPacket::parse_packet(&bytes).unwrap().1);
        }
    }
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!((sent[0].code, sent[0].sub_code), (NotifyCode::Cease, 1));
    let mut data = vec![0, 1, 1];
    data.extend(max.to_be_bytes());
    assert_eq!(sent[0].data, data);
    assert_eq!(
        peer.last_reset.map(|(reason, _)| reason),
        Some(PeerDownReason::PrefixLimit)
    );
    assert!(peer.prefix_overflow.is_some());
}

#[tokio::test]
async fn a_ce_over_the_limit_closes_and_clear_bgp_vrf_brings_it_back() {
    let limit = PrefixLimitConfig {
        max: Some(2),
        ..Default::default()
    };
    let (mut vrf, ident, mut rx) = vrf_with_ce(Some(limit));
    receive_v4(&mut vrf, ident, &["10.9.0.0/24", "10.9.1.0/24"]);
    assert_eq!(state(&vrf, ident), State::Established);
    receive_v4(&mut vrf, ident, &["10.9.2.0/24"]);
    assert_tripped(&vrf, &mut rx, ident, 2);
    assert!(vrf.shard.v4.1.iter().next().is_none(), "routes withdrawn");

    vrf.process_global_msg(BgpVrfMsg::Clear {
        target: "192.0.2.1".to_string(),
        op: BgpClearOp::Hard,
    });
    assert!(
        vrf.peers
            .get_by_idx(ident)
            .unwrap()
            .prefix_overflow
            .is_some(),
        "another address is not this peer"
    );
    vrf.process_global_msg(BgpVrfMsg::Clear {
        target: CE.to_string(),
        op: BgpClearOp::Hard,
    });
    let peer = vrf.peers.get_by_idx(ident).unwrap();
    assert!(peer.prefix_overflow.is_none());
    assert!(peer.timer.idle_hold_timer.is_some(), "it dials again");
}

#[tokio::test]
async fn a_lower_limit_from_a_reconfigure_closes_the_ce_session_at_once() {
    let (mut vrf, ident, mut rx) = vrf_with_ce(None);
    receive_v4(
        &mut vrf,
        ident,
        &["10.9.0.0/24", "10.9.1.0/24", "10.9.2.0/24"],
    );
    assert_eq!(state(&vrf, ident), State::Established);

    let limit = PrefixLimitConfig {
        max: Some(2),
        ..Default::default()
    };
    let (remote_as, config, knobs) = resolved(Some(limit));
    vrf.process_global_msg(BgpVrfMsg::ReconfigurePeer {
        addr: CE.parse().unwrap(),
        remote_as,
        config: Box::new(config),
        knobs: Box::new(knobs),
        policy_refs: BTreeMap::new(),
    });
    assert_tripped(&vrf, &mut rx, ident, 2);
}
