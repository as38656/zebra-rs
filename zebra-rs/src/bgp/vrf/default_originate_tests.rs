//! `default-originate` on the CE peers of a VRF task: the CE gets the
//! default when its session comes up and when a reconfigure adds the
//! statement, loses it when a reconfigure deletes it, and never gets a
//! default the VRF imports from the VPN while the statement is on. The
//! originated route never reaches the VRF Loc-RIB or the VPN.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpPacket, CapMultiProtocol, MpReachAttr,
    MpUnreachAttr, Origin, Safi,
};
use bytes::BytesMut;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::sync::mpsc::unbounded_channel;

use super::*;
use crate::bgp::default_originate::DefaultOriginateConfig;
use crate::bgp::peer::{Event, State};
use crate::bgp::vrf_config::BgpVrfNeighborConfig;
use crate::rib::client::{ProtoId, RibClient, RibInbound};

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const CE4: &str = "10.0.0.2";
const CE6: &str = "2001:db8:1e::2";

type Rx = tokio::sync::mpsc::UnboundedReceiver<BytesMut>;
type GlobalRx = tokio::sync::mpsc::UnboundedReceiver<BgpGlobalMsg>;

fn v4u() -> AfiSafi {
    AfiSafi::new(Afi::Ip, Safi::Unicast)
}

fn v6u() -> AfiSafi {
    AfiSafi::new(Afi::Ip6, Safi::Unicast)
}

fn ctx() -> ProtoContext {
    let (inbound_tx, inbound_rx) = unbounded_channel::<RibInbound>();
    Box::leak(Box::new(inbound_rx));
    let rib = RibClient::new(inbound_tx, ProtoId::from_raw(0));
    ProtoContext::for_vrf(rib, 61, "vrf-default".to_string())
}

fn vrf() -> (BgpVrf, GlobalRx) {
    let (global_tx, global_rx) = unbounded_channel::<BgpGlobalMsg>();
    let (rib_tx, rib_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(rib_tx));
    let (vrf, inbox) = BgpVrf::new(
        "vrf-default".to_string(),
        ctx(),
        ROUTER_ID,
        65000,
        16,
        global_tx,
        rib_rx,
    );
    Box::leak(Box::new(inbox));
    (vrf, global_rx)
}

/// The CE neighbor at `addr` as the global task resolves it for the VRF
/// task, with `default-originate` on `families`.
fn resolved(
    addr: &str,
    families: &[AfiSafi],
) -> (u32, crate::bgp::peer::PeerConfig, InheritableKnobs) {
    let mut nbr = BgpVrfNeighborConfig {
        remote_as: Some(65001),
        ..Default::default()
    };
    nbr.config.timer.min_adv_interval = Some(0);
    for afi_safi in families {
        nbr.config
            .sub
            .entry(*afi_safi)
            .or_default()
            .default_originate = Some(DefaultOriginateConfig::default());
    }
    let addr: IpAddr = addr.parse().unwrap();
    super::super::spawn::resolve_vrf_peer_config(&addr, &nbr, &BTreeMap::new()).unwrap()
}

/// Add the CE at `addr` (session from `local`) with `default-originate`
/// on `families`, in OpenConfirm until [`come_up`]. What it is sent comes
/// out of the receiver.
fn add_ce(vrf: &mut BgpVrf, addr: &str, local: &str, families: &[AfiSafi]) -> (usize, Rx) {
    let (remote_as, config, knobs) = resolved(addr, families);
    let ip: IpAddr = addr.parse().unwrap();
    vrf.process_global_msg(BgpVrfMsg::AddPeer {
        addr: ip,
        remote_as,
        config: Box::new(config),
        knobs: Box::new(knobs),
        policy_refs: BTreeMap::new(),
    });
    let (ptx, prx) = unbounded_channel();
    let peer = vrf.peers.get_mut(&ip).expect("CE added");
    peer.state = State::OpenConfirm;
    peer.primary_conn_id = Some(1);
    peer.as4 = true;
    peer.param.local_addr = Some(local.parse().unwrap());
    let family = if ip.is_ipv4() { v4u() } else { v6u() };
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&family.afi, &family.safi))
        .or_default();
    entry.send = true;
    entry.recv = true;
    peer.packet_tx = Some(ptx);
    (peer.ident, prx)
}

fn come_up(vrf: &mut BgpVrf, ident: usize) {
    vrf.process_msg(Message::Event(ident, Event::KeepAliveMsg(1)));
    assert_eq!(
        vrf.peers.get_by_idx(ident).unwrap().state,
        State::Established
    );
}

fn reconfigure(vrf: &mut BgpVrf, addr: &str, families: &[AfiSafi]) {
    let (remote_as, config, knobs) = resolved(addr, families);
    vrf.process_global_msg(BgpVrfMsg::ReconfigurePeer {
        addr: addr.parse().unwrap(),
        remote_as,
        config: Box::new(config),
        knobs: Box::new(knobs),
        policy_refs: BTreeMap::new(),
    });
}

/// Run the task's own messages, the advertise timers and their flushes,
/// until it is quiet.
async fn settle(vrf: &mut BgpVrf) {
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(300), vrf.rx.recv()).await
    {
        vrf.process_msg(msg);
    }
}

/// What the CE was told about the default route of its family: each
/// announcement as `(AS_PATH, next hop)`, and the number of withdrawals.
#[derive(Debug, Default)]
struct DefaultTold {
    announced: Vec<(String, IpAddr)>,
    withdrawn: usize,
    /// Whether the last thing said about it was a withdrawal.
    last_withdrawn: bool,
}

fn default_told(rx: &mut Rx) -> DefaultTold {
    let mut told = DefaultTold::default();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, true, None).expect("well formed");
        let BgpPacket::Update(update) = packet else {
            continue;
        };
        let path = update
            .bgp_attr
            .as_ref()
            .and_then(|a| a.aspath.as_ref())
            .map(|p| p.to_string())
            .unwrap_or_default();
        if update
            .ipv4_withdraw
            .iter()
            .any(|n| n.prefix == Ipv4Net::default())
            || matches!(&update.mp_withdraw, Some(MpUnreachAttr::Ipv6Nlri(nlris))
                if nlris.iter().any(|n| n.prefix == Ipv6Net::default()))
        {
            told.withdrawn += 1;
            told.last_withdrawn = true;
        }
        if update
            .ipv4_update
            .iter()
            .any(|n| n.prefix == Ipv4Net::default())
        {
            let Some(BgpNexthop::Ipv4(nhop)) = update.bgp_attr.as_ref().unwrap().nexthop else {
                panic!("an IPv4 next hop");
            };
            told.announced.push((path.clone(), IpAddr::V4(nhop)));
            told.last_withdrawn = false;
        }
        if let Some(MpReachAttr::Ipv6 { nhop, updates, .. }) = &update.mp_update
            && updates.iter().any(|n| n.prefix == Ipv6Net::default())
        {
            told.announced.push((path, *nhop));
            told.last_withdrawn = false;
        }
    }
    told
}

/// Every default route the VRF pushed to the global task for the VPN.
fn exported_defaults(global_rx: &mut GlobalRx) -> Vec<IpNet> {
    let mut out = Vec::new();
    while let Ok(msg) = global_rx.try_recv() {
        match msg {
            BgpGlobalMsg::Export { prefix, .. } | BgpGlobalMsg::WithdrawExport { prefix, .. }
                if prefix.prefix_len() == 0 =>
            {
                out.push(IpNet::V4(prefix))
            }
            BgpGlobalMsg::ExportV6 { prefix, .. }
            | BgpGlobalMsg::WithdrawExportV6 { prefix, .. }
                if prefix.prefix_len() == 0 =>
            {
                out.push(IpNet::V6(prefix))
            }
            _ => {}
        }
    }
    out
}

fn sent(vrf: &BgpVrf, ident: usize, afi: Afi) -> bool {
    vrf.peers
        .get_by_idx(ident)
        .unwrap()
        .default_originate
        .is_sent(afi)
}

/// A default route imported from the VPN, with the far CE's AS.
fn import_defaults(vrf: &mut BgpVrf) {
    let rd: bgp_packet::RouteDistinguisher = "65000:1".parse().unwrap();
    let attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from(vec![65010])),
        ..Default::default()
    };
    let transport = vec![crate::rib::nht::ResolvedNexthop {
        addr: "192.0.2.1".parse().unwrap(),
        ifindex: 2,
        labels: vec![100],
        segs: Vec::new(),
        seg_encap: None,
    }];
    vrf.handle_import_v4(
        rd,
        ImportSource::Vpn,
        Ipv4Net::default(),
        attr.clone(),
        100,
        &transport,
    );
    vrf.handle_import_v6(
        rd,
        ImportSource::Vpn,
        Ipv6Net::default(),
        attr,
        100,
        &transport,
    );
}

#[tokio::test]
async fn a_ce_gets_the_defaults_when_its_session_comes_up() {
    let (mut vrf, mut global_rx) = vrf();
    let (ce4, mut rx4) = add_ce(&mut vrf, CE4, "10.0.0.1:179", &[v4u()]);
    let (ce6, mut rx6) = add_ce(&mut vrf, CE6, "[2001:db8:1e::1]:179", &[v6u()]);
    come_up(&mut vrf, ce4);
    come_up(&mut vrf, ce6);
    settle(&mut vrf).await;

    let told = default_told(&mut rx4);
    assert_eq!(
        told.announced,
        vec![("65000".to_string(), "10.0.0.1".parse().unwrap())]
    );
    let told = default_told(&mut rx6);
    assert_eq!(
        told.announced,
        vec![("65000".to_string(), "2001:db8:1e::1".parse().unwrap())]
    );
    assert!(sent(&vrf, ce4, Afi::Ip));
    assert!(sent(&vrf, ce6, Afi::Ip6));
    assert!(vrf.shard.v4.candidates(Ipv4Net::default()).is_empty());
    assert!(vrf.shard.v6.candidates(Ipv6Net::default()).is_empty());
    assert_eq!(exported_defaults(&mut global_rx), Vec::<IpNet>::new());
}

#[tokio::test]
async fn a_reconfigure_adds_and_deletes_the_default() {
    let (mut vrf, mut global_rx) = vrf();
    let (ce4, mut rx4) = add_ce(&mut vrf, CE4, "10.0.0.1:179", &[]);
    let (ce6, mut rx6) = add_ce(&mut vrf, CE6, "[2001:db8:1e::1]:179", &[]);
    come_up(&mut vrf, ce4);
    come_up(&mut vrf, ce6);
    settle(&mut vrf).await;
    assert!(default_told(&mut rx4).announced.is_empty());
    assert!(default_told(&mut rx6).announced.is_empty());

    reconfigure(&mut vrf, CE4, &[v4u()]);
    reconfigure(&mut vrf, CE6, &[v6u()]);
    settle(&mut vrf).await;
    assert_eq!(default_told(&mut rx4).announced.len(), 1);
    assert_eq!(default_told(&mut rx6).announced.len(), 1);
    assert!(sent(&vrf, ce4, Afi::Ip) && sent(&vrf, ce6, Afi::Ip6));

    reconfigure(&mut vrf, CE4, &[]);
    reconfigure(&mut vrf, CE6, &[]);
    settle(&mut vrf).await;
    for rx in [&mut rx4, &mut rx6] {
        let told = default_told(rx);
        assert_eq!((told.withdrawn, told.announced.len()), (1, 0), "{told:?}");
    }
    assert!(!sent(&vrf, ce4, Afi::Ip) && !sent(&vrf, ce6, Afi::Ip6));
    for ident in [ce4, ce6] {
        assert_eq!(
            vrf.peers.get_by_idx(ident).unwrap().state,
            State::Established,
            "no session reset"
        );
    }
    assert_eq!(exported_defaults(&mut global_rx), Vec::<IpNet>::new());
}

/// The case the statement is for: the VRF holds a default from the VPN
/// (an Internet exit elsewhere). The CE gets only ours while the statement
/// is on, and the imported one once it is deleted.
#[tokio::test]
async fn an_imported_default_reaches_the_ce_only_after_the_delete() {
    let (mut vrf, _global_rx) = vrf();
    let (ce4, mut rx4) = add_ce(&mut vrf, CE4, "10.0.0.1:179", &[v4u()]);
    let (ce6, mut rx6) = add_ce(&mut vrf, CE6, "[2001:db8:1e::1]:179", &[v6u()]);
    come_up(&mut vrf, ce4);
    come_up(&mut vrf, ce6);
    import_defaults(&mut vrf);
    settle(&mut vrf).await;
    assert!(!vrf.shard.v4.candidates(Ipv4Net::default()).is_empty());
    for rx in [&mut rx4, &mut rx6] {
        let told = default_told(rx);
        let paths: Vec<&str> = told.announced.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, vec!["65000"], "ours only: {told:?}");
        assert_eq!(told.withdrawn, 0);
    }

    reconfigure(&mut vrf, CE4, &[]);
    reconfigure(&mut vrf, CE6, &[]);
    settle(&mut vrf).await;
    for rx in [&mut rx4, &mut rx6] {
        let told = default_told(rx);
        let paths: Vec<&str> = told.announced.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(paths, vec!["65000 65010"], "{told:?}");
        assert_eq!(told.withdrawn, 1, "{told:?}");
        assert!(!told.last_withdrawn, "the withdraw comes first: {told:?}");
    }
}
