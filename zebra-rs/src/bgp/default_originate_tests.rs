//! `afi-safi <ipv4|ipv6> default-originate` on a neighbor of the global
//! instance, through the FSM and the config callbacks: what the neighbor
//! is sent when the session comes up and when the statement is added or
//! deleted, how it meets a default in the Loc-RIB, and that no other
//! neighbor and no table ever gets the route.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpPacket, CapMultiProtocol, Direct, Ipv4Nlri,
    Ipv6Nlri, Med, MpReachAttr, MpUnreachAttr, Origin, ParseOption, RouteDistinguisher, Safi,
    UpdatePacket, Vpnv4Nexthop,
};
use bytes::BytesMut;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use tokio::sync::mpsc;

use super::*;
use crate::bgp::peer::{Peer, PeerType, State, apply_soft_out_peer};
use crate::bgp::policy::{EbgpRequiresPolicy, InOut};
use crate::bgp::route::{BgpRib, BgpRibType, VpnNexthop, route_update_ipv4};
use crate::bgp::update_group::signature_of;
use crate::rib::nht::NexthopResolution;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const LOCAL_AS: u32 = 65000;

/// A neighbor: address, AS, and the local end of its session.
type Neighbor = (&'static str, u32, &'static str);
/// The eBGP neighbor the tests configure.
const CE: Neighbor = ("10.0.0.2", 65002, "10.0.0.99:179");
/// The same over IPv6 transport, so that IPv6 has a next hop self.
const CE6: Neighbor = ("2001:db8::2", 65002, "[2001:db8::99]:179");
/// A second eBGP neighbor, without the statement.
const OTHER: Neighbor = ("10.0.0.4", 65004, "10.0.0.99:179");
/// The neighbor that puts a default route in the Loc-RIB.
const SOURCE: Neighbor = ("10.0.0.3", 65003, "10.0.0.99:179");
const IBGP: Neighbor = ("10.0.0.5", LOCAL_AS, "10.0.0.99:179");

type Rx = mpsc::UnboundedReceiver<BytesMut>;

fn v4u() -> AfiSafi {
    AfiSafi::new(Afi::Ip, Safi::Unicast)
}

fn v6u() -> AfiSafi {
    AfiSafi::new(Afi::Ip6, Safi::Unicast)
}

fn default4() -> IpNet {
    IpNet::V4(Ipv4Net::default())
}

fn default6() -> IpNet {
    IpNet::V6(Ipv6Net::default())
}

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
    bgp.asn = LOCAL_AS;
    bgp.router_id = ROUTER_ID;
    bgp
}

/// `neighbor` with IPv4 and IPv6 unicast negotiated and no MRAI, in
/// OpenConfirm until [`come_up`]. What it is sent comes out of the
/// receiver.
fn add_peer(bgp: &mut Bgp, (addr, remote_as, local): Neighbor) -> (usize, Rx) {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = addr.parse().unwrap();
    let mut peer = Peer::new(
        0,
        LOCAL_AS,
        ROUTER_ID,
        remote_as,
        ip,
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = State::OpenConfirm;
    peer.primary_conn_id = Some(1);
    peer.peer_type = if remote_as == LOCAL_AS {
        PeerType::IBGP
    } else {
        PeerType::EBGP
    };
    peer.first_start = false;
    peer.as4 = true;
    peer.param.local_addr = Some(local.parse().unwrap());
    peer.config.timer.min_adv_interval = Some(0);
    for afi_safi in [v4u(), v6u()] {
        let entry = peer
            .cap_map
            .entries
            .entry(CapMultiProtocol::new(&afi_safi.afi, &afi_safi.safi))
            .or_default();
        entry.send = true;
        entry.recv = true;
    }
    let (ptx, prx) = mpsc::unbounded_channel();
    peer.packet_tx = Some(ptx);
    bgp.peers.insert(ip, peer);
    (bgp.peers.get(&ip).unwrap().ident, prx)
}

/// The OPEN exchange of `id` completes: the session is Established and
/// the session-up dump runs.
fn come_up(bgp: &mut Bgp, id: usize) {
    bgp.process_msg(Message::Event(id, Event::KeepAliveMsg(1)));
    assert_eq!(peer(bgp, id).state, State::Established);
}

fn peer(bgp: &Bgp, id: usize) -> &Peer {
    bgp.peers.get_by_idx(id).unwrap()
}

fn peer_mut(bgp: &mut Bgp, id: usize) -> &mut Peer {
    bgp.peers.get_mut_by_idx(id).unwrap()
}

/// `afi-safi <family> default-originate` on the neighbor at `addr`, set
/// or deleted, through its config callback.
fn knob(bgp: &mut Bgp, addr: &str, family: &str, op: ConfigOp) {
    let cb = *bgp
        .callbacks
        .get("/router/bgp/neighbor/afi-safi/default-originate")
        .expect("callback registered");
    let args = [addr, family].iter().map(|w| w.to_string()).collect();
    cb(bgp, crate::config::Args(args), op);
}

fn commit_end(bgp: &mut Bgp) {
    bgp.process_cm_msg(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));
}

/// Run the instance's own messages, the advertise timers and their
/// flushes, until it is quiet.
async fn settle(bgp: &mut Bgp) {
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(300), bgp.rx.recv()).await
    {
        bgp.process_msg(msg);
    }
}

/// `SOURCE` sends a default route of both families and 10.9.0.0/24, and
/// the RIB resolves their next hops.
fn source_sends_defaults(bgp: &mut Bgp, id: usize) {
    let attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from(vec![SOURCE.1])),
        nexthop: Some(BgpNexthop::Ipv4(SOURCE.0.parse().unwrap())),
        ..Default::default()
    };
    let mut v4 = UpdatePacket::new();
    v4.bgp_attr = Some(attr.clone());
    v4.ipv4_update = ["0.0.0.0/0", "10.9.0.0/24"]
        .iter()
        .map(|p| Ipv4Nlri {
            id: 0,
            prefix: p.parse().unwrap(),
        })
        .collect();
    bgp.process_msg(Message::Event(id, Event::UpdateMsg(v4)));
    let mut v6 = UpdatePacket::new();
    v6.bgp_attr = Some(attr);
    v6.mp_update = Some(MpReachAttr::Ipv6 {
        snpa: 0,
        nhop: "2001:db8::3".parse().unwrap(),
        updates: vec![Ipv6Nlri {
            id: 0,
            prefix: Ipv6Net::default(),
        }],
    });
    bgp.process_msg(Message::Event(id, Event::UpdateMsg(v6)));
    for nh in [SOURCE.0, "2001:db8::3"] {
        let resolution = NexthopResolution {
            reachable: true,
            metric: 0,
            nexthops: Vec::new(),
        };
        bgp.nht_handle_update(0, nh.parse().unwrap(), &resolution);
    }
}

/// `SOURCE` withdraws its default routes.
fn source_withdraws_defaults(bgp: &mut Bgp, id: usize) {
    let mut v4 = UpdatePacket::new();
    v4.ipv4_withdraw = vec![Ipv4Nlri {
        id: 0,
        prefix: Ipv4Net::default(),
    }];
    bgp.process_msg(Message::Event(id, Event::UpdateMsg(v4)));
    let mut v6 = UpdatePacket::new();
    v6.mp_withdraw = Some(MpUnreachAttr::Ipv6Nlri(vec![Ipv6Nlri {
        id: 0,
        prefix: Ipv6Net::default(),
    }]));
    bgp.process_msg(Message::Event(id, Event::UpdateMsg(v6)));
}

/// One thing a neighbor was told, in the order it was told.
#[derive(Debug, Clone, PartialEq)]
enum Told {
    /// A route, its attributes, and the MP_REACH next hop of IPv6.
    Reach(IpNet, BgpAttr, Option<IpAddr>),
    Unreach(IpNet),
    EndOfRib(Afi),
}

/// Every UPDATE on `rx`, read as the neighbor reads it.
fn told(rx: &mut Rx) -> Vec<Told> {
    told_with(rx, ParseOption::default())
}

fn told_with(rx: &mut Rx, opt: ParseOption) -> Vec<Told> {
    let mut out = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        let (_, packet) = BgpPacket::parse_packet(&bytes, true, Some(opt.clone()))
            .expect("a well-formed message");
        let BgpPacket::Update(update) = packet else {
            continue;
        };
        let attr = update.bgp_attr.clone().unwrap_or_default();
        for nlri in &update.ipv4_withdraw {
            out.push(Told::Unreach(IpNet::V4(nlri.prefix)));
        }
        match &update.mp_withdraw {
            Some(MpUnreachAttr::Ipv6Nlri(nlris)) => {
                out.extend(nlris.iter().map(|n| Told::Unreach(IpNet::V6(n.prefix))));
            }
            Some(MpUnreachAttr::Ipv6Eor) => out.push(Told::EndOfRib(Afi::Ip6)),
            _ => {}
        }
        for nlri in &update.ipv4_update {
            out.push(Told::Reach(IpNet::V4(nlri.prefix), attr.clone(), None));
        }
        if let Some(MpReachAttr::Ipv6 { nhop, updates, .. }) = &update.mp_update {
            for nlri in updates {
                out.push(Told::Reach(
                    IpNet::V6(nlri.prefix),
                    attr.clone(),
                    Some(*nhop),
                ));
            }
        }
        if update.ipv4_update.is_empty()
            && update.ipv4_withdraw.is_empty()
            && update.mp_update.is_none()
            && update.mp_withdraw.is_none()
        {
            out.push(Told::EndOfRib(Afi::Ip));
        }
    }
    out
}

/// The announcements of `prefix` among `told`.
fn reach(told: &[Told], prefix: IpNet) -> Vec<(BgpAttr, Option<IpAddr>)> {
    told.iter()
        .filter_map(|t| match t {
            Told::Reach(p, attr, nhop) if *p == prefix => Some((attr.clone(), *nhop)),
            _ => None,
        })
        .collect()
}

fn unreach(told: &[Told], prefix: IpNet) -> usize {
    told.iter()
        .filter(|t| matches!(t, Told::Unreach(p) if *p == prefix))
        .count()
}

fn path(attr: &BgpAttr) -> String {
    attr.aspath
        .as_ref()
        .map(|p| p.to_string())
        .unwrap_or_default()
}

/// The originated default as an external neighbor reads it: ORIGIN IGP,
/// our AS alone in the AS_PATH, MED 0, and no community, Prefix-SID or
/// LOCAL_PREF.
fn assert_originated_external(attr: &BgpAttr) {
    assert_eq!(attr.origin, Some(Origin::Igp));
    assert_eq!(path(attr), LOCAL_AS.to_string());
    assert_eq!(attr.med, Some(Med { med: 0 }));
    assert_eq!(attr.local_pref, None);
    assert_eq!(attr.com, None);
    assert_eq!(attr.ecom, None);
    assert_eq!(attr.lcom, None);
    assert_eq!(attr.prefix_sid, None);
}

fn assert_default_not_in_loc_rib(bgp: &Bgp) {
    assert!(bgp.shard.v4.candidates(Ipv4Net::default()).is_empty());
    assert!(bgp.shard.v6.candidates(Ipv6Net::default()).is_empty());
}

/// An outbound policy that denies every route of `afi_safi`.
fn deny_all_out(bgp: &mut Bgp, id: usize, afi_safi: AfiSafi) {
    let mut list = crate::policy::PolicyList::default();
    list.entry(10).action = crate::policy::PolicyAction::Deny;
    let peer = peer_mut(bgp, id);
    let slot = peer.policy_list_slot(afi_safi, InOut::Output);
    slot.name = Some("DENY-ALL".into());
    slot.policy_list = Some(list);
    peer.rebuild_out_policy();
}

// --- session up ---------------------------------------------------------

#[tokio::test]
async fn ipv4_default_is_sent_when_the_session_comes_up() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, CE);
    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Set);
    come_up(&mut bgp, id);

    let told = told(&mut rx);
    let sent = reach(&told, default4());
    assert_eq!(sent.len(), 1, "{told:?}");
    let (attr, _) = &sent[0];
    assert_originated_external(attr);
    assert_eq!(
        attr.nexthop,
        Some(BgpNexthop::Ipv4("10.0.0.99".parse().unwrap())),
        "next hop self"
    );
    let at = |want: &Told| told.iter().position(|t| t == want);
    assert!(
        told.iter()
            .position(|t| matches!(t, Told::Reach(p, ..) if *p == default4()))
            < at(&Told::EndOfRib(Afi::Ip)),
        "the default comes before End-of-RIB: {told:?}"
    );
    assert!(reach(&told, default6()).is_empty(), "ipv6 has no statement");
    assert!(peer(&bgp, id).default_originate.is_sent(Afi::Ip));
    assert!(!peer(&bgp, id).default_originate.is_sent(Afi::Ip6));
    assert_default_not_in_loc_rib(&bgp);
}

#[tokio::test]
async fn ipv6_default_is_sent_when_the_session_comes_up() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, CE6);
    knob(&mut bgp, CE6.0, "ipv6", ConfigOp::Set);
    come_up(&mut bgp, id);

    let told = told(&mut rx);
    let sent = reach(&told, default6());
    assert_eq!(sent.len(), 1, "{told:?}");
    let (attr, nhop) = &sent[0];
    assert_originated_external(attr);
    assert_eq!(
        *nhop,
        Some("2001:db8::99".parse().unwrap()),
        "next hop self"
    );
    assert!(reach(&told, default4()).is_empty(), "ipv4 has no statement");
    assert!(peer(&bgp, id).default_originate.is_sent(Afi::Ip6));
    assert_default_not_in_loc_rib(&bgp);
}

#[tokio::test]
async fn an_internal_neighbor_gets_local_pref_and_no_prepend() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, IBGP);
    knob(&mut bgp, IBGP.0, "ipv4", ConfigOp::Set);
    come_up(&mut bgp, id);

    let told = told(&mut rx);
    let sent = reach(&told, default4());
    assert_eq!(sent.len(), 1, "{told:?}");
    let (attr, _) = &sent[0];
    assert_eq!(path(attr), "");
    assert_eq!(attr.local_pref.as_ref().map(|l| l.local_pref), Some(100));
    assert_eq!(
        attr.nexthop,
        Some(BgpNexthop::Ipv4("10.0.0.99".parse().unwrap()))
    );
}

/// RFC 7911: toward an AddPath neighbor the route carries FRR's path
/// identifier for the originated default.
#[tokio::test]
async fn an_addpath_neighbor_gets_path_id_1() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, CE);
    peer_mut(&mut bgp, id).opt.add_path.insert(
        v4u(),
        Direct {
            send: true,
            recv: false,
        },
    );
    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Set);
    come_up(&mut bgp, id);

    let mut opt = ParseOption::default();
    opt.add_path.insert(
        v4u(),
        Direct {
            send: false,
            recv: true,
        },
    );
    let mut ids = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        if let (_, BgpPacket::Update(update)) =
            BgpPacket::parse_packet(&bytes, true, Some(opt.clone())).unwrap()
        {
            ids.extend(
                update
                    .ipv4_update
                    .iter()
                    .filter(|n| n.prefix == Ipv4Net::default())
                    .map(|n| n.id),
            );
        }
    }
    assert_eq!(ids, vec![1]);
}

/// The route is not a Loc-RIB row: the table, and a second neighbor, never
/// see it.
#[tokio::test]
async fn no_other_neighbor_and_no_table_gets_the_default() {
    let mut bgp = fresh_bgp();
    let (ce, _ce_rx) = add_peer(&mut bgp, CE);
    let (other, mut other_rx) = add_peer(&mut bgp, OTHER);
    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Set);
    knob(&mut bgp, CE.0, "ipv6", ConfigOp::Set);
    come_up(&mut bgp, ce);
    come_up(&mut bgp, other);
    settle(&mut bgp).await;

    let told = told(&mut other_rx);
    assert!(reach(&told, default4()).is_empty(), "{told:?}");
    assert!(reach(&told, default6()).is_empty(), "{told:?}");
    assert_default_not_in_loc_rib(&bgp);
}

// --- the statement at run time ------------------------------------------

#[tokio::test]
async fn adding_the_statement_sends_the_default_at_commit_end() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, CE);
    come_up(&mut bgp, id);
    told(&mut rx);

    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Set);
    assert!(
        reach(&told(&mut rx), default4()).is_empty(),
        "not before CommitEnd"
    );
    commit_end(&mut bgp);
    let told = told(&mut rx);
    let sent = reach(&told, default4());
    assert_eq!(sent.len(), 1, "{told:?}");
    assert_originated_external(&sent[0].0);
    assert!(peer(&bgp, id).default_originate.is_sent(Afi::Ip));
    assert!(
        peer(&bgp, id).config.sub[&v4u()]
            .default_originate
            .is_some(),
        "the statement reaches the peer config"
    );
}

#[tokio::test]
async fn deleting_the_statement_withdraws_the_ipv4_default() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, CE);
    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Set);
    come_up(&mut bgp, id);
    told(&mut rx);

    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Delete);
    commit_end(&mut bgp);
    let told = told(&mut rx);
    assert_eq!(unreach(&told, default4()), 1, "{told:?}");
    assert!(reach(&told, default4()).is_empty(), "{told:?}");
    assert!(!peer(&bgp, id).default_originate.is_sent(Afi::Ip));
    assert!(
        peer(&bgp, id).config.sub[&v4u()]
            .default_originate
            .is_none()
    );

    // Nothing is held, so nothing more is withdrawn.
    apply_soft_out_peer(&mut bgp, id);
    assert_eq!(unreach(&self::told(&mut rx), default4()), 0);
}

#[tokio::test]
async fn deleting_the_statement_withdraws_the_ipv6_default() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, CE6);
    knob(&mut bgp, CE6.0, "ipv6", ConfigOp::Set);
    come_up(&mut bgp, id);
    told(&mut rx);

    knob(&mut bgp, CE6.0, "ipv6", ConfigOp::Delete);
    commit_end(&mut bgp);
    let told = told(&mut rx);
    assert_eq!(unreach(&told, default6()), 1, "{told:?}");
    assert!(reach(&told, default6()).is_empty(), "{told:?}");
    assert!(!peer(&bgp, id).default_originate.is_sent(Afi::Ip6));

    apply_soft_out_peer(&mut bgp, id);
    assert_eq!(unreach(&self::told(&mut rx), default6()), 0);
}

/// A soft-out (`clear bgp … soft out`, a route refresh) sends every route
/// again, the default too, and withdraws nothing.
#[tokio::test]
async fn a_soft_out_sends_the_default_again() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, CE);
    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Set);
    come_up(&mut bgp, id);
    told(&mut rx);

    apply_soft_out_peer(&mut bgp, id);
    let told = told(&mut rx);
    assert_eq!(reach(&told, default4()).len(), 1, "{told:?}");
    assert_eq!(unreach(&told, default4()), 0, "{told:?}");
}

/// The session ends: nothing is held any more.
#[tokio::test]
async fn the_session_end_clears_what_was_sent() {
    let mut bgp = fresh_bgp();
    let (id, _rx) = add_peer(&mut bgp, CE);
    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Set);
    come_up(&mut bgp, id);
    assert!(peer(&bgp, id).default_originate.is_sent(Afi::Ip));
    bgp.process_msg(Message::Event(id, Event::Stop));
    assert!(!peer(&bgp, id).state.is_established());
    assert!(!peer(&bgp, id).default_originate.is_sent(Afi::Ip));
}

// --- a default route in the Loc-RIB ---------------------------------------

/// While the statement is on, the neighbor gets only the originated
/// default; a Loc-RIB default coming and going does not reach it.
#[tokio::test]
async fn a_loc_rib_default_is_not_sent_while_the_statement_is_on() {
    let mut bgp = fresh_bgp();
    let (source, _source_rx) = add_peer(&mut bgp, SOURCE);
    let (ce, mut ce_rx) = add_peer(&mut bgp, CE6);
    let (other, mut other_rx) = add_peer(&mut bgp, OTHER);
    knob(&mut bgp, CE6.0, "ipv4", ConfigOp::Set);
    knob(&mut bgp, CE6.0, "ipv6", ConfigOp::Set);
    for id in [source, ce, other] {
        come_up(&mut bgp, id);
    }
    told(&mut ce_rx);
    told(&mut other_rx);

    source_sends_defaults(&mut bgp, source);
    settle(&mut bgp).await;
    let to_ce = told(&mut ce_rx);
    assert!(reach(&to_ce, default4()).is_empty(), "{to_ce:?}");
    assert!(reach(&to_ce, default6()).is_empty(), "{to_ce:?}");
    assert_eq!(
        reach(&to_ce, "10.9.0.0/24".parse().unwrap()).len(),
        1,
        "other routes still go: {to_ce:?}"
    );
    let to_other = told(&mut other_rx);
    assert_eq!(
        reach(&to_other, default4())
            .iter()
            .map(|(attr, _)| path(attr))
            .collect::<Vec<_>>(),
        vec!["65000 65003".to_string()],
        "a neighbor without the statement gets the Loc-RIB default"
    );

    source_withdraws_defaults(&mut bgp, source);
    settle(&mut bgp).await;
    let to_ce = told(&mut ce_rx);
    assert_eq!(unreach(&to_ce, default4()), 0, "{to_ce:?}");
    assert_eq!(unreach(&to_ce, default6()), 0, "{to_ce:?}");
    assert!(peer(&bgp, ce).default_originate.is_sent(Afi::Ip));
    assert!(peer(&bgp, ce).default_originate.is_sent(Afi::Ip6));
}

/// FRR order: deleting the statement withdraws the originated default,
/// then sends the Loc-RIB default the outbound policy permits.
#[tokio::test]
async fn after_the_delete_the_loc_rib_default_is_sent() {
    let mut bgp = fresh_bgp();
    let (source, _source_rx) = add_peer(&mut bgp, SOURCE);
    let (ce, mut ce_rx) = add_peer(&mut bgp, CE6);
    knob(&mut bgp, CE6.0, "ipv4", ConfigOp::Set);
    knob(&mut bgp, CE6.0, "ipv6", ConfigOp::Set);
    come_up(&mut bgp, source);
    source_sends_defaults(&mut bgp, source);
    come_up(&mut bgp, ce);
    settle(&mut bgp).await;
    let sent = told(&mut ce_rx);
    for prefix in [default4(), default6()] {
        let paths: Vec<String> = reach(&sent, prefix).iter().map(|(a, _)| path(a)).collect();
        assert_eq!(paths, vec!["65000".to_string()], "{prefix}: {sent:?}");
    }

    knob(&mut bgp, CE6.0, "ipv4", ConfigOp::Delete);
    knob(&mut bgp, CE6.0, "ipv6", ConfigOp::Delete);
    commit_end(&mut bgp);
    settle(&mut bgp).await;
    let told = told(&mut ce_rx);
    for prefix in [default4(), default6()] {
        let withdraw = told
            .iter()
            .position(|t| matches!(t, Told::Unreach(p) if *p == prefix));
        let announce = told
            .iter()
            .position(|t| matches!(t, Told::Reach(p, ..) if *p == prefix));
        assert!(
            withdraw.is_some() && withdraw < announce,
            "{prefix}: {told:?}"
        );
        let paths: Vec<String> = reach(&told, prefix).iter().map(|(a, _)| path(a)).collect();
        assert_eq!(paths, vec!["65000 65003".to_string()], "{prefix}");
    }
    assert!(!peer(&bgp, ce).default_originate.is_sent(Afi::Ip));
}

/// Adding the statement while the neighbor holds the Loc-RIB default: the
/// originated route replaces it in one UPDATE, and the Loc-RIB row is no
/// longer withdrawn from it later.
#[tokio::test]
async fn adding_the_statement_replaces_an_advertised_loc_rib_default() {
    let mut bgp = fresh_bgp();
    let (source, _source_rx) = add_peer(&mut bgp, SOURCE);
    let (ce, mut ce_rx) = add_peer(&mut bgp, CE6);
    come_up(&mut bgp, source);
    source_sends_defaults(&mut bgp, source);
    come_up(&mut bgp, ce);
    settle(&mut bgp).await;
    let sent = told(&mut ce_rx);
    assert_eq!(reach(&sent, default4()).len(), 1, "{sent:?}");
    assert_eq!(reach(&sent, default6()).len(), 1, "{sent:?}");

    knob(&mut bgp, CE6.0, "ipv4", ConfigOp::Set);
    knob(&mut bgp, CE6.0, "ipv6", ConfigOp::Set);
    commit_end(&mut bgp);
    settle(&mut bgp).await;
    let told = told(&mut ce_rx);
    for prefix in [default4(), default6()] {
        assert_eq!(unreach(&told, prefix), 0, "{prefix}: {told:?}");
        let paths: Vec<String> = reach(&told, prefix).iter().map(|(a, _)| path(a)).collect();
        assert_eq!(paths, vec!["65000".to_string()], "{prefix}: {told:?}");
    }
    let adj_out = &peer(&bgp, ce).adj_out;
    assert!(!adj_out.v4.0.contains_key(&Ipv4Net::default()));
    assert!(!adj_out.v6.0.contains_key(&Ipv6Net::default()));

    source_withdraws_defaults(&mut bgp, source);
    settle(&mut bgp).await;
    apply_soft_out_peer(&mut bgp, ce);
    let told = self::told(&mut ce_rx);
    assert_eq!(unreach(&told, default4()), 0, "{told:?}");
    assert_eq!(unreach(&told, default6()), 0, "{told:?}");
}

// --- outbound policy and RFC 8212 -------------------------------------------

/// FRR: ebgp-requires-policy does not hold the originated default back.
#[tokio::test]
async fn rfc8212_without_an_outbound_policy_still_sends_the_default() {
    let mut bgp = fresh_bgp();
    let (source, _source_rx) = add_peer(&mut bgp, SOURCE);
    let (ce, mut ce_rx) = add_peer(&mut bgp, CE6);
    peer_mut(&mut bgp, ce).ebgp_requires_policy = EbgpRequiresPolicy(true);
    knob(&mut bgp, CE6.0, "ipv4", ConfigOp::Set);
    knob(&mut bgp, CE6.0, "ipv6", ConfigOp::Set);
    come_up(&mut bgp, source);
    source_sends_defaults(&mut bgp, source);
    come_up(&mut bgp, ce);
    settle(&mut bgp).await;

    let told = told(&mut ce_rx);
    assert_eq!(reach(&told, default4()).len(), 1, "{told:?}");
    assert_eq!(reach(&told, default6()).len(), 1, "{told:?}");
    assert!(
        reach(&told, "10.9.0.0/24".parse().unwrap()).is_empty(),
        "no policy, so nothing else goes"
    );
}

/// FRR: the outbound policy is not run on the originated default, so a
/// policy that denies 0.0.0.0/0 does not stop it; after the delete the
/// Loc-RIB default stays denied.
#[tokio::test]
async fn an_outbound_policy_that_denies_the_default_does_not_stop_it() {
    let mut bgp = fresh_bgp();
    let (source, _source_rx) = add_peer(&mut bgp, SOURCE);
    let (ce, mut ce_rx) = add_peer(&mut bgp, CE6);
    deny_all_out(&mut bgp, ce, v4u());
    deny_all_out(&mut bgp, ce, v6u());
    knob(&mut bgp, CE6.0, "ipv4", ConfigOp::Set);
    knob(&mut bgp, CE6.0, "ipv6", ConfigOp::Set);
    come_up(&mut bgp, source);
    source_sends_defaults(&mut bgp, source);
    come_up(&mut bgp, ce);
    settle(&mut bgp).await;
    let told = told(&mut ce_rx);
    assert_eq!(reach(&told, default4()).len(), 1, "{told:?}");
    assert_eq!(reach(&told, default6()).len(), 1, "{told:?}");
    assert!(reach(&told, "10.9.0.0/24".parse().unwrap()).is_empty());

    knob(&mut bgp, CE6.0, "ipv4", ConfigOp::Delete);
    knob(&mut bgp, CE6.0, "ipv6", ConfigOp::Delete);
    commit_end(&mut bgp);
    settle(&mut bgp).await;
    let told = self::told(&mut ce_rx);
    for prefix in [default4(), default6()] {
        assert_eq!(unreach(&told, prefix), 1, "{prefix}: {told:?}");
        assert!(reach(&told, prefix).is_empty(), "{prefix}: {told:?}");
    }
}

// --- the egress builder and update groups -------------------------------------

/// Only a plain unicast default row is kept back; a VPN row of 0.0.0.0/0
/// and other prefixes still go.
#[tokio::test]
async fn only_the_plain_unicast_default_row_is_kept_back() {
    let mut bgp = fresh_bgp();
    let (id, _rx) = add_peer(&mut bgp, CE);
    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Set);
    let ctx = peer(&bgp, id).sync_ctx(ROUTER_ID, false);
    let attr = BgpAttr {
        nexthop: Some(BgpNexthop::Ipv4("10.0.0.7".parse().unwrap())),
        ..Default::default()
    };
    let row = BgpRib::new(
        99,
        "10.0.0.7".parse().unwrap(),
        BgpRibType::EBGP,
        0,
        0,
        &attr,
        None,
        None,
        false,
    );
    assert!(route_update_ipv4(&ctx, &Ipv4Net::default(), &row, false).is_none());
    assert!(route_update_ipv4(&ctx, &"10.9.0.0/24".parse().unwrap(), &row, false).is_some());
    let mut vpn = row.clone();
    vpn.nexthop = Some(VpnNexthop::V4(Vpnv4Nexthop {
        rd: RouteDistinguisher::default(),
        nhop: "10.0.0.7".parse().unwrap(),
    }));
    assert!(route_update_ipv4(&ctx, &Ipv4Net::default(), &vpn, false).is_some());
}

/// The statement changes what a family sends, so a neighbor with it and
/// one without never share UPDATEs of that family.
#[tokio::test]
async fn the_statement_splits_the_update_groups_of_its_family() {
    let mut bgp = fresh_bgp();
    let (ce, _ce_rx) = add_peer(&mut bgp, CE);
    let (other, _other_rx) = add_peer(&mut bgp, ("10.0.0.6", CE.1, CE.2));
    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Set);
    let sig = |bgp: &Bgp, id: usize, afi_safi: AfiSafi| {
        signature_of(peer(bgp, id), afi_safi.afi, afi_safi.safi).unwrap()
    };
    assert_ne!(sig(&bgp, ce, v4u()), sig(&bgp, other, v4u()));
    assert_eq!(sig(&bgp, ce, v6u()), sig(&bgp, other, v6u()));

    come_up(&mut bgp, ce);
    come_up(&mut bgp, other);
    let group = |bgp: &Bgp, id: usize, afi_safi: AfiSafi| {
        peer(bgp, id)
            .update_group_id
            .get(&afi_safi)
            .cloned()
            .unwrap()
    };
    assert_ne!(group(&bgp, ce, v4u()), group(&bgp, other, v4u()));
    assert_eq!(group(&bgp, ce, v6u()), group(&bgp, other, v6u()));

    // Deleting it at run time moves the neighbor back.
    knob(&mut bgp, CE.0, "ipv4", ConfigOp::Delete);
    commit_end(&mut bgp);
    assert_eq!(group(&bgp, ce, v4u()), group(&bgp, other, v4u()));
}
