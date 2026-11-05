//! `maximum-prefix` through the FSM of the global instance: the counts an
//! UPDATE raises, what happens over the limit, and how a peer kept down
//! comes back. Both the inline shard (N=1) and the worker pool (N>1).

use super::*;
use crate::bgp::peer::{BgpClearOp, Peer, PeerDownReason, PeerType, State, clear_bgp_action};
use crate::bgp::policy::EbgpRequiresPolicy;
use crate::bgp::prefix_limit::{PrefixCounts, PrefixLimitConfig};
use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, BgpType, CapMultiProtocol, Ipv4Nlri, Ipv6Nlri,
    MpReachAttr, NotificationPacket, NotifyCode, Origin, Safi, UpdatePacket,
};
use bytes::BytesMut;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::sync::mpsc;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const LOCAL_AS: u32 = 65000;
const REMOTE_AS: u32 = 65002;
const ADDR: &str = "10.0.0.2";

fn v4u() -> AfiSafi {
    AfiSafi::new(Afi::Ip, Safi::Unicast)
}

fn v6u() -> AfiSafi {
    AfiSafi::new(Afi::Ip6, Safi::Unicast)
}

type Rx = mpsc::UnboundedReceiver<BytesMut>;

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

/// Give `bgp` a pool of `n` workers, as `router bgp shards` does.
fn pooled(bgp: &mut Bgp, n: usize) {
    let (tx, rx) = mpsc::unbounded_channel();
    bgp.shards = Some(crate::bgp::shard::pool::ShardPool::spawn(
        (0..n).map(|_| Default::default()).collect(),
        tx,
    ));
    bgp.shard_results_rx = rx;
}

/// An eBGP neighbor at [`ADDR`] with IPv4 and IPv6 unicast negotiated,
/// in `state`. What it is sent comes out of the receiver.
fn add_peer(bgp: &mut Bgp, state: State) -> (usize, Rx) {
    let (tx, rx) = mpsc::channel(64);
    Box::leak(Box::new(rx));
    let ip: IpAddr = ADDR.parse().unwrap();
    let mut peer = Peer::new(
        0,
        LOCAL_AS,
        ROUTER_ID,
        REMOTE_AS,
        ip,
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = state;
    peer.peer_type = PeerType::EBGP;
    peer.first_start = false;
    peer.param.local_addr = Some("10.0.0.99:179".parse().unwrap());
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
    let id = bgp.peers.get(&ip).unwrap().ident;
    if state.is_established() {
        bgp.peers.membership_enroll(id);
        crate::bgp::update_group::attach(
            &mut bgp.update_groups,
            &mut bgp.peers,
            id,
            ROUTER_ID,
            false,
        );
    }
    (id, prx)
}

fn peer(bgp: &Bgp, id: usize) -> &Peer {
    bgp.peers.get_by_idx(id).unwrap()
}

fn peer_mut(bgp: &mut Bgp, id: usize) -> &mut Peer {
    bgp.peers.get_mut_by_idx(id).unwrap()
}

fn set_limit(bgp: &mut Bgp, id: usize, afi_safi: AfiSafi, limit: PrefixLimitConfig) {
    peer_mut(bgp, id)
        .config
        .sub
        .entry(afi_safi)
        .or_default()
        .prefix_limit = limit;
}

fn max(max: u32) -> PrefixLimitConfig {
    PrefixLimitConfig {
        max: Some(max),
        ..Default::default()
    }
}

fn attr() -> BgpAttr {
    BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from(vec![REMOTE_AS])),
        nexthop: Some(BgpNexthop::Ipv4(ADDR.parse().unwrap())),
        ..Default::default()
    }
}

fn update_v4(prefixes: &[&str]) -> UpdatePacket {
    let mut update = UpdatePacket::new();
    update.bgp_attr = Some(attr());
    update.ipv4_update = prefixes
        .iter()
        .map(|p| Ipv4Nlri {
            id: 0,
            prefix: p.parse().unwrap(),
        })
        .collect();
    update
}

fn update_v6(prefixes: &[&str]) -> UpdatePacket {
    let mut update = UpdatePacket::new();
    update.bgp_attr = Some(attr());
    update.mp_update = Some(MpReachAttr::Ipv6 {
        snpa: 0,
        nhop: "2001:db8::2".parse().unwrap(),
        updates: prefixes
            .iter()
            .map(|p| Ipv6Nlri {
                id: 0,
                prefix: p.parse().unwrap(),
            })
            .collect(),
    });
    update
}

fn withdraw_v4(prefixes: &[&str]) -> UpdatePacket {
    let mut update = UpdatePacket::new();
    update.ipv4_withdraw = prefixes
        .iter()
        .map(|p| Ipv4Nlri {
            id: 0,
            prefix: p.parse().unwrap(),
        })
        .collect();
    update
}

/// `n` distinct /24s under 10.`second`.0.0/16.
fn v4_prefixes(second: u8, n: u8) -> Vec<String> {
    (0..n).map(|i| format!("10.{second}.{i}.0/24")).collect()
}

fn receive(bgp: &mut Bgp, id: usize, update: UpdatePacket) {
    bgp.process_msg(Message::Event(id, Event::UpdateMsg(update)));
}

fn receive_v4(bgp: &mut Bgp, id: usize, prefixes: &[String]) {
    let prefixes: Vec<&str> = prefixes.iter().map(String::as_str).collect();
    receive(bgp, id, update_v4(&prefixes));
}

/// Every NOTIFICATION sent so far.
fn notifications(rx: &mut Rx) -> Vec<NotificationPacket> {
    let mut sent = Vec::new();
    while let Ok(bytes) = rx.try_recv() {
        if bytes.get(18) == Some(&(BgpType::Notification as u8)) {
            sent.push(NotificationPacket::parse_packet(&bytes).unwrap().1);
        }
    }
    sent
}

fn counts(bgp: &Bgp, id: usize, afi_safi: AfiSafi) -> PrefixCounts {
    peer(bgp, id).prefix_counts(&bgp.shard, afi_safi)
}

/// The session was closed for going over the limit, with Cease /
/// Maximum Number of Prefixes Reached carrying `afi`, `safi` and `max`
/// (RFC 4486 §4).
fn assert_tripped(bgp: &Bgp, rx: &mut Rx, id: usize, afi: Afi, safi: Safi, max: u32) {
    let peer = peer(bgp, id);
    assert_eq!(peer.state, State::Idle);
    let sent = notifications(rx);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].code, NotifyCode::Cease);
    assert_eq!(sent[0].sub_code, 1);
    let mut data = vec![0, 0, u8::from(safi), 0, 0, 0, 0];
    data[..2].copy_from_slice(&u16::from(afi).to_be_bytes());
    data[3..].copy_from_slice(&max.to_be_bytes());
    assert_eq!(sent[0].data, data);
    assert_eq!(
        peer.last_reset.map(|(reason, _)| reason),
        Some(PeerDownReason::PrefixLimit)
    );
    let overflow = peer.prefix_overflow.as_ref().expect("kept down");
    assert_eq!(overflow.afi_safi, AfiSafi::new(afi, safi));
}

#[tokio::test]
async fn under_and_at_the_limit_the_session_stays() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, State::Established);
    set_limit(&mut bgp, id, v4u(), max(3));
    receive_v4(&mut bgp, id, &v4_prefixes(1, 2));
    receive_v4(&mut bgp, id, &v4_prefixes(1, 3));
    assert_eq!(peer(&bgp, id).state, State::Established);
    assert_eq!(
        counts(&bgp, id, v4u()).accepted,
        3,
        "a re-sent prefix replaces"
    );
    assert!(notifications(&mut rx).is_empty());
    assert!(peer(&bgp, id).prefix_overflow.is_none());
}

#[tokio::test]
async fn over_the_limit_the_session_closes_with_cease_1() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, State::Established);
    set_limit(&mut bgp, id, v4u(), max(3));
    receive_v4(&mut bgp, id, &v4_prefixes(1, 3));
    receive_v4(&mut bgp, id, &v4_prefixes(2, 1));
    assert_tripped(&bgp, &mut rx, id, Afi::Ip, Safi::Unicast, 3);
    assert_eq!(counts(&bgp, id, v4u()), PrefixCounts::default());
    assert!(bgp.shard.v4.1.iter().next().is_none(), "routes withdrawn");
}

/// The peer stays down: no timer brings it back, a Start does not dial,
/// and an inbound connection is closed.
#[tokio::test]
async fn a_peer_over_the_limit_stays_down() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, State::Established);
    set_limit(&mut bgp, id, v4u(), max(1));
    receive_v4(&mut bgp, id, &v4_prefixes(1, 2));
    assert_tripped(&bgp, &mut rx, id, Afi::Ip, Safi::Unicast, 1);
    let peer_ref = peer(&bgp, id);
    assert!(peer_ref.timer.idle_hold_timer.is_none(), "no redial");
    assert!(peer_ref.timer.connect_retry.is_none());

    for event in [
        Event::Start,
        Event::IdleHoldTimerExpires,
        Event::ConnRetryTimerExpires,
    ] {
        bgp.process_msg(Message::Event(id, event));
        assert_eq!(peer(&bgp, id).state, State::Idle);
        assert!(peer(&bgp, id).task.connect.is_none(), "no dial");
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    bgp.process_msg(Message::Event(id, Event::Accepted(server)));
    assert_eq!(peer(&bgp, id).state, State::Idle);
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut client, &mut buf),
    )
    .await
    .expect("closed at once");
    assert!(matches!(read, Ok(0) | Err(_)), "inbound refused: {read:?}");
}

#[tokio::test]
async fn a_passive_peer_over_the_limit_does_not_listen() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, State::Established);
    peer_mut(&mut bgp, id).config.transport.passive = true;
    set_limit(&mut bgp, id, v4u(), max(1));
    receive_v4(&mut bgp, id, &v4_prefixes(1, 2));
    assert_tripped(&bgp, &mut rx, id, Afi::Ip, Safi::Unicast, 1);
    assert_eq!(peer(&bgp, id).state, State::Idle, "not Active");
}

#[tokio::test]
async fn clear_bgp_brings_the_peer_back() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, State::Established);
    set_limit(&mut bgp, id, v4u(), max(1));
    receive_v4(&mut bgp, id, &v4_prefixes(1, 2));
    assert_tripped(&bgp, &mut rx, id, Afi::Ip, Safi::Unicast, 1);

    let mut args = crate::config::Args(std::collections::VecDeque::from([ADDR.to_string()]));
    clear_bgp_action(&mut bgp, &mut args, None, BgpClearOp::Hard).unwrap();
    let peer_ref = peer(&bgp, id);
    assert!(peer_ref.prefix_overflow.is_none());
    assert!(peer_ref.timer.idle_hold_timer.is_some(), "it dials again");
    bgp.process_msg(Message::Event(id, Event::Start));
    assert_eq!(peer(&bgp, id).state, State::Connect);
}

#[tokio::test]
async fn the_restart_timer_brings_the_peer_back() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, State::Established);
    let limit = PrefixLimitConfig {
        restart: Some(2),
        ..max(1)
    };
    set_limit(&mut bgp, id, v4u(), limit);
    receive_v4(&mut bgp, id, &v4_prefixes(1, 2));
    assert_tripped(&bgp, &mut rx, id, Afi::Ip, Safi::Unicast, 1);
    let restart = peer(&bgp, id)
        .prefix_overflow
        .as_ref()
        .and_then(|overflow| overflow.restart.as_ref())
        .expect("restart timer armed");
    assert_eq!(restart.duration_sec(), 120);

    bgp.process_msg(Message::Event(id, Event::PrefixLimitRestart));
    assert!(peer(&bgp, id).prefix_overflow.is_none());
    assert!(peer(&bgp, id).timer.idle_hold_timer.is_some());
}

#[tokio::test]
async fn a_stale_restart_event_does_nothing() {
    let mut bgp = fresh_bgp();
    let (id, _rx) = add_peer(&mut bgp, State::Established);
    bgp.process_msg(Message::Event(id, Event::PrefixLimitRestart));
    assert_eq!(peer(&bgp, id).state, State::Established);
}

/// `force` counts every received prefix, including the ones the RFC 8212
/// gate keeps out of the Loc-RIB; without it only accepted ones count.
#[tokio::test]
async fn force_counts_the_denied_prefixes_too() {
    for force in [false, true] {
        let mut bgp = fresh_bgp();
        let (id, mut rx) = add_peer(&mut bgp, State::Established);
        peer_mut(&mut bgp, id).ebgp_requires_policy = EbgpRequiresPolicy(true);
        let limit = PrefixLimitConfig { force, ..max(2) };
        set_limit(&mut bgp, id, v4u(), limit);
        receive_v4(&mut bgp, id, &v4_prefixes(1, 3));
        if force {
            assert_tripped(&bgp, &mut rx, id, Afi::Ip, Safi::Unicast, 2);
        } else {
            assert_eq!(peer(&bgp, id).state, State::Established);
            assert_eq!(
                counts(&bgp, id, v4u()),
                PrefixCounts {
                    received: 3,
                    accepted: 0
                }
            );
        }
    }
}

#[tokio::test]
async fn warning_only_keeps_the_session() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, State::Established);
    let limit = PrefixLimitConfig {
        warning_only: true,
        ..max(2)
    };
    set_limit(&mut bgp, id, v4u(), limit);
    receive_v4(&mut bgp, id, &v4_prefixes(1, 5));
    assert_eq!(peer(&bgp, id).state, State::Established);
    assert_eq!(counts(&bgp, id, v4u()).accepted, 5, "every route is taken");
    assert!(notifications(&mut rx).is_empty());
    assert!(peer(&bgp, id).prefix_overflow.is_none());
}

/// A family without a limit is not counted against another's.
#[tokio::test]
async fn ipv6_unicast_has_its_own_limit() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, State::Established);
    set_limit(&mut bgp, id, v6u(), max(2));
    receive_v4(&mut bgp, id, &v4_prefixes(1, 5));
    receive(
        &mut bgp,
        id,
        update_v6(&["2001:db8:1::/64", "2001:db8:2::/64"]),
    );
    assert_eq!(peer(&bgp, id).state, State::Established);
    receive(&mut bgp, id, update_v6(&["2001:db8:3::/64"]));
    assert_tripped(&bgp, &mut rx, id, Afi::Ip6, Safi::Unicast, 2);
}

/// Lowering the limit under the count closes the session at the end of
/// the commit; deleting it later does not bring the peer back.
#[tokio::test]
async fn a_lower_limit_closes_the_session_at_once_and_deleting_it_keeps_it_down() {
    let mut bgp = fresh_bgp();
    let (id, mut rx) = add_peer(&mut bgp, State::Established);
    receive_v4(&mut bgp, id, &v4_prefixes(1, 4));
    assert_eq!(counts(&bgp, id, v4u()).accepted, 4);

    let set = |bgp: &mut Bgp, leaf: &str, value: &str, op: ConfigOp| {
        let path = format!("/router/bgp/neighbor/afi-safi/maximum-prefix/{leaf}");
        let cb = *bgp.callbacks.get(&path).expect("callback registered");
        let words = [ADDR, "ipv4", value];
        cb(
            bgp,
            crate::config::Args(words.iter().map(|w| w.to_string()).collect()),
            op,
        );
    };
    let commit_end = |bgp: &mut Bgp| {
        bgp.process_cm_msg(ConfigRequest::new(Vec::new(), ConfigOp::CommitEnd));
    };

    set(&mut bgp, "max", "10", ConfigOp::Set);
    commit_end(&mut bgp);
    assert_eq!(peer(&bgp, id).state, State::Established);

    set(&mut bgp, "max", "3", ConfigOp::Set);
    assert_eq!(
        peer(&bgp, id).state,
        State::Established,
        "not before CommitEnd"
    );
    commit_end(&mut bgp);
    assert_tripped(&bgp, &mut rx, id, Afi::Ip, Safi::Unicast, 3);

    set(&mut bgp, "max", "3", ConfigOp::Delete);
    commit_end(&mut bgp);
    assert!(
        peer(&bgp, id).prefix_overflow.is_some(),
        "as FRR: still down"
    );
    assert_eq!(peer(&bgp, id).prefix_limit_of(v4u()), None);
}

/// A withdrawal takes the count back down; the limit is on what is held,
/// not on what was ever sent.
#[tokio::test]
async fn withdrawals_make_room() {
    let mut bgp = fresh_bgp();
    let (id, _rx) = add_peer(&mut bgp, State::Established);
    set_limit(&mut bgp, id, v4u(), max(3));
    receive_v4(&mut bgp, id, &v4_prefixes(1, 3));
    receive(&mut bgp, id, withdraw_v4(&["10.1.0.0/24", "10.1.1.0/24"]));
    receive_v4(&mut bgp, id, &v4_prefixes(2, 2));
    assert_eq!(peer(&bgp, id).state, State::Established);
    assert_eq!(counts(&bgp, id, v4u()).accepted, 3);
}

/// The worker pool path (N>1): the session gets a gauge when it comes up,
/// the workers fill it, and the session closes when the sum goes over.
#[tokio::test]
async fn the_pool_counts_across_workers_and_closes_the_session() {
    let mut bgp = fresh_bgp();
    pooled(&mut bgp, 2);
    let (id, mut rx) = add_peer(&mut bgp, State::OpenConfirm);
    set_limit(&mut bgp, id, v4u(), max(6));
    peer_mut(&mut bgp, id).primary_conn_id = Some(1);
    bgp.process_msg(Message::Event(id, Event::KeepAliveMsg(1)));
    assert_eq!(peer(&bgp, id).state, State::Established);
    assert!(
        peer(&bgp, id).prefix_gauge.is_some(),
        "a gauge for the session"
    );

    receive_v4(&mut bgp, id, &v4_prefixes(1, 6));
    drain_until(&mut bgp, |bgp| counts(bgp, id, v4u()).accepted == 6).await;
    assert_eq!(peer(&bgp, id).state, State::Established, "at the limit");

    receive_v4(&mut bgp, id, &v4_prefixes(2, 4));
    drain_until(&mut bgp, |bgp| peer(bgp, id).state == State::Idle).await;
    assert_tripped(&bgp, &mut rx, id, Afi::Ip, Safi::Unicast, 6);
    assert!(
        peer(&bgp, id).prefix_gauge.is_none(),
        "let go with the session"
    );
}

/// Main takes the pool's results until `done`, or fails after a while.
async fn drain_until(bgp: &mut Bgp, done: impl Fn(&Bgp) -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !done(bgp) {
        let result = tokio::time::timeout_at(deadline, bgp.shard_results_rx.recv())
            .await
            .expect("the pool answers in time")
            .expect("pool alive");
        bgp.process_shard_result(result);
    }
}
