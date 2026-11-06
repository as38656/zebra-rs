//! What crosses an external session, and what a VRF CE is sent:
//!
//! * the BGP Prefix-SID stays inside the AS on plain unicast unless the
//!   neighbor is configured for it (RFC 8669 §4, §5.1; RFC 9252 §9.2);
//! * `send-community` and the Route Target strip toward a VRF CE run
//!   after the outbound policy;
//! * with `ebgp-requires-policy` on, a family of an eBGP session with no
//!   policy bound in a direction exchanges nothing in that direction
//!   (RFC 8212).

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use bgp_packet::{CapMultiProtocol, EvpnMulticast, Vpnv4Nexthop, Vpnv6Nexthop};
use bytes::BytesMut;

use super::*;
use crate::bgp::attr_filter::{PostPolicyFilter, PrefixSidBoundary, SendCommunity};
use crate::bgp::peer::{AfiSafiEncapType, Peer, PeerInstance, State, reader_parse_option};
use crate::bgp::peer_map::PeerMap;
use crate::bgp::policy::EbgpRequiresPolicy;
use crate::bgp::update_group::signature_of;
use crate::policy::{CommunitySet, SetCommunityConfig, SetCommunityMode};

const LOCAL_AS: u32 = 65001;
const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
const SOURCE_RID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 7);
/// The ident of the peer every test route was learned from; no test peer
/// has it, so split horizon never decides.
const SOURCE: usize = 99;

fn v4u() -> AfiSafi {
    AfiSafi::new(Afi::Ip, Safi::Unicast)
}

fn v6u() -> AfiSafi {
    AfiSafi::new(Afi::Ip6, Safi::Unicast)
}

fn vpnv4() -> AfiSafi {
    AfiSafi::new(Afi::Ip, Safi::MplsVpn)
}

fn evpn() -> AfiSafi {
    AfiSafi::new(Afi::L2vpn, Safi::Evpn)
}

/// An Established peer with IPv4 and IPv6 unicast negotiated; eBGP when
/// `remote_as` differs from ours. Built like `Peer::new` leaves it, so
/// `ebgp-requires-policy` is at its default (off).
fn peer(addr: &str, remote_as: u32, local_addr: &str) -> Peer {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    Box::leak(Box::new(rx));
    let mut peer = Peer::new(
        0,
        LOCAL_AS,
        ROUTER_ID,
        remote_as,
        addr.parse::<IpAddr>().unwrap(),
        None,
        tx,
        crate::context::ProtoContext::default_table_no_rib(),
    );
    peer.state = State::Established;
    peer.peer_type = if remote_as == LOCAL_AS {
        PeerType::IBGP
    } else {
        PeerType::EBGP
    };
    for (afi, safi) in [(Afi::Ip, Safi::Unicast), (Afi::Ip6, Safi::Unicast)] {
        let key = CapMultiProtocol::new(&afi, &safi);
        let entry = peer.cap_map.entries.get_mut(&key).expect("pre-seeded");
        entry.send = true;
        entry.recv = true;
    }
    peer.param.local_addr = Some(local_addr.parse::<SocketAddr>().unwrap());
    let (ptx, prx) = tokio::sync::mpsc::unbounded_channel();
    Box::leak(Box::new(prx));
    peer.packet_tx = Some(ptx);
    peer
}

fn ebgp() -> Peer {
    peer("10.0.0.2", 65002, "10.0.0.1:179")
}

fn ibgp() -> Peer {
    peer("10.0.0.3", LOCAL_AS, "10.0.0.1:179")
}

fn ebgp_v6() -> Peer {
    peer("2001:db8::2", 65002, "[2001:db8::1]:179")
}

fn ibgp_v6() -> Peer {
    peer("2001:db8::3", LOCAL_AS, "[2001:db8::1]:179")
}

fn vrf_ce(mut peer: Peer) -> Peer {
    peer.instance = PeerInstance::Vrf;
    peer
}

/// The peer as an instance with `ebgp-requires-policy true` leaves it.
fn with_rfc8212(mut peer: Peer) -> Peer {
    peer.ebgp_requires_policy = EbgpRequiresPolicy(true);
    peer
}

fn sub(peer: &mut Peer, afi_safi: AfiSafi) -> &mut crate::bgp::peer::PeerSubConfig {
    peer.config.sub.entry(afi_safi).or_default()
}

fn sid() -> PrefixSid {
    crate::bgp::inst::srv6_l3_service_prefix_sid("2001:db8:ff::100".parse().unwrap(), None, 0x0012)
}

fn v4_attr() -> BgpAttr {
    BgpAttr {
        nexthop: Some(BgpNexthop::Ipv4("10.0.0.7".parse().unwrap())),
        prefix_sid: Some(sid()),
        ..Default::default()
    }
}

fn v6_attr() -> BgpAttr {
    BgpAttr {
        nexthop: Some(BgpNexthop::Ipv6("2001:db8::7".parse().unwrap())),
        prefix_sid: Some(sid()),
        ..Default::default()
    }
}

/// A route learned over eBGP, so it may go to every kind of peer.
fn learned(attr: &BgpAttr, nexthop: Option<VpnNexthop>) -> BgpRib {
    BgpRib::new(
        SOURCE,
        SOURCE_RID,
        BgpRibType::EBGP,
        0,
        0,
        attr,
        None,
        nexthop,
        false,
    )
}

fn originated(attr: &BgpAttr) -> BgpRib {
    BgpRib::new(
        ORIGINATED_PEER,
        ROUTER_ID,
        BgpRibType::Originated,
        0,
        0,
        attr,
        None,
        None,
        false,
    )
}

fn prefix4() -> Ipv4Net {
    "10.9.0.0/24".parse().unwrap()
}

fn prefix6() -> Ipv6Net {
    "2001:db8:9::/64".parse().unwrap()
}

fn advertised_v4(peer: &Peer, rib: &BgpRib) -> BgpAttr {
    let ctx = peer.sync_ctx(ROUTER_ID, false);
    route_update_ipv4(&ctx, &prefix4(), rib, false)
        .expect("the route is advertised")
        .1
}

/// The `BgpTop` an advertise needs; `srv6` is this speaker's own SRv6
/// IPv6-unicast service, when it has one.
macro_rules! with_top {
    ($top:ident, $srv6:expr, $body:block) => {{
        let router_id = ROUTER_ID;
        let ctx = crate::context::ProtoContext::default_table_no_rib();
        let mut local_rib = LocalRib::default();
        let mut shard = crate::bgp::shard::BgpShard::default();
        let mut attr_store = crate::bgp::BgpAttrStore::default();
        let mut update_groups = crate::bgp::update_group::empty_map();
        let interface_addrs = crate::bgp::interface_addrs::InterfaceAddrs::default();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        Box::leak(Box::new(rx));
        let srv6: Option<crate::bgp::inst::Srv6Ipv6Export> = $srv6;
        let mut $top = BgpTop {
            router_id: &router_id,
            srv6_ipv6_export: srv6.as_ref(),
            local_rib: &mut local_rib,
            shard: &mut shard,
            tx: &tx,
            rib_client: &ctx.rib,
            attr_store: &mut attr_store,
            update_groups: &mut update_groups,
            interface_addrs: &interface_addrs,
            vrf_export: None,
            color_policy: None,
            flex_algo_routes: None,
            flex_algo_srv6_routes: None,
            vrf_import: None,
            nexthop_cache: None,
            vrf_imports: None,
            as_sets_withdraw: false,
        };
        $body
    }};
}

fn own_srv6_service() -> Option<crate::bgp::inst::Srv6Ipv6Export> {
    Some(crate::bgp::inst::Srv6Ipv6Export {
        prefix_sid: sid(),
        nexthop: "2001:db8:ff::".parse().unwrap(),
    })
}

fn advertised_v6(peer: &mut Peer, rib: &BgpRib, top: &mut BgpTop) -> BgpAttr {
    route_update_ipv6(peer, &prefix6(), rib, top, false)
        .expect("the route is advertised")
        .1
}

// --- BGP Prefix-SID, egress --------------------------------------------

#[tokio::test]
async fn prefix_sid_is_not_sent_to_an_external_ipv4_unicast_peer() {
    let attrs = advertised_v4(&ebgp(), &learned(&v4_attr(), None));
    assert_eq!(attrs.prefix_sid, None);
}

#[tokio::test]
async fn prefix_sid_send_lets_ipv4_unicast_carry_it_to_an_external_peer() {
    let mut peer = ebgp();
    sub(&mut peer, v4u()).prefix_sid.send = true;
    let attrs = advertised_v4(&peer, &learned(&v4_attr(), None));
    assert_eq!(attrs.prefix_sid, Some(sid()));
}

#[tokio::test]
async fn internal_ipv4_unicast_peers_still_get_the_prefix_sid() {
    let attrs = advertised_v4(&ibgp(), &learned(&v4_attr(), None));
    assert_eq!(attrs.prefix_sid, Some(sid()));
}

#[tokio::test]
async fn vpnv4_over_ebgp_keeps_its_prefix_sid() {
    let nexthop = VpnNexthop::V4(Vpnv4Nexthop {
        rd: RouteDistinguisher::default(),
        nhop: IpAddr::V4("10.0.0.7".parse().unwrap()),
    });
    let attrs = advertised_v4(&ebgp(), &learned(&v4_attr(), Some(nexthop)));
    assert_eq!(attrs.prefix_sid, Some(sid()));
}

#[tokio::test]
async fn a_vrf_ce_gets_no_prefix_sid_on_ipv4_unicast() {
    let attrs = advertised_v4(&vrf_ce(ebgp()), &learned(&v4_attr(), None));
    assert_eq!(attrs.prefix_sid, None);
}

#[tokio::test]
async fn prefix_sid_is_not_sent_to_an_external_ipv6_unicast_peer() {
    with_top!(top, None, {
        let attrs = advertised_v6(&mut ebgp_v6(), &learned(&v6_attr(), None), &mut top);
        assert_eq!(attrs.prefix_sid, None, "a relayed SID stays inside");
    });
    with_top!(top, own_srv6_service(), {
        let attrs = advertised_v6(&mut ebgp_v6(), &originated(&v6_attr()), &mut top);
        assert_eq!(
            attrs.prefix_sid, None,
            "our own SRv6 service is not sent to a neighbor without SRv6 either"
        );
    });
}

#[tokio::test]
async fn prefix_sid_send_lets_ipv6_unicast_carry_it_to_an_external_peer() {
    with_top!(top, None, {
        let mut peer = ebgp_v6();
        sub(&mut peer, v6u()).prefix_sid.send = true;
        let attrs = advertised_v6(&mut peer, &learned(&v6_attr(), None), &mut top);
        assert_eq!(attrs.prefix_sid, Some(sid()));
    });
}

#[tokio::test]
async fn own_srv6_service_reaches_an_srv6_external_peer() {
    for encap in [AfiSafiEncapType::Srv6, AfiSafiEncapType::Srv6Relax] {
        with_top!(top, own_srv6_service(), {
            let mut peer = ebgp_v6();
            sub(&mut peer, v6u()).encapsulation_type = Some(encap);
            let attrs = advertised_v6(&mut peer, &originated(&v6_attr()), &mut top);
            assert_eq!(attrs.prefix_sid, Some(sid()), "{encap:?}");
            assert_eq!(
                attrs.nexthop,
                Some(BgpNexthop::Ipv6("2001:db8:ff::".parse().unwrap())),
                "{encap:?}: the locator stays the next-hop"
            );
        });
    }
}

#[tokio::test]
async fn a_vrf_ce_gets_no_prefix_sid_on_ipv6_unicast() {
    with_top!(top, None, {
        let attrs = advertised_v6(&mut vrf_ce(ebgp_v6()), &learned(&v6_attr(), None), &mut top);
        assert_eq!(attrs.prefix_sid, None);
    });
}

#[tokio::test]
async fn internal_ipv6_unicast_keeps_the_relay_rule() {
    with_top!(top, None, {
        let attrs = advertised_v6(&mut ibgp_v6(), &learned(&v6_attr(), None), &mut top);
        assert_eq!(
            attrs.prefix_sid, None,
            "a relayed SID still does not reach an internal peer without SRv6"
        );
    });
    with_top!(top, own_srv6_service(), {
        let attrs = advertised_v6(&mut ibgp_v6(), &learned(&v6_attr(), None), &mut top);
        assert_eq!(
            attrs.prefix_sid,
            Some(sid()),
            "an SRv6 speaker keeps it toward internal peers"
        );
    });
}

#[tokio::test]
async fn vpnv6_over_ebgp_keeps_its_prefix_sid() {
    with_top!(top, None, {
        let nexthop = VpnNexthop::V6(Vpnv6Nexthop {
            rd: RouteDistinguisher::default(),
            nhop: "2001:db8::7".parse().unwrap(),
        });
        let mut attr = v6_attr();
        attr.nexthop = Some(BgpNexthop::Vpnv6(Vpnv6Nexthop {
            rd: RouteDistinguisher::default(),
            nhop: "2001:db8::7".parse().unwrap(),
        }));
        let attrs = advertised_v6(&mut ebgp_v6(), &learned(&attr, Some(nexthop)), &mut top);
        assert_eq!(attrs.prefix_sid, Some(sid()));
    });
}

// --- BGP Prefix-SID, ingress -------------------------------------------

#[test]
fn an_external_peer_discards_the_prefix_sid_of_both_unicast_families() {
    let peer = ebgp();
    assert_eq!(
        peer.prefix_sid_discard_families(),
        BTreeSet::from([v4u(), v6u()])
    );
}

#[test]
fn prefix_sid_accept_keeps_it_for_that_family_only() {
    let mut peer = ebgp();
    sub(&mut peer, v4u()).prefix_sid.accept = true;
    assert_eq!(peer.prefix_sid_discard_families(), BTreeSet::from([v6u()]));
}

#[test]
fn srv6_encapsulation_accepts_the_ipv6_prefix_sid() {
    let mut peer = ebgp_v6();
    sub(&mut peer, v6u()).encapsulation_type = Some(AfiSafiEncapType::Srv6Relax);
    assert_eq!(peer.prefix_sid_discard_families(), BTreeSet::from([v4u()]));
}

/// One IPv4-unicast UPDATE carrying a Prefix-SID, parsed the way a new
/// reader of `peer` parses it.
fn receive_with_prefix_sid(peer: &Peer) -> UpdatePacket {
    let mut update = UpdatePacket::new();
    update.bgp_attr = Some(BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from(vec![65002])),
        ..v4_attr()
    });
    update.ipv4_update.push(Ipv4Nlri {
        id: 0,
        prefix: prefix4(),
    });
    let bytes = BytesMut::try_from(update).unwrap();
    let opt = reader_parse_option(peer);
    UpdatePacket::parse_packet(&bytes, true, Some(opt))
        .expect("parses")
        .1
}

#[test]
fn the_reader_drops_the_prefix_sid_from_an_external_peer() {
    let update = receive_with_prefix_sid(&ebgp());
    assert!(update.prefix_sid_discarded);
    assert_eq!(update.bgp_attr.unwrap().prefix_sid, None);
    assert!(!update.treat_as_withdraw, "the route itself is kept");
}

#[test]
fn the_reader_keeps_the_prefix_sid_when_accepted_or_internal() {
    let mut accepting = ebgp();
    sub(&mut accepting, v4u()).prefix_sid.accept = true;
    for peer in [accepting, ibgp()] {
        let update = receive_with_prefix_sid(&peer);
        assert!(!update.prefix_sid_discarded);
        assert_eq!(update.bgp_attr.unwrap().prefix_sid, Some(sid()));
    }
}

#[test]
fn discarded_prefix_sids_are_counted_per_peer() {
    let mut peer = ebgp();
    note_prefix_sid_discarded(&mut peer);
    note_prefix_sid_discarded(&mut peer);
    assert_eq!(peer.prefix_sid_discarded, 2);
}

// --- send-community and the VRF CE Route Target strip ------------------

/// An outbound policy that sets standard community 64500:1 on every
/// route, so the tests show the filter runs after it.
fn set_community_policy(peer: &mut Peer, afi_safi: AfiSafi) {
    let mut set = CommunitySet::default();
    set.vals
        .insert(crate::policy::CommunityMatcher::from_str("64500:1").unwrap());
    let mut list = PolicyList::default();
    list.entry(10).set_community = Some(SetCommunityConfig {
        name: "TAG".into(),
        mode: SetCommunityMode::Additive,
        resolved: Some(set),
    });
    let slot = peer.policy_list_slot(afi_safi, InOut::Output);
    slot.name = Some("TAG".into());
    slot.policy_list = Some(list);
    peer.rebuild_out_policy();
}

fn every_community() -> BgpAttr {
    BgpAttr {
        nexthop: Some(BgpNexthop::Ipv4("10.0.0.7".parse().unwrap())),
        com: Some(Community::from([0xfde8_0002])),
        ecom: Some(ExtCommunity::from_str("rt:65000:100 soo:65000:7").unwrap()),
        lcom: Some(LargeCommunity::from_str("65000:1:2").unwrap()),
        ..Default::default()
    }
}

fn out_v4(peer: &Peer, attr: BgpAttr) -> Option<BgpAttr> {
    let ctx = peer.sync_ctx(ROUTER_ID, false);
    let nlri = Ipv4Nlri {
        id: 0,
        prefix: prefix4(),
    };
    route_apply_policy_out(&ctx, &nlri, attr, 0, 0).map(|d| d.attr)
}

fn out_v6(peer: &Peer, attr: BgpAttr) -> Option<BgpAttr> {
    let nlri = Ipv6Nlri {
        id: 0,
        prefix: prefix6(),
    };
    route_apply_policy_out_v6(peer, v6u(), &nlri, attr, 0, 0).map(|d| d.attr)
}

#[tokio::test]
async fn send_community_standard_false_removes_communities_set_by_policy() {
    let mut peer = ebgp();
    set_community_policy(&mut peer, v4u());
    sub(&mut peer, v4u()).send_community.standard = false;
    let attr = out_v4(&peer, every_community()).expect("permitted");
    assert_eq!(attr.com, None);
    assert_eq!(attr.ecom, every_community().ecom);
    assert_eq!(attr.lcom, every_community().lcom);
}

#[tokio::test]
async fn send_community_extended_false_removes_extended_communities() {
    let mut peer = ebgp();
    sub(&mut peer, v4u()).send_community.extended = false;
    let attr = out_v4(&peer, every_community()).expect("permitted");
    assert_eq!(attr.ecom, None);
    assert_eq!(attr.com, every_community().com);
}

#[tokio::test]
async fn send_community_large_false_removes_large_communities() {
    let mut peer = ebgp();
    sub(&mut peer, v4u()).send_community.large = false;
    let attr = out_v4(&peer, every_community()).expect("permitted");
    assert_eq!(attr.lcom, None);
    assert_eq!(attr.com, every_community().com);
}

#[tokio::test]
async fn send_community_is_per_family() {
    let mut peer = ebgp_v6();
    sub(&mut peer, v4u()).send_community.standard = false;
    let attr = out_v6(&peer, every_community()).expect("permitted");
    assert_eq!(attr.com, every_community().com, "ipv6 is not affected");
}

#[tokio::test]
async fn every_community_is_sent_by_default() {
    let mut peer = ebgp();
    set_community_policy(&mut peer, v4u());
    let attr = out_v4(&peer, every_community()).expect("permitted");
    let mut com = every_community().com.unwrap();
    com.insert(0xfbf4_0001);
    assert_eq!(attr.com, Some(com), "the policy's community is added");
    assert_eq!(attr.ecom, every_community().ecom);
    assert_eq!(attr.lcom, every_community().lcom);
}

#[tokio::test]
async fn a_vrf_ce_is_sent_no_route_target() {
    for peer in [vrf_ce(ebgp()), vrf_ce(ibgp())] {
        let v4 = out_v4(&peer, every_community()).expect("permitted");
        let v6 = out_v6(&peer, every_community()).expect("permitted");
        for attr in [v4, v6] {
            assert_eq!(
                attr.ecom,
                Some(ExtCommunity::from_str("soo:65000:7").unwrap()),
                "the Site of Origin stays"
            );
            assert_eq!(attr.com, every_community().com);
            assert_eq!(attr.lcom, every_community().lcom);
        }
    }
}

#[tokio::test]
async fn a_global_peer_keeps_its_route_targets() {
    let attr = out_v4(&ebgp(), every_community()).expect("permitted");
    assert_eq!(attr.ecom, every_community().ecom);
}

// --- RFC 8212 -----------------------------------------------------------

fn in_v4(peer: &Peer, afi_safi: AfiSafi) -> Option<PolicyDecision> {
    let nlri = Ipv4Nlri {
        id: 0,
        prefix: prefix4(),
    };
    route_apply_policy_in(peer, afi_safi, &nlri, v4_attr(), 0)
}

fn in_v6(peer: &Peer) -> Option<PolicyDecision> {
    let nlri = Ipv6Nlri {
        id: 0,
        prefix: prefix6(),
    };
    route_apply_policy_in_v6(peer, v6u(), &nlri, v6_attr(), 0, 0)
}

fn evpn_route() -> EvpnRoute {
    EvpnRoute::Multicast(EvpnMulticast {
        id: 0,
        rd: RouteDistinguisher::default(),
        ether_tag: 0,
        addr: IpAddr::V4(SOURCE_RID),
    })
}

fn permit_all() -> crate::bgp::PolicyListValue {
    let mut list = PolicyList::default();
    list.entry(10);
    crate::bgp::PolicyListValue {
        name: Some("ALL".into()),
        policy_list: Some(list),
    }
}

/// Every inbound and outbound policy entry point of `peer`, in order:
/// v4 unicast in, v6 unicast in, EVPN in, v4 unicast out, VPNv4 out,
/// v6 unicast out, EVPN out.
fn verdicts(peer: &mut Peer) -> [bool; 7] {
    let nlri = Ipv4Nlri {
        id: 0,
        prefix: prefix4(),
    };
    let route = evpn_route();
    [
        in_v4(peer, v4u()).is_some(),
        in_v6(peer).is_some(),
        route_apply_policy_in_evpn(peer, &route, v4_attr(), 0).is_some(),
        out_v4(peer, v4_attr()).is_some(),
        route_apply_policy_out_at(peer, vpnv4(), &nlri, v4_attr(), 0, 0).is_some(),
        out_v6(peer, v6_attr()).is_some(),
        route_apply_policy_out_evpn(peer, &route, v4_attr(), 0).is_some(),
    ]
}

#[tokio::test]
async fn an_external_peer_without_policy_exchanges_nothing() {
    assert_eq!(verdicts(&mut with_rfc8212(ebgp())), [false; 7]);
    assert_eq!(
        verdicts(&mut with_rfc8212(vrf_ce(ebgp()))),
        [false; 7],
        "VRF CE too"
    );
}

#[tokio::test]
async fn an_internal_peer_needs_no_policy() {
    assert_eq!(verdicts(&mut with_rfc8212(ibgp())), [true; 7]);
}

#[tokio::test]
async fn by_default_an_external_peer_without_policy_exchanges_everything() {
    assert_eq!(verdicts(&mut ebgp()), [true; 7]);
}

#[tokio::test]
async fn rfc8212_is_decided_per_family_and_direction() {
    let mut peer = with_rfc8212(ebgp());
    *peer.policy_list_slot(v4u(), InOut::Input) = permit_all();
    assert!(in_v4(&peer, v4u()).is_some(), "ipv4 in has a policy");
    assert!(in_v6(&peer).is_none(), "ipv6 in has none");
    assert!(out_v4(&peer, v4_attr()).is_none(), "ipv4 out has none");
}

#[tokio::test]
async fn a_bound_prefix_set_counts_as_policy() {
    let mut peer = with_rfc8212(ebgp());
    let mut set = crate::policy::PrefixSet::default();
    set.insert(
        "0.0.0.0/0".parse().unwrap(),
        crate::policy::prefix::set::PrefixSetEntry {
            le: Some(32),
            ..Default::default()
        },
    );
    let slot = peer.prefix_set_slot(v4u(), InOut::Input);
    slot.name = Some("ANY".into());
    slot.prefix_set = Some(set);
    assert!(in_v4(&peer, v4u()).is_some());
}

#[tokio::test]
async fn a_bound_policy_that_is_not_resolved_yet_still_denies() {
    let mut peer = ebgp();
    peer.policy_list_slot(v4u(), InOut::Input).name = Some("LATER".into());
    assert!(in_v4(&peer, v4u()).is_none());
}

#[test]
fn missing_policy_reports_the_unbound_directions() {
    let mut peer = with_rfc8212(ebgp());
    *peer.policy_list_slot(v4u(), InOut::Output) = permit_all();
    assert!(peer.missing_policy(v4u(), InOut::Input));
    assert!(!peer.missing_policy(v4u(), InOut::Output));
    assert!(!with_rfc8212(ibgp()).missing_policy(v4u(), InOut::Input));
    assert!(!ebgp().missing_policy(v4u(), InOut::Input));
    // EVPN reads only the route-policy.
    peer.prefix_set_slot(evpn(), InOut::Input).name = Some("UNUSED".into());
    assert!(peer.missing_policy(evpn(), InOut::Input));
}

// --- update-group signatures ---------------------------------------------

fn sig(peer: &Peer, afi_safi: AfiSafi) -> crate::bgp::update_group::UpdateGroupSig {
    signature_of(peer, afi_safi.afi, afi_safi.safi).expect("family negotiated")
}

#[tokio::test]
async fn send_community_splits_update_groups_of_its_family_only() {
    let plain = ebgp();
    let mut quiet = ebgp();
    sub(&mut quiet, v4u()).send_community = SendCommunity {
        standard: false,
        ..Default::default()
    };
    assert_ne!(sig(&plain, v4u()), sig(&quiet, v4u()));
    assert_eq!(sig(&plain, v6u()), sig(&quiet, v6u()));
}

#[tokio::test]
async fn prefix_sid_send_splits_external_unicast_groups_only() {
    let plain = ebgp();
    let mut sending = ebgp();
    sub(&mut sending, v4u()).prefix_sid = PrefixSidBoundary {
        send: true,
        accept: false,
    };
    assert_ne!(sig(&plain, v4u()), sig(&sending, v4u()));
    assert_eq!(sig(&plain, v6u()), sig(&sending, v6u()));

    let internal = ibgp();
    let mut internal_sending = ibgp();
    sub(&mut internal_sending, v4u()).prefix_sid.send = true;
    assert_eq!(
        sig(&internal, v4u()),
        sig(&internal_sending, v4u()),
        "the knob does nothing on iBGP, so it must not split iBGP groups"
    );
}

#[tokio::test]
async fn ebgp_requires_policy_splits_external_groups() {
    assert_ne!(sig(&with_rfc8212(ebgp()), v4u()), sig(&ebgp(), v4u()));
    assert_eq!(
        sig(&with_rfc8212(ibgp()), v4u()),
        sig(&ibgp(), v4u()),
        "iBGP is not affected"
    );
}

#[tokio::test]
async fn a_vrf_ce_does_not_share_a_group_with_a_global_peer() {
    assert_ne!(
        sig(&ebgp(), v4u()).post_policy,
        sig(&vrf_ce(ebgp()), v4u()).post_policy
    );
    assert_eq!(
        sig(&vrf_ce(ebgp()), v4u()).post_policy,
        PostPolicyFilter {
            send_community: SendCommunity::default(),
            strip_route_targets: true,
        }
    );
}

/// Two eBGP peers that differ only in `send-community` end up in two
/// groups, so a canonical encode for one is never replicated to the other.
#[tokio::test]
async fn peers_with_different_send_community_attach_to_different_groups() {
    let mut peers = PeerMap::new();
    let mut update_groups = crate::bgp::update_group::empty_map();
    let a = peer("10.0.0.2", 65002, "10.0.0.1:179");
    let mut b = peer("10.0.0.4", 65002, "10.0.0.1:179");
    sub(&mut b, v4u()).send_community.large = false;
    peers.insert(a.address, a);
    peers.insert(b.address, b);
    for ident in 0..2 {
        peers.membership_enroll(ident);
        crate::bgp::update_group::attach(&mut update_groups, &mut peers, ident, ROUTER_ID, false);
    }
    let group = |ident: usize| {
        peers
            .get_by_idx(ident)
            .unwrap()
            .update_group_id
            .get(&v4u())
            .cloned()
            .expect("attached")
    };
    assert_ne!(group(0), group(1));
}
