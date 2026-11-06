//! The VRF FIB follows the best path between a CE route and the routes
//! the VRF imports from the VPN, whatever moves it: the CE route
//! withdrawn, the CE session going down, an inbound policy that denies
//! the CE route, an import or the withdraw of one. An imported winner is
//! installed with the transport of its own import, also when that import
//! arrived while the CE route was best.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr};

use bgp_packet::{
    Afi, AfiSafi, As4Path, BgpAttr, BgpNexthop, CapMultiProtocol, Ipv4Nlri, Ipv6Nlri, MpReachAttr,
    MpUnreachAttr, Origin, Safi, UpdatePacket,
};
use ipnet::IpNet;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use super::*;
use crate::bgp::peer::{Event, State};
use crate::bgp::vrf_config::BgpVrfNeighborConfig;
use crate::rib::client::{ProtoId, RibClient, RibInbound};
use crate::rib::nht::ResolvedNexthop;

const ROUTER_ID: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const CE4: &str = "10.0.0.2";
const CE6: &str = "2001:db8:1e::2";
const CE_AS: u32 = 65100;
/// The AS of the CE behind the remote PE. One AS on both paths makes the
/// AS-path lengths equal, so the CE route wins as eBGP over the iBGP
/// import, as with two upstreams on two PEs.
const REMOTE_CE_AS: u32 = 65200;
const P4: &str = "192.0.2.64/26";
const P6: &str = "2001:db8:e1::/48";

type FibRx = UnboundedReceiver<RibInbound>;

/// A VRF task with no peers, and the FIB changes it sends to the RIB.
fn vrf() -> (BgpVrf, FibRx) {
    let (inbound_tx, fib_rx) = unbounded_channel::<RibInbound>();
    let rib = RibClient::new(inbound_tx, ProtoId::from_raw(0));
    let ctx = ProtoContext::for_vrf(rib, 62, "vrf-fib".to_string());
    let (global_tx, global_rx) = unbounded_channel::<BgpGlobalMsg>();
    Box::leak(Box::new(global_rx));
    let (rib_tx, rib_rx) = mpsc::unbounded_channel();
    Box::leak(Box::new(rib_tx));
    let (vrf, inbox) = BgpVrf::new(
        "vrf-fib".to_string(),
        ctx,
        ROUTER_ID,
        65000,
        16,
        global_tx,
        rib_rx,
    );
    Box::leak(Box::new(inbox));
    (vrf, fib_rx)
}

#[derive(Clone, Copy, Debug)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn prefix(self) -> IpNet {
        match self {
            Family::V4 => P4.parse().unwrap(),
            Family::V6 => P6.parse().unwrap(),
        }
    }

    fn ce(self) -> IpAddr {
        match self {
            Family::V4 => CE4.parse().unwrap(),
            Family::V6 => CE6.parse().unwrap(),
        }
    }

    fn afi_safi(self) -> AfiSafi {
        match self {
            Family::V4 => AfiSafi::new(Afi::Ip, Safi::Unicast),
            Family::V6 => AfiSafi::new(Afi::Ip6, Safi::Unicast),
        }
    }
}

/// Add the eBGP CE of `family` and bring its session up.
fn add_ce(vrf: &mut BgpVrf, family: Family) -> usize {
    let mut nbr = BgpVrfNeighborConfig {
        remote_as: Some(CE_AS),
        ..Default::default()
    };
    nbr.config.timer.min_adv_interval = Some(0);
    let addr = family.ce();
    let (remote_as, config, knobs) =
        super::super::spawn::resolve_vrf_peer_config(&addr, &nbr, &BTreeMap::new()).unwrap();
    vrf.process_global_msg(BgpVrfMsg::AddPeer {
        addr,
        remote_as,
        config: Box::new(config),
        knobs: Box::new(knobs),
        policy_refs: BTreeMap::new(),
    });
    let (packet_tx, packet_rx) = unbounded_channel();
    Box::leak(Box::new(packet_rx));
    let peer = vrf.peers.get_mut(&addr).expect("CE added");
    peer.state = State::OpenConfirm;
    peer.primary_conn_id = Some(1);
    peer.as4 = true;
    peer.param.local_addr = Some(match family {
        Family::V4 => "10.0.0.1:179".parse().unwrap(),
        Family::V6 => "[2001:db8:1e::1]:179".parse().unwrap(),
    });
    let afi_safi = family.afi_safi();
    let entry = peer
        .cap_map
        .entries
        .entry(CapMultiProtocol::new(&afi_safi.afi, &afi_safi.safi))
        .or_default();
    entry.send = true;
    entry.recv = true;
    peer.packet_tx = Some(packet_tx);
    let ident = peer.ident;
    vrf.process_msg(Message::Event(ident, Event::KeepAliveMsg(1)));
    assert_eq!(
        vrf.peers.get_by_idx(ident).unwrap().state,
        State::Established
    );
    ident
}

/// The CE announces the test prefix of `family`.
fn ce_announces(vrf: &mut BgpVrf, ident: usize, family: Family) {
    let mut update = UpdatePacket::new();
    let mut attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from(vec![CE_AS])),
        ..Default::default()
    };
    match family {
        Family::V4 => {
            attr.nexthop = Some(BgpNexthop::Ipv4(CE4.parse().unwrap()));
            update.ipv4_update = vec![Ipv4Nlri {
                id: 0,
                prefix: P4.parse().unwrap(),
            }];
        }
        Family::V6 => {
            update.mp_update = Some(MpReachAttr::Ipv6 {
                snpa: 0,
                nhop: CE6.parse().unwrap(),
                updates: vec![Ipv6Nlri {
                    id: 0,
                    prefix: P6.parse().unwrap(),
                }],
            });
        }
    }
    update.bgp_attr = Some(attr);
    vrf.process_msg(Message::Event(ident, Event::UpdateMsg(update)));
}

/// How the CE route leaves the VRF Loc-RIB.
#[derive(Clone, Copy, Debug)]
enum CeLeaves {
    Withdraw,
    SessionDown,
    PolicyDeny,
}

impl CeLeaves {
    /// The ways the CE route of `family` can leave. Inbound policy is
    /// replayed for IPv4 only: `route_soft_in_peer` has no IPv6 table.
    fn all(family: Family) -> &'static [CeLeaves] {
        match family {
            Family::V4 => &[
                CeLeaves::Withdraw,
                CeLeaves::SessionDown,
                CeLeaves::PolicyDeny,
            ],
            Family::V6 => &[CeLeaves::Withdraw, CeLeaves::SessionDown],
        }
    }
}

fn ce_leaves(vrf: &mut BgpVrf, ident: usize, family: Family, how: CeLeaves) {
    match how {
        CeLeaves::Withdraw => {
            let mut update = UpdatePacket::new();
            match family {
                Family::V4 => {
                    update.ipv4_withdraw = vec![Ipv4Nlri {
                        id: 0,
                        prefix: P4.parse().unwrap(),
                    }];
                }
                Family::V6 => {
                    update.mp_withdraw = Some(MpUnreachAttr::Ipv6Nlri(vec![Ipv6Nlri {
                        id: 0,
                        prefix: P6.parse().unwrap(),
                    }]));
                }
            }
            vrf.process_msg(Message::Event(ident, Event::UpdateMsg(update)));
        }
        CeLeaves::SessionDown => {
            vrf.process_msg(Message::Event(ident, Event::HoldTimerExpires));
            assert!(!vrf.peers.get_by_idx(ident).unwrap().state.is_established());
        }
        CeLeaves::PolicyDeny => deny_in(vrf, ident, family),
    }
}

/// Bind an inbound prefix-set to the CE that does not hold the test
/// prefix, so the replay denies the CE route.
fn deny_in(vrf: &mut BgpVrf, ident: usize, family: Family) {
    use crate::bgp::config::peer_policy_ident;
    use crate::bgp::policy::InOut;
    use crate::policy::prefix::set::{PrefixSet, PrefixSetEntry};
    use crate::policy::{PolicyRx, PolicyType};

    let afi_safi = family.afi_safi();
    vrf.peers
        .get_mut_by_idx(ident)
        .unwrap()
        .prefix_set_slot(afi_safi, InOut::Input)
        .name = Some("ce-in".to_string());
    let other: IpNet = match family {
        Family::V4 => "198.51.100.0/24".parse().unwrap(),
        Family::V6 => "2001:db8:ff::/48".parse().unwrap(),
    };
    let mut set = PrefixSet::default();
    set.insert(other, PrefixSetEntry::default());
    vrf.process_policy_msg(PolicyRx::PrefixSet {
        name: "ce-in".to_string(),
        ident: peer_policy_ident(ident, Some(afi_safi)),
        policy_type: PolicyType::PrefixSetIn,
        prefix_set: Some(set),
    });
}

/// How the remote PE's route reaches the VRF.
#[derive(Clone, Copy, Debug)]
enum Encap {
    Mpls,
    Srv6,
}

const SID: &str = "fcbb:bbbb:1:e000::";
const SERVICE_LABEL: u32 = 100;
const TRANSPORT_LABEL: u32 = 16001;

fn import_attr(encap: Encap) -> BgpAttr {
    let mut attr = BgpAttr {
        origin: Some(Origin::Igp),
        aspath: Some(As4Path::from(vec![REMOTE_CE_AS])),
        ..Default::default()
    };
    if let Encap::Srv6 = encap {
        attr.prefix_sid = Some(bgp_packet::PrefixSid {
            tlvs: vec![bgp_packet::PrefixSidTlv::Srv6L3Service(
                bgp_packet::Srv6ServiceTlv {
                    sids: vec![bgp_packet::Srv6SidInfo::new(
                        SID.parse().unwrap(),
                        0,
                        bgp_packet::SRV6_BEHAVIOR_END_DT46,
                        None,
                    )],
                    ..Default::default()
                },
            )],
        });
    }
    attr
}

/// The resolved underlay toward the remote PE, through `gw`.
fn transport(encap: Encap, gw: &str) -> Vec<ResolvedNexthop> {
    vec![ResolvedNexthop {
        addr: gw.parse().unwrap(),
        ifindex: 7,
        labels: match encap {
            Encap::Mpls => vec![TRANSPORT_LABEL],
            Encap::Srv6 => Vec::new(),
        },
        segs: Vec::new(),
        seg_encap: None,
    }]
}

fn import(
    vrf: &mut BgpVrf,
    rd: &str,
    source: ImportSource,
    family: Family,
    encap: Encap,
    transport: &[ResolvedNexthop],
) {
    let rd = rd.parse().unwrap();
    let label = match encap {
        Encap::Mpls => SERVICE_LABEL,
        Encap::Srv6 => 0,
    };
    match family.prefix() {
        IpNet::V4(p) => vrf.handle_import_v4(rd, source, p, import_attr(encap), label, transport),
        IpNet::V6(p) => vrf.handle_import_v6(rd, source, p, import_attr(encap), label, transport),
    }
}

fn withdraw_import(vrf: &mut BgpVrf, rd: &str, source: ImportSource, family: Family) {
    let rd = rd.parse().unwrap();
    match family.prefix() {
        IpNet::V4(p) => vrf.handle_withdraw_import(rd, source, p),
        IpNet::V6(p) => vrf.handle_withdraw_import_v6(rd, source, p),
    }
}

/// What the VRF last told the RIB about one prefix.
#[derive(Debug, PartialEq)]
enum Fib {
    Removed,
    Installed {
        via: IpAddr,
        labels: Vec<u32>,
        segs: Vec<Ipv6Addr>,
    },
}

impl Fib {
    fn ce(family: Family) -> Self {
        Fib::Installed {
            via: family.ce(),
            labels: Vec::new(),
            segs: Vec::new(),
        }
    }

    fn vpn(encap: Encap, gw: &str) -> Self {
        let (labels, segs) = match encap {
            Encap::Mpls => (vec![TRANSPORT_LABEL, SERVICE_LABEL], Vec::new()),
            Encap::Srv6 => (Vec::new(), vec![SID.parse().unwrap()]),
        };
        Fib::Installed {
            via: gw.parse().unwrap(),
            labels,
            segs,
        }
    }

    fn of(entry: &crate::rib::entry::RibEntry) -> Self {
        let crate::rib::Nexthop::Uni(uni) = &entry.nexthop else {
            panic!("one next hop expected: {:?}", entry.nexthop);
        };
        Fib::Installed {
            via: uni.addr,
            labels: uni.mpls_label.clone(),
            segs: uni.segs.clone(),
        }
    }
}

/// The last FIB change the VRF sent for `prefix` since the last call, if
/// any. Other prefixes are skipped.
fn last_fib(rx: &mut FibRx, prefix: IpNet) -> Option<Fib> {
    let mut last = None;
    while let Ok(inbound) = rx.try_recv() {
        let fib = match inbound.msg {
            crate::rib::Message::Ipv4Add { prefix: p, rib } if IpNet::V4(p) == prefix => {
                Fib::of(&rib)
            }
            crate::rib::Message::Ipv6Add { prefix: p, rib } if IpNet::V6(p) == prefix => {
                Fib::of(&rib)
            }
            crate::rib::Message::Ipv4Del { prefix: p, .. } if IpNet::V4(p) == prefix => {
                Fib::Removed
            }
            crate::rib::Message::Ipv6Del { prefix: p, .. } if IpNet::V6(p) == prefix => {
                Fib::Removed
            }
            _ => continue,
        };
        last = Some(fib);
    }
    last
}

fn best_is_imported(vrf: &mut BgpVrf, family: Family) -> bool {
    let selected = match family.prefix() {
        IpNet::V4(p) => vrf.shard.select_best_path(p),
        IpNet::V6(p) => vrf.shard.select_best_path_v6(p),
    };
    selected.first().expect("a best path").vrf_imported
}

/// The CE route is best and installed, and an import from the remote PE
/// sits behind it.
fn ce_first_then_import(family: Family, encap: Encap, gw: &str) -> (BgpVrf, FibRx, usize) {
    let (mut vrf, mut fib) = vrf();
    let ce = add_ce(&mut vrf, family);
    ce_announces(&mut vrf, ce, family);
    assert_eq!(last_fib(&mut fib, family.prefix()), Some(Fib::ce(family)));
    import(
        &mut vrf,
        "65000:1",
        ImportSource::Vpn,
        family,
        encap,
        &transport(encap, gw),
    );
    assert!(
        !best_is_imported(&mut vrf, family),
        "the CE route stays best"
    );
    assert_eq!(last_fib(&mut fib, family.prefix()), Some(Fib::ce(family)));
    (vrf, fib, ce)
}

/// The bug from the lab: the import came second, so when the CE route
/// left, best path moved to the import but its transport was not found
/// and nothing reached the FIB.
#[tokio::test]
async fn the_import_that_came_after_the_ce_route_is_installed_when_it_leaves() {
    let mut wrong = Vec::new();
    for family in [Family::V4, Family::V6] {
        for encap in [Encap::Mpls, Encap::Srv6] {
            for &how in CeLeaves::all(family) {
                let (mut vrf, mut fib, ce) = ce_first_then_import(family, encap, "fe80::1");
                ce_leaves(&mut vrf, ce, family, how);
                assert!(best_is_imported(&mut vrf, family));
                let got = last_fib(&mut fib, family.prefix());
                if got != Some(Fib::vpn(encap, "fe80::1")) {
                    wrong.push(format!("{family:?} {encap:?} {how:?}: {got:?}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "the import was not installed: {wrong:#?}");
}

/// When the CE route comes back it takes the FIB back.
#[tokio::test]
async fn the_ce_route_takes_the_fib_back_when_it_returns() {
    for family in [Family::V4, Family::V6] {
        let case = format!("{family:?}");
        let (mut vrf, mut fib, ce) = ce_first_then_import(family, Encap::Srv6, "fe80::1");
        ce_leaves(&mut vrf, ce, family, CeLeaves::Withdraw);
        assert_eq!(
            last_fib(&mut fib, family.prefix()),
            Some(Fib::vpn(Encap::Srv6, "fe80::1")),
            "{case}"
        );
        ce_announces(&mut vrf, ce, family);
        assert!(!best_is_imported(&mut vrf, family), "{case}");
        assert_eq!(
            last_fib(&mut fib, family.prefix()),
            Some(Fib::ce(family)),
            "{case}"
        );
    }
}

/// A new transport for the import (the underlay rerouted) that arrives
/// while the CE route is best is the one installed when the CE route
/// leaves; an unresolved one installs nothing.
#[tokio::test]
async fn a_transport_change_while_the_ce_route_is_best_is_what_gets_installed() {
    for family in [Family::V4, Family::V6] {
        let case = format!("{family:?}");
        let (mut vrf, mut fib, ce) = ce_first_then_import(family, Encap::Mpls, "fe80::1");
        import(
            &mut vrf,
            "65000:1",
            ImportSource::Vpn,
            family,
            Encap::Mpls,
            &transport(Encap::Mpls, "fe80::2"),
        );
        assert_eq!(
            last_fib(&mut fib, family.prefix()),
            Some(Fib::ce(family)),
            "{case}"
        );
        ce_leaves(&mut vrf, ce, family, CeLeaves::Withdraw);
        assert_eq!(
            last_fib(&mut fib, family.prefix()),
            Some(Fib::vpn(Encap::Mpls, "fe80::2")),
            "{case}"
        );

        let (mut vrf, mut fib, ce) = ce_first_then_import(family, Encap::Srv6, "fe80::1");
        import(
            &mut vrf,
            "65000:1",
            ImportSource::Vpn,
            family,
            Encap::Srv6,
            &[],
        );
        ce_leaves(&mut vrf, ce, family, CeLeaves::Withdraw);
        assert!(best_is_imported(&mut vrf, family), "{case}");
        assert_eq!(
            last_fib(&mut fib, family.prefix()),
            Some(Fib::Removed),
            "{case}: no transport, no entry"
        );
    }
}

/// Two PEs import the prefix under two RDs while the CE route is best.
/// When it leaves, the import that wins is installed with its own
/// transport, and when that one is withdrawn the other PE's takes over.
#[tokio::test]
async fn imports_from_two_rds_each_install_their_own_transport() {
    for family in [Family::V4, Family::V6] {
        let case = format!("{family:?}");
        let (mut vrf, mut fib, ce) = ce_first_then_import(family, Encap::Srv6, "fe80::1");
        import(
            &mut vrf,
            "65000:2",
            ImportSource::Vpn,
            family,
            Encap::Srv6,
            &transport(Encap::Srv6, "fe80::2"),
        );
        ce_leaves(&mut vrf, ce, family, CeLeaves::SessionDown);
        // Equal imports: the RD seen first has the lower candidate id.
        assert_eq!(
            last_fib(&mut fib, family.prefix()),
            Some(Fib::vpn(Encap::Srv6, "fe80::1")),
            "{case}"
        );
        withdraw_import(&mut vrf, "65000:1", ImportSource::Vpn, family);
        assert_eq!(
            last_fib(&mut fib, family.prefix()),
            Some(Fib::vpn(Encap::Srv6, "fe80::2")),
            "{case}"
        );
        withdraw_import(&mut vrf, "65000:2", ImportSource::Vpn, family);
        assert_eq!(
            last_fib(&mut fib, family.prefix()),
            Some(Fib::Removed),
            "{case}"
        );
    }
}

/// One PE exports the prefix as VPN and as EVPN Type-5 under one RD.
/// The two are separate candidates with their own transports: on a full
/// tie the EVPN copy is installed whichever came first, and withdrawing
/// either leaves the other installed.
#[tokio::test]
async fn vpn_and_evpn_imports_of_one_rd_install_their_own_transport() {
    for family in [Family::V4, Family::V6] {
        for evpn_first in [false, true] {
            for gone in [ImportSource::Evpn, ImportSource::Vpn] {
                let case = format!("{family:?} evpn_first={evpn_first} withdraw {gone:?}");
                let (mut vrf, mut fib) = vrf();
                let vpn = (ImportSource::Vpn, "fe80::1");
                let evpn = (ImportSource::Evpn, "fe80::2");
                let order = if evpn_first { [evpn, vpn] } else { [vpn, evpn] };
                for (source, gw) in order {
                    import(
                        &mut vrf,
                        "65000:1",
                        source,
                        family,
                        Encap::Mpls,
                        &transport(Encap::Mpls, gw),
                    );
                }
                assert_eq!(
                    last_fib(&mut fib, family.prefix()),
                    Some(Fib::vpn(Encap::Mpls, evpn.1)),
                    "{case}"
                );
                withdraw_import(&mut vrf, "65000:1", gone, family);
                let kept = if gone == ImportSource::Evpn {
                    vpn
                } else {
                    evpn
                };
                assert_eq!(
                    last_fib(&mut fib, family.prefix()),
                    Some(Fib::vpn(Encap::Mpls, kept.1)),
                    "{case}"
                );
                withdraw_import(&mut vrf, "65000:1", kept.0, family);
                assert_eq!(
                    last_fib(&mut fib, family.prefix()),
                    Some(Fib::Removed),
                    "{case}"
                );
            }
        }
    }
}
