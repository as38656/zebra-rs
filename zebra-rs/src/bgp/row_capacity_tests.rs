//! Per-prefix candidate rows must hold exactly the room they need.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bgp_packet::*;
use ipnet::{Ipv4Net, Ipv6Net};

use crate::bgp::adj_rib::{
    AdjRibBgpLsTable, AdjRibEvpnTable, AdjRibFlowspecTable, AdjRibMupTable, AdjRibTable, In, Out,
};
use crate::bgp::route::{
    BgpRib, BgpRibType, LocalRibBgpLsTable, LocalRibEvpnTable, LocalRibFlowspecTable,
    LocalRibMupTable, LocalRibTable,
};
use crate::bgp::shard::BgpShard;

/// A row whose path identity (peer slot, remote id, local id) is `n`.
fn rib(n: u32) -> BgpRib {
    let mut rib = BgpRib::new(
        n as usize,
        Ipv4Addr::new(10, 0, 0, 1),
        BgpRibType::EBGP,
        n,
        0,
        &BgpAttr::default(),
        None,
        None,
        false,
    );
    rib.local_id = n;
    rib
}

/// Grow a table to three paths and shrink it back, checking the row
/// capacity after every step. `cap` reads the capacity of the only row
/// vector in the table (0 when the prefix is gone).
fn check_exact_growth<T>(
    table: &mut T,
    add: fn(&mut T, u32),
    remove: fn(&mut T, u32),
    cap: fn(&T) -> usize,
) {
    add(table, 1);
    assert_eq!(cap(table), 1, "one path");
    add(table, 2);
    assert_eq!(cap(table), 2, "two paths");
    add(table, 3);
    assert_eq!(cap(table), 3, "three paths");
    add(table, 2);
    assert_eq!(cap(table), 3, "replacing a path keeps the room");
    remove(table, 2);
    assert_eq!(cap(table), 2, "one path removed");
    remove(table, 3);
    assert_eq!(cap(table), 1, "two paths removed");
    remove(table, 1);
    assert_eq!(cap(table), 0, "all paths removed");
}

fn v4() -> Ipv4Net {
    "10.9.0.0/24".parse().unwrap()
}

fn v6() -> Ipv6Net {
    "2001:db8:9::/48".parse().unwrap()
}

fn evpn() -> EvpnPrefix {
    EvpnPrefix::EthernetAd {
        esi: [0; 10],
        eth_tag: 1,
    }
}

fn mup() -> MupPrefix {
    MupPrefix::Dsd {
        address: IpAddr::V6(Ipv6Addr::LOCALHOST),
    }
}

fn flowspec() -> FlowspecNlri {
    FlowspecNlri::new(Afi::Ip, Vec::new())
}

fn bgpls() -> BgpLsNlri {
    BgpLsNlri::Node(LsNodeNlri {
        protocol_id: LsProtocolId::Direct,
        identifier: 0,
        local_node: LsNodeDescriptor::default(),
    })
}

#[test]
fn adj_rib_in_v4_rows_are_exact() {
    check_exact_growth(
        &mut AdjRibTable::<In>::new(),
        |t, n| {
            t.add(v4(), rib(n));
        },
        |t, n| {
            t.remove(v4(), n);
        },
        |t| t.0.get(&v4()).map_or(0, Vec::capacity),
    );
}

#[test]
fn adj_rib_in_v6_rows_are_exact() {
    check_exact_growth(
        &mut AdjRibTable::<In, Ipv6Net>::new(),
        |t, n| {
            t.add(v6(), rib(n));
        },
        |t, n| {
            t.remove(v6(), n);
        },
        |t| t.0.get(&v6()).map_or(0, Vec::capacity),
    );
}

#[test]
fn adj_rib_out_rows_are_exact() {
    check_exact_growth(
        &mut AdjRibTable::<Out>::new(),
        |t, n| {
            t.add(v4(), rib(n));
        },
        |t, n| {
            t.remove(v4(), n);
        },
        |t| t.0.get(&v4()).map_or(0, Vec::capacity),
    );
}

#[test]
fn adj_rib_evpn_rows_are_exact() {
    check_exact_growth(
        &mut AdjRibEvpnTable::<In>::new(),
        |t, n| {
            t.add(evpn(), rib(n));
        },
        |t, n| {
            t.remove(&evpn(), n);
        },
        |t| t.0.get(&evpn()).map_or(0, Vec::capacity),
    );
}

#[test]
fn adj_rib_mup_rows_are_exact() {
    check_exact_growth(
        &mut AdjRibMupTable::<In>::new(),
        |t, n| {
            t.add(mup(), rib(n));
        },
        |t, n| {
            t.remove(&mup(), n);
        },
        |t| t.0.get(&mup()).map_or(0, Vec::capacity),
    );
}

#[test]
fn adj_rib_flowspec_rows_are_exact() {
    check_exact_growth(
        &mut AdjRibFlowspecTable::<In>::new(),
        |t, n| {
            t.add(flowspec(), rib(n));
        },
        |t, n| {
            t.remove(&flowspec(), n);
        },
        |t| t.0.get(&flowspec()).map_or(0, Vec::capacity),
    );
}

#[test]
fn adj_rib_bgpls_rows_are_exact() {
    check_exact_growth(
        &mut AdjRibBgpLsTable::<In>::new(),
        |t, n| {
            t.add(bgpls(), rib(n));
        },
        |t, n| {
            t.remove(&bgpls(), n);
        },
        |t| t.0.get(&bgpls()).map_or(0, Vec::capacity),
    );
}

#[test]
fn adj_rib_out_record_out_rows_are_exact() {
    let mut t = AdjRibTable::<Out>::new();
    t.record_out(v4(), rib(1), false);
    t.record_out(v4(), rib(2), false);
    assert_eq!(t.0[&v4()].capacity(), 1, "non-AddPath keeps one row");
}

#[test]
fn loc_rib_v4_rows_are_exact() {
    check_exact_growth(
        &mut LocalRibTable::<Ipv4Net>::default(),
        |t, n| {
            t.update(v4(), rib(n));
        },
        |t, n| {
            t.remove(v4(), n, n as usize);
        },
        |t| t.0.get(&v4()).map_or(0, Vec::capacity),
    );
}

#[test]
fn loc_rib_v6_rows_are_exact() {
    check_exact_growth(
        &mut LocalRibTable::<Ipv6Net>::default(),
        |t, n| {
            t.update(v6(), rib(n));
        },
        |t, n| {
            t.remove(v6(), n, n as usize);
        },
        |t| t.0.get(&v6()).map_or(0, Vec::capacity),
    );
}

#[test]
fn loc_rib_evpn_rows_are_exact() {
    check_exact_growth(
        &mut LocalRibEvpnTable::default(),
        |t, n| {
            t.update(evpn(), rib(n));
        },
        |t, n| {
            t.remove(&evpn(), n, n as usize);
        },
        |t| t.cands.get(&evpn()).map_or(0, Vec::capacity),
    );
}

#[test]
fn loc_rib_mup_rows_are_exact() {
    check_exact_growth(
        &mut LocalRibMupTable::default(),
        |t, n| {
            t.update(mup(), rib(n));
        },
        |t, n| {
            t.remove(&mup(), n, n as usize);
        },
        |t| t.cands.get(&mup()).map_or(0, Vec::capacity),
    );
}

#[test]
fn loc_rib_flowspec_rows_are_exact() {
    check_exact_growth(
        &mut LocalRibFlowspecTable::default(),
        |t, n| {
            t.update(flowspec(), rib(n));
        },
        |t, n| {
            t.remove(&flowspec(), n, n as usize);
        },
        |t| t.cands.get(&flowspec()).map_or(0, Vec::capacity),
    );
}

#[test]
fn loc_rib_bgpls_rows_are_exact() {
    check_exact_growth(
        &mut LocalRibBgpLsTable::default(),
        |t, n| {
            t.update(bgpls(), rib(n));
        },
        |t, n| {
            t.remove(&bgpls(), n, n as usize);
        },
        |t| t.cands.get(&bgpls()).map_or(0, Vec::capacity),
    );
}

#[test]
fn shard_v4_mirror_rows_are_exact() {
    check_exact_growth(
        &mut BgpShard::default(),
        |t, n| t.mirror_v4(v4(), Some(&rib(n)), &[], Some(&rib(n))),
        |t, n| t.mirror_v4(v4(), None, &[rib(n)], None),
        |t| t.v4.0.get(&v4()).map_or(0, Vec::capacity),
    );
}
