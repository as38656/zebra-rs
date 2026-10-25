//! What Linux removes by itself when a link goes down.
//!
//! Linux deletes every nexthop object that sends out of the link, every
//! group left with no member, and every route that uses one of these
//! objects. It sends no RTM_DELNEXTHOP for any of them, and no
//! RTM_DELROUTE for the IPv4 routes. So the RIB follows on its own: a
//! route it still takes for installed is not written again
//! (`route::Handover::Keep`), and a nexthop it takes for installed is not
//! added again.

use std::collections::BTreeSet;

use prefix_trie::{Prefix, PrefixMap};

use super::inst::Rib;
use super::{Group, GroupTrait, Nexthop, NexthopMap, NexthopMember, RibEntries};
use crate::fib::netlink::handle::protect_primary_nexthop;

/// The installed nexthop objects that send out of `ifindex`.
pub fn link_nexthops(nmap: &NexthopMap, ifindex: u32) -> BTreeSet<usize> {
    nmap.groups
        .iter()
        .flatten()
        .filter_map(|group| match group {
            Group::Uni(uni) if uni.is_installed() && uni.ifindex() == Some(ifindex) => {
                Some(uni.gid())
            }
            _ => None,
        })
        .collect()
}

/// Marks the nexthop objects `removed`, and the groups they leave with no
/// member, as out of the kernel. Returns all of them.
pub fn nexthops_removed(nmap: &mut NexthopMap, mut removed: BTreeSet<usize>) -> BTreeSet<usize> {
    let emptied: Vec<usize> = nmap
        .groups
        .iter()
        .flatten()
        .filter(|group| group.is_installed() && !removed.contains(&group.gid()))
        .filter(|group| match group {
            Group::Uni(_) => false,
            Group::Multi(multi) => {
                !multi.valid.is_empty()
                    && multi
                        .valid
                        .iter()
                        .all(|(member, _)| removed.contains(member))
            }
            Group::Protect(pro) => removed.contains(&pro.active_gid()),
        })
        .map(|group| group.gid())
        .collect();
    removed.extend(emptied);
    for gid in &removed {
        if let Some(group) = nmap.get_mut(*gid) {
            group.set_installed(false);
        }
    }
    removed
}

/// Marks the routes that lost every kernel route with the nexthop objects
/// `removed` as out of the kernel. A route of several priorities that
/// keeps one of them is still in the kernel, as replacing it must delete
/// what is left.
pub fn routes_removed<P: Prefix>(table: &mut PrefixMap<P, RibEntries>, removed: &BTreeSet<usize>) {
    for (_, entries) in table.iter_mut() {
        for entry in entries.iter_mut() {
            if entry.is_protocol() && entry.is_fib() && all_removed(&entry.nexthop, removed) {
                entry.set_fib(false);
            }
        }
    }
}

/// Whether every kernel route of `nexthop`, one per priority, used one of
/// the nexthop objects `removed`.
fn all_removed(nexthop: &Nexthop, removed: &BTreeSet<usize>) -> bool {
    let member = |member: &NexthopMember| match member {
        NexthopMember::Uni(uni) => uni.gid,
        NexthopMember::Multi(multi) => multi.gid,
    };
    match nexthop {
        Nexthop::Uni(uni) => removed.contains(&uni.gid),
        Nexthop::Multi(multi) => removed.contains(&multi.gid),
        Nexthop::List(list) => list
            .nexthops
            .iter()
            .all(|nexthop| removed.contains(&member(nexthop))),
        Nexthop::Protect(pro) => {
            all_removed(&protect_primary_nexthop(pro), removed)
                && removed.contains(&member(&pro.backup))
        }
        Nexthop::Blackhole(_) | Nexthop::Link(_) => false,
    }
}

impl Rib {
    /// Linux removed the nexthop objects `nexthops`, and with them the
    /// groups left with no member and the routes that used any of them.
    pub(super) fn kernel_removed(&mut self, nexthops: BTreeSet<usize>) {
        let removed = nexthops_removed(&mut self.nmap, nexthops);
        routes_removed(&mut self.table, &removed);
        routes_removed(&mut self.table_v6, &removed);
        for tables in self.vrf_tables.values_mut() {
            routes_removed(&mut tables.table, &removed);
            routes_removed(&mut tables.table_v6, &removed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fib::FibMessage;
    use crate::rib::entry::RibEntry;
    use crate::rib::vrf::VrfRibTables;
    use crate::rib::{
        Group, GroupMulti, GroupProtect, GroupTrait, GroupUni, Nexthop, NexthopList, NexthopMember,
        NexthopMulti, NexthopProtect, NexthopUni, ProtectActive, RibType,
    };
    use ipnet::{Ipv4Net, Ipv6Net};

    const LINK: u32 = 5;
    const OTHER: u32 = 6;

    fn put(nmap: &mut NexthopMap, group: Group) {
        let gid = group.gid();
        if nmap.groups.len() <= gid {
            nmap.groups.resize_with(gid + 1, || None);
        }
        nmap.groups[gid] = Some(group);
    }

    /// A nexthop object in the kernel: pinned to `origin` by its protocol,
    /// or resolved through the table to `resolved`.
    fn uni(gid: usize, origin: Option<u32>, resolved: Option<u32>) -> Group {
        let source = NexthopUni {
            addr: "2001:db8::1".parse().unwrap(),
            ifindex_origin: origin,
            ..Default::default()
        };
        let mut group = GroupUni::new(gid, &source, 0);
        group.ifindex_resolved = resolved;
        let mut group = Group::Uni(group);
        group.set_valid(true);
        group.set_installed(true);
        group
    }

    fn multi(gid: usize, members: &[usize]) -> Group {
        let mut group = GroupMulti::new(gid);
        group.set = members.iter().map(|member| (*member, 1)).collect();
        group.valid = group.set.clone();
        let mut group = Group::Multi(group);
        group.set_valid(true);
        group.set_installed(true);
        group
    }

    fn protect(gid: usize, primary: usize, backup: usize, active: ProtectActive) -> Group {
        let mut group = GroupProtect::new(gid, primary, backup);
        group.active = active;
        let mut group = Group::Protect(group);
        group.set_valid(true);
        group.set_installed(true);
        group
    }

    fn installed(nmap: &NexthopMap, gid: usize) -> bool {
        nmap.get(gid).is_some_and(|group| group.is_installed())
    }

    fn member(gid: usize, metric: u32) -> NexthopMember {
        NexthopMember::Uni(NexthopUni {
            gid,
            metric,
            ..Default::default()
        })
    }

    fn on(gid: usize) -> Nexthop {
        Nexthop::Uni(NexthopUni {
            gid,
            ..Default::default()
        })
    }

    fn route(nexthop: Nexthop, fib: bool) -> RibEntry {
        let mut entry = RibEntry::new(RibType::Bgp);
        entry.nexthop = nexthop;
        entry.valid = true;
        entry.selected = true;
        entry.fib = fib;
        entry
    }

    fn in_kernel(table: &PrefixMap<Ipv6Net, RibEntries>, prefix: &str) -> bool {
        table.get(&prefix.parse().unwrap()).unwrap()[0].is_fib()
    }

    #[test]
    fn a_link_takes_the_nexthop_objects_that_send_out_of_it() {
        let mut nmap = NexthopMap::default();
        put(&mut nmap, uni(1, Some(LINK), None));
        // A recursive nexthop is sent out of the link it resolved to.
        put(&mut nmap, uni(2, None, Some(LINK)));
        put(&mut nmap, uni(3, None, Some(OTHER)));
        let mut not_installed = uni(4, Some(LINK), None);
        not_installed.set_installed(false);
        put(&mut nmap, not_installed);
        put(&mut nmap, multi(5, &[1, 3]));
        assert_eq!(link_nexthops(&nmap, LINK), BTreeSet::from([1, 2]));
    }

    #[test]
    fn a_group_with_no_member_left_goes_with_them() {
        let mut nmap = NexthopMap::default();
        put(&mut nmap, uni(1, Some(LINK), None));
        put(&mut nmap, uni(2, None, Some(LINK)));
        put(&mut nmap, uni(3, None, Some(OTHER)));
        put(&mut nmap, multi(10, &[1, 2]));
        put(&mut nmap, multi(11, &[1, 3]));
        put(&mut nmap, protect(12, 1, 3, ProtectActive::Primary));
        // After a switchover the kernel group holds the repair.
        put(&mut nmap, protect(13, 1, 3, ProtectActive::Switched));
        let removed = nexthops_removed(&mut nmap, BTreeSet::from([1, 2]));
        assert_eq!(removed, BTreeSet::from([1, 2, 10, 12]));
        for gid in [1, 2, 10, 12] {
            assert!(!installed(&nmap, gid), "{gid} is still taken for installed");
        }
        for gid in [3, 11, 13] {
            assert!(
                installed(&nmap, gid),
                "{gid} is no longer taken for installed"
            );
        }
    }

    #[test]
    fn a_route_on_a_removed_nexthop_object_is_out_of_the_kernel() {
        let removed = BTreeSet::from([1, 2, 12]);
        let mut table: PrefixMap<Ipv6Net, RibEntries> = PrefixMap::new();
        let mut add = |prefix: &str, nexthop: Nexthop, fib: bool| {
            table.insert(prefix.parse().unwrap(), vec![route(nexthop, fib)]);
        };
        add("2001:db8:1::/64", on(1), true);
        add("2001:db8:2::/64", on(3), true);
        // A group that lost one member is still in the kernel, and so is
        // its route.
        add(
            "2001:db8:3::/64",
            Nexthop::Multi(NexthopMulti {
                gid: 11,
                nexthops: vec![
                    NexthopUni {
                        gid: 1,
                        ..Default::default()
                    },
                    NexthopUni {
                        gid: 3,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }),
            true,
        );
        // One kernel route per priority. While one of them is left, the
        // entry is still in the kernel: replacing it deletes that one.
        let list = |members: Vec<NexthopMember>| Nexthop::List(NexthopList { nexthops: members });
        add(
            "2001:db8:4::/64",
            list(vec![member(3, 10), member(1, 20)]),
            true,
        );
        add(
            "2001:db8:5::/64",
            list(vec![member(1, 10), member(2, 20)]),
            true,
        );
        // The primary route uses the protection group, not its member.
        let protect = |primary, backup, gid| {
            Nexthop::Protect(NexthopProtect {
                primary: member(primary, 10),
                backup: member(backup, 11),
                gid,
            })
        };
        add("2001:db8:6::/64", protect(4, 3, 12), true);
        add("2001:db8:7::/64", protect(4, 2, 12), true);
        add("2001:db8:8::/64", protect(1, 3, 13), true);
        routes_removed(&mut table, &removed);
        assert!(!in_kernel(&table, "2001:db8:1::/64"));
        assert!(in_kernel(&table, "2001:db8:2::/64"));
        assert!(in_kernel(&table, "2001:db8:3::/64"));
        assert!(in_kernel(&table, "2001:db8:4::/64"));
        assert!(!in_kernel(&table, "2001:db8:5::/64"));
        assert!(in_kernel(&table, "2001:db8:6::/64"));
        assert!(!in_kernel(&table, "2001:db8:7::/64"));
        assert!(in_kernel(&table, "2001:db8:8::/64"));
    }

    #[test]
    fn only_routes_of_ours_are_marked() {
        let mut table: PrefixMap<Ipv6Net, RibEntries> = PrefixMap::new();
        let mut connected = route(on(1), true);
        connected.rtype = RibType::Connected;
        table.insert("2001:db8:1::/64".parse().unwrap(), vec![connected]);
        routes_removed(&mut table, &BTreeSet::from([1]));
        assert!(in_kernel(&table, "2001:db8:1::/64"));
    }

    #[tokio::test]
    async fn the_rib_follows_the_kernel_in_every_table() {
        let mut rib = Rib::new(false).expect("rib");
        put(&mut rib.nmap, uni(1, None, Some(LINK)));
        put(&mut rib.nmap, multi(2, &[1]));
        let v4: Ipv4Net = "192.0.2.0/24".parse().unwrap();
        let v6: Ipv6Net = "2001:db8::/64".parse().unwrap();
        rib.table.insert(v4, vec![route(on(1), true)]);
        rib.table_v6.insert(v6, vec![route(on(2), true)]);
        let mut vrf = VrfRibTables::new();
        vrf.table.insert(v4, vec![route(on(1), true)]);
        vrf.table_v6.insert(v6, vec![route(on(1), true)]);
        rib.vrf_tables.insert(100, vrf);

        rib.kernel_removed(link_nexthops(&rib.nmap, LINK));

        assert!(!installed(&rib.nmap, 1));
        assert!(!installed(&rib.nmap, 2));
        assert!(!rib.table.get(&v4).unwrap()[0].is_fib());
        assert!(!rib.table_v6.get(&v6).unwrap()[0].is_fib());
        let vrf = &rib.vrf_tables[&100];
        assert!(!vrf.table.get(&v4).unwrap()[0].is_fib());
        assert!(!vrf.table_v6.get(&v6).unwrap()[0].is_fib());
    }

    #[tokio::test]
    async fn a_nexthop_object_the_kernel_reports_removed_takes_its_routes() {
        let mut rib = Rib::new(false).expect("rib");
        put(&mut rib.nmap, uni(1, None, Some(LINK)));
        let v6: Ipv6Net = "2001:db8::/64".parse().unwrap();
        rib.table_v6.insert(v6, vec![route(on(1), true)]);

        rib.process_fib_msg(FibMessage::DelNexthop(1)).await;

        assert!(!installed(&rib.nmap, 1));
        assert!(!rib.table_v6.get(&v6).unwrap()[0].is_fib());
    }
}
