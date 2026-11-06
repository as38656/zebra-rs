//! What a VRF task keeps about the routes it imports from the VPN
//! (VPNv4, VPNv6 and EVPN Type-5): the Loc-RIB candidate id of each
//! origin, and the resolved transport of each import.
//!
//! The FIB install reads the transport of whichever imported row wins
//! best path through [`VrfImports::transport_v4`] /
//! [`VrfImports::transport_v6`]. No copy is kept per winner, so a
//! best-path change that does not come from the import path (a CE route
//! withdrawn, a CE session going down, an inbound policy replay) still
//! installs the transport of the import that takes over.

use std::collections::BTreeMap;

use bgp_packet::RouteDistinguisher;
use ipnet::{Ipv4Net, Ipv6Net};

use super::msg::ImportSource;
use crate::bgp::route::BgpRib;
use crate::rib::nht::ResolvedNexthop;

/// First synthetic `remote_id` for imported rows. Everything below is
/// reserved: 0 is the legacy shared-import id (and the unknown-rtype
/// redistribute fallback), 1..=5 are the per-rtype redistribute
/// identities — all under the same `ORIGINATED_PEER` ident.
pub(super) const IMPORT_ID_BASE: u32 = 16;

/// Resolved transport of every import of one address family, keyed by
/// `(prefix, origin RD, source)`. An import whose transport has not
/// resolved has no entry.
#[derive(Debug)]
pub struct ImportTransports<P> {
    by_origin: BTreeMap<(P, RouteDistinguisher, ImportSource), Vec<ResolvedNexthop>>,
}

impl<P> Default for ImportTransports<P> {
    fn default() -> Self {
        Self {
            by_origin: BTreeMap::new(),
        }
    }
}

impl<P: Ord + Copy> ImportTransports<P> {
    /// Record the transport of one import. An empty `transport` (the
    /// next-hop has not resolved) removes the entry.
    pub fn set(
        &mut self,
        prefix: P,
        rd: RouteDistinguisher,
        source: ImportSource,
        transport: &[ResolvedNexthop],
    ) {
        let key = (prefix, rd, source);
        if transport.is_empty() {
            self.by_origin.remove(&key);
        } else {
            self.by_origin.insert(key, transport.to_vec());
        }
    }

    /// Forget the transport of a withdrawn import.
    pub fn remove(&mut self, prefix: P, rd: RouteDistinguisher, source: ImportSource) {
        self.by_origin.remove(&(prefix, rd, source));
    }

    fn get(
        &self,
        prefix: P,
        rd: RouteDistinguisher,
        source: ImportSource,
    ) -> Option<&[ResolvedNexthop]> {
        self.by_origin.get(&(prefix, rd, source)).map(Vec::as_slice)
    }

    /// Number of imports with a resolved transport.
    #[cfg(test)]
    fn stored(&self) -> usize {
        self.by_origin.len()
    }
}

/// The imports of one VRF task: candidate ids and transports.
#[derive(Debug, Default)]
pub struct VrfImports {
    /// Slot of each origin RD this VRF imported from, in order of first
    /// sight; [`Self::id`] turns `(slot, source)` into the candidate id of
    /// an imported row. A dual-homed prefix arrives from two PEs under two
    /// RDs; storing every import under one `(remote_id 0, ORIGINATED_PEER)`
    /// identity aliased them to a single row, so the first PE's withdraw
    /// removed the row that by then held the *surviving* PE's route — a
    /// CE-side blackhole (review finding #4). The same holds within one RD
    /// across the two [`ImportSource`]s: a PE exporting a prefix as both
    /// VPNv4 and EVPN Type-5 under one RD must leave two rows, or the last
    /// import overwrites the other and either withdraw removes both. Never
    /// recycled; bounded by the number of distinct origin RDs this VRF
    /// ever imported from.
    slots: BTreeMap<RouteDistinguisher, u32>,
    /// The origin RD of each slot, indexed by slot.
    rds: Vec<RouteDistinguisher>,
    pub v4: ImportTransports<Ipv4Net>,
    pub v6: ImportTransports<Ipv6Net>,
}

impl VrfImports {
    /// The candidate id for imports from `rd` out of `source`, allocating
    /// the RD's slot on first sight. Each slot owns two ids, the EVPN one
    /// first: `remote_id` is best-path's last tie-break (lower wins), so
    /// when the two copies of one RD's route tie on every attribute the
    /// EVPN Type-5 is installed. Under `encapsulation vxlan` it is the
    /// copy that carries the VXLAN encapsulation (VTEP, L3VNI, Router's
    /// MAC); its VPNv4 twin carries an MPLS label.
    pub fn id(&mut self, rd: RouteDistinguisher, source: ImportSource) -> u32 {
        let slot = match self.slots.get(&rd) {
            Some(&slot) => slot,
            None => {
                let slot = self.rds.len() as u32;
                self.slots.insert(rd, slot);
                self.rds.push(rd);
                slot
            }
        };
        id_of(slot, source)
    }

    /// The candidate id [`Self::id`] already allocated, or `None` when
    /// this VRF never imported from `rd`.
    pub fn existing_id(&self, rd: RouteDistinguisher, source: ImportSource) -> Option<u32> {
        self.slots.get(&rd).map(|&slot| id_of(slot, source))
    }

    /// Reverse of [`Self::id`]: the origin RD and source of a candidate id.
    pub fn origin_of(&self, id: u32) -> Option<(RouteDistinguisher, ImportSource)> {
        let offset = id.checked_sub(IMPORT_ID_BASE)?;
        let source = if offset % 2 == 0 {
            ImportSource::Evpn
        } else {
            ImportSource::Vpn
        };
        let rd = *self.rds.get((offset / 2) as usize)?;
        Some((rd, source))
    }

    /// The transport `row` of `prefix` installs with: the resolved
    /// transport of its import. `None` when `row` was not imported or its
    /// transport has not resolved.
    pub fn transport_v4(&self, prefix: Ipv4Net, row: &BgpRib) -> Option<&[ResolvedNexthop]> {
        let (rd, source) = self.import_origin(row)?;
        self.v4.get(prefix, rd, source)
    }

    /// IPv6 twin of [`Self::transport_v4`].
    pub fn transport_v6(&self, prefix: Ipv6Net, row: &BgpRib) -> Option<&[ResolvedNexthop]> {
        let (rd, source) = self.import_origin(row)?;
        self.v6.get(prefix, rd, source)
    }

    fn import_origin(&self, row: &BgpRib) -> Option<(RouteDistinguisher, ImportSource)> {
        if !row.vrf_imported {
            return None;
        }
        self.origin_of(row.remote_id)
    }
}

/// The candidate id of origin-RD slot `slot`'s `source` import: two ids
/// per slot, EVPN then VPN (see [`VrfImports::id`]).
fn id_of(slot: u32, source: ImportSource) -> u32 {
    let offset = match source {
        ImportSource::Evpn => 0,
        ImportSource::Vpn => 1,
    };
    IMPORT_ID_BASE + slot * 2 + offset
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    use super::*;
    use crate::bgp::route::BgpRibType;

    fn rd(s: &str) -> RouteDistinguisher {
        s.parse().unwrap()
    }

    fn transport(gw: &str, label: u32) -> Vec<ResolvedNexthop> {
        vec![ResolvedNexthop {
            addr: gw.parse().unwrap(),
            ifindex: 2,
            labels: vec![label],
            segs: Vec::new(),
            seg_encap: None,
        }]
    }

    fn row(remote_id: u32, vrf_imported: bool) -> BgpRib {
        let mut row = BgpRib::new(
            crate::bgp::route::ORIGINATED_PEER,
            Ipv4Addr::UNSPECIFIED,
            BgpRibType::Originated,
            remote_id,
            0,
            &bgp_packet::BgpAttr::new(),
            None,
            None,
            false,
        );
        row.vrf_imported = vrf_imported;
        row
    }

    /// Two origin RDs keep two ids per source (review finding #4), and
    /// every candidate id maps back to the RD and source it was drawn for.
    #[test]
    fn ids_map_back_to_their_origin() {
        let (rd1, rd2) = (rd("65001:100"), rd("65002:100"));
        let mut imports = VrfImports::default();
        let ids = [
            (rd1, ImportSource::Vpn),
            (rd2, ImportSource::Evpn),
            (rd1, ImportSource::Evpn),
            (rd2, ImportSource::Vpn),
        ]
        .map(|(rd, source)| (rd, source, imports.id(rd, source)));
        let distinct: BTreeSet<u32> = ids.iter().map(|&(_, _, id)| id).collect();
        assert_eq!(distinct.len(), 4);
        for (rd, source, id) in ids {
            assert!(id >= IMPORT_ID_BASE);
            assert_eq!(imports.id(rd, source), id, "stable");
            assert_eq!(imports.origin_of(id), Some((rd, source)));
            assert_eq!(imports.existing_id(rd, source), Some(id));
        }
        assert_eq!(imports.origin_of(IMPORT_ID_BASE - 1), None);
        assert_eq!(imports.origin_of(IMPORT_ID_BASE + 4), None);
        assert_eq!(
            imports.existing_id(rd("65003:100"), ImportSource::Vpn),
            None
        );
    }

    /// A row gets the transport of its own origin, whatever else is
    /// stored for the prefix.
    #[test]
    fn a_row_gets_the_transport_of_its_origin() {
        let prefix: Ipv4Net = "10.1.0.0/24".parse().unwrap();
        let (rd1, rd2) = (rd("65001:100"), rd("65002:100"));
        let mut imports = VrfImports::default();
        let vpn1 = imports.id(rd1, ImportSource::Vpn);
        let evpn1 = imports.id(rd1, ImportSource::Evpn);
        let vpn2 = imports.id(rd2, ImportSource::Vpn);
        imports
            .v4
            .set(prefix, rd1, ImportSource::Vpn, &transport("192.0.2.1", 1));
        imports
            .v4
            .set(prefix, rd1, ImportSource::Evpn, &transport("192.0.2.2", 2));
        imports
            .v4
            .set(prefix, rd2, ImportSource::Vpn, &transport("192.0.2.3", 3));

        let of = |id| {
            imports
                .transport_v4(prefix, &row(id, true))
                .map(<[_]>::to_vec)
        };
        assert_eq!(of(vpn1), Some(transport("192.0.2.1", 1)));
        assert_eq!(of(evpn1), Some(transport("192.0.2.2", 2)));
        assert_eq!(of(vpn2), Some(transport("192.0.2.3", 3)));
        let other: Ipv4Net = "10.2.0.0/24".parse().unwrap();
        assert_eq!(imports.transport_v4(other, &row(vpn1, true)), None);
    }

    /// A row that was not imported never gets a transport, even when its
    /// `remote_id` is in the import range.
    #[test]
    fn a_row_that_was_not_imported_has_no_transport() {
        let prefix: Ipv4Net = "10.1.0.0/24".parse().unwrap();
        let rd1 = rd("65001:100");
        let mut imports = VrfImports::default();
        let id = imports.id(rd1, ImportSource::Vpn);
        imports
            .v4
            .set(prefix, rd1, ImportSource::Vpn, &transport("192.0.2.1", 1));
        assert_eq!(imports.transport_v4(prefix, &row(id, false)), None);
        assert!(imports.transport_v4(prefix, &row(id, true)).is_some());
    }

    /// An unresolved transport and a withdraw both leave no entry.
    #[test]
    fn an_empty_transport_and_a_remove_clear_the_entry() {
        let prefix: Ipv6Net = "2001:db8:1::/64".parse().unwrap();
        let rd1 = rd("65001:100");
        let mut imports = VrfImports::default();
        let id = imports.id(rd1, ImportSource::Vpn);
        imports
            .v6
            .set(prefix, rd1, ImportSource::Vpn, &transport("192.0.2.1", 1));
        assert!(imports.transport_v6(prefix, &row(id, true)).is_some());
        imports.v6.set(prefix, rd1, ImportSource::Vpn, &[]);
        assert_eq!(imports.transport_v6(prefix, &row(id, true)), None);
        assert_eq!(imports.v6.stored(), 0);

        imports
            .v6
            .set(prefix, rd1, ImportSource::Vpn, &transport("192.0.2.1", 1));
        imports.v6.remove(prefix, rd1, ImportSource::Vpn);
        assert_eq!(imports.transport_v6(prefix, &row(id, true)), None);
        assert_eq!(imports.v6.stored(), 0);
    }
}
