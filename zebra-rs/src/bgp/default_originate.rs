//! Per-neighbor default-originate: FRR's `neighbor X default-originate`.
//!
//! While `afi-safi <ipv4|ipv6> default-originate` is set, the neighbor is
//! sent 0.0.0.0/0 or ::/0 with this router as next hop. The route is built
//! here for that one neighbor. It is not a Loc-RIB row, so the FIB, the VPN
//! and the other neighbors never get it.
//!
//! The rules follow FRR (`subgroup_default_originate`): the outbound policy
//! and RFC 8212 are not run on the route, and while the statement is set the
//! neighbor is not sent a Loc-RIB default ([`holds_back`]). When the
//! statement goes, the route is withdrawn first and then the table walk
//! sends the Loc-RIB default, if the outbound policy lets it go.
//!
//! [`DefaultOriginateState`] records which families hold the route. It is
//! kept apart from the Adj-RIB-Out so the Loc-RIB walks never see it.

use std::collections::BTreeSet;
use std::sync::Arc;

use bgp_packet::{Afi, AfiSafi, BgpAttr, Ipv4Nlri, Ipv6Nlri, MpUnreachAttr, Safi};
use bytes::BytesMut;
use ipnet::{Ipv4Net, Ipv6Net};

use super::peer::{BgpTop, Peer};
use super::peer_egress::{EgressDeltaV4, PeerEgressTask};
use super::route::{BgpRib, BgpRibType, ORIGINATED_PEER};

/// The RFC 7911 path id of the route toward an AddPath neighbor. FRR uses
/// the same (`BGP_ADDPATH_TX_ID_FOR_DEFAULT_ORIGINATE`).
pub const ADDPATH_ID: u32 = 1;

/// `afi-safi <name> default-originate`, a presence container. It has no
/// leaf yet: FRR's `default-originate route-map NAME` would be one.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DefaultOriginateConfig {}

/// Whether `afi_safi` takes the statement. The commit check refuses it on
/// any other family.
pub fn supported_family(afi_safi: AfiSafi) -> bool {
    afi_safi.safi == Safi::Unicast && matches!(afi_safi.afi, Afi::Ip | Afi::Ip6)
}

/// The families of one session that hold the originated default.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DefaultOriginateState {
    sent: BTreeSet<Afi>,
}

impl DefaultOriginateState {
    pub fn is_sent(&self, afi: Afi) -> bool {
        self.sent.contains(&afi)
    }

    pub(super) fn set_sent(&mut self, afi: Afi, sent: bool) {
        if sent {
            self.sent.insert(afi);
        } else {
            self.sent.remove(&afi);
        }
    }

    /// The session ended: nothing is held any more.
    pub fn clear(&mut self) {
        self.sent.clear();
    }
}

/// Whether a Loc-RIB row of a `prefix_len` prefix is kept from a neighbor
/// whose statement for the family is `on`: that neighbor gets its own
/// default instead. Only plain unicast rows; a VPN row has a VPN next hop.
pub(super) fn holds_back(on: bool, prefix_len: u8, rib: &BgpRib) -> bool {
    on && prefix_len == 0 && rib.nexthop.is_none()
}

/// Bring the default of `afi` toward `peer` in line with its config: send
/// it while the statement is set and the family is up, and withdraw it once
/// it is not. A route that was sent is sent again, as a soft-out sends every
/// route again.
pub(super) fn sync(peer: &mut Peer, afi: Afi, bgp: &mut BgpTop) {
    if !matches!(afi, Afi::Ip | Afi::Ip6) {
        return;
    }
    let add_path = peer.opt.is_add_path_send(afi, Safi::Unicast);
    let id = if add_path { ADDPATH_ID } else { 0 };
    let on = peer.state.is_established()
        && peer.is_afi_safi(afi, Safi::Unicast)
        && peer.default_originate_config(afi).is_some();
    let built = if on {
        build(peer, afi, id, bgp)
    } else {
        Built::Nothing
    };
    let (packets, sent) = match built {
        Built::Packets(packets) => (packets, true),
        Built::Nothing if peer.default_originate.is_sent(afi) => {
            (vec![withdraw(peer, afi, id)], false)
        }
        Built::Nothing | Built::Waiting => return,
    };
    deliver(peer, afi, id, packets, bgp);
    peer.default_originate.set_sent(afi, sent);
}

/// The UPDATE of the route toward one neighbor.
enum Built {
    Packets(Vec<BytesMut>),
    /// The neighbor cannot be sent the route, such as an IPv6 neighbor with
    /// no IPv6 next hop of ours.
    Nothing,
    /// An extended next hop neighbor whose link-local is not known yet.
    /// `Bgp::enhe_catch_up_v4` syncs again once it is.
    Waiting,
}

/// Build the route as a `network` route of ours goes out: ORIGIN IGP, an
/// AS_PATH with only the eBGP prepend, MED 0, next hop self.
fn build(peer: &mut Peer, afi: Afi, id: u32, bgp: &mut BgpTop) -> Built {
    let mut rib = BgpRib::new(
        ORIGINATED_PEER,
        *bgp.router_id,
        BgpRibType::Originated,
        0,
        0,
        &BgpAttr::new(),
        None,
        None,
        false,
    );
    rib.local_id = id;
    let add_path = id != 0;
    let afi_safi = AfiSafi::new(afi, Safi::Unicast);
    match afi {
        Afi::Ip => {
            let Some(enhe) = super::route::enhe_next_hop(peer, bgp.interface_addrs).for_send()
            else {
                return Built::Waiting;
            };
            let ctx = peer.sync_ctx(*bgp.router_id, bgp.as_sets_withdraw);
            let Some((nlri, mut attr)) =
                super::route::egress_update_ipv4(&ctx, &Ipv4Net::default(), &rib, add_path)
            else {
                return Built::Nothing;
            };
            ctx.post_policy.apply(&mut attr);
            Built::Packets(super::update_group::encode_ipv4_update(
                &Arc::new(attr),
                &[nlri],
                ctx.max_packet_size(),
                ctx.as4,
                enhe,
            ))
        }
        _ => {
            let Some((nlri, mut attr)) =
                super::route::egress_update_ipv6(peer, &Ipv6Net::default(), &rib, bgp, add_path)
            else {
                return Built::Nothing;
            };
            peer.post_policy_filter(afi_safi).apply(&mut attr);
            Built::Packets(super::update_group::encode_ipv6_update(
                &Arc::new(attr),
                &[nlri],
                peer.max_packet_size(),
                peer.as4,
            ))
        }
    }
}

fn withdraw(peer: &Peer, afi: Afi, id: u32) -> BytesMut {
    let mut update = peer.update_packet();
    match afi {
        Afi::Ip => update.ipv4_withdraw.push(Ipv4Nlri {
            id,
            prefix: Ipv4Net::default(),
        }),
        _ => {
            update.mp_withdraw = Some(MpUnreachAttr::Ipv6Nlri(vec![Ipv6Nlri {
                id,
                prefix: Ipv6Net::default(),
            }]))
        }
    }
    update
        .try_emit()
        .expect("one withdrawn route fits in an UPDATE")
}

/// Send `packets` in place of the Loc-RIB default `peer` holds: a row under
/// path id `id` is replaced by them without a withdraw, and a row under
/// another id is withdrawn first. When an egress task sends the peer's IPv4
/// routes, the task holds those rows and does this itself, in order with
/// the routes it is sending.
fn deliver(peer: &mut Peer, afi: Afi, id: u32, packets: Vec<BytesMut>, bgp: &BgpTop) {
    let add_path = peer.opt.is_add_path_send(afi, Safi::Unicast);
    let held = match afi {
        Afi::Ip => peer.adj_out.v4.0.remove(&Ipv4Net::default()),
        _ => peer.adj_out.v6.0.remove(&Ipv6Net::default()),
    };
    if afi == Afi::Ip
        && let Some(task) = egress_task(peer, bgp)
    {
        let _ = task.delta_tx.send(EgressDeltaV4::SendOwn {
            prefix: Ipv4Net::default(),
            id,
            packets,
        });
        return;
    }
    for row in held.unwrap_or_default() {
        let held_id = if add_path { row.local_id } else { 0 };
        if held_id != id {
            peer.send_packet(withdraw(peer, afi, held_id));
        }
    }
    for bytes in packets {
        peer.send_packet(bytes);
    }
}

/// The peer egress task that sends `peer` its IPv4 routes. An update group
/// egress task, when one runs, takes precedence, as on the advertise path.
fn egress_task<'a>(peer: &'a Peer, bgp: &BgpTop) -> Option<&'a PeerEgressTask> {
    let v4 = AfiSafi::new(Afi::Ip, Safi::Unicast);
    let group_task = peer
        .update_group_id
        .get(&v4)
        .and_then(|gid| bgp.update_groups.get(&v4)?.group_by_id(gid))
        .is_some_and(|group| group.task.is_some());
    if group_task { None } else { peer.pet.as_ref() }
}
