//! The envelopes protocols have sent to the RIB, held until it handles
//! them, so the RIB can order and merge them.
//!
//! There are two lanes. BGP fills the RIB with a whole table at a time
//! (a peer going down rewrites every route of that peer), so its lane
//! waits behind the lane of every other protocol: an IGP change is not
//! stuck behind a table of BGP routes. Each lane keeps the order the
//! envelopes came in.
//!
//! A protocol's route add or delete replaces that protocol's route at
//! the prefix as a whole, so once a newer one for the same sender,
//! table, prefix and protocol is queued, an older one still waiting
//! changes nothing in the end. The older one is dropped and the newer
//! one stays at its own place in the lane.

use std::collections::{BTreeMap, VecDeque};

use ipnet::IpNet;

use super::RibType;
use super::client::{ProtoId, RibInbound};
use super::inst::Message;

/// Which lane an envelope waits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Every protocol but BGP, and senders not registered yet.
    Control,
    /// BGP and its per-VRF tasks (`bgp:vrf:<name>`).
    Bulk,
}

impl Lane {
    /// The lane of a sender registered as `proto`, or of one not
    /// registered yet (`None`).
    pub fn of_proto(proto: Option<&str>) -> Self {
        match proto.and_then(|proto| proto.split(':').next()) {
            Some("bgp") => Lane::Bulk,
            _ => Lane::Control,
        }
    }
}

/// What a route add or delete replaces: one protocol's route at one
/// prefix of one table, as one sender sees it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RouteKey {
    from: ProtoId,
    vrf: Option<String>,
    prefix: IpNet,
    rtype: RibType,
}

impl RouteKey {
    /// The key of a route add or delete that a newer one for the same
    /// key makes pointless.
    fn of(env: &RibInbound) -> Option<Self> {
        let (vrf, prefix, rib) = match &env.msg {
            Message::Ipv4Add { prefix, rib } | Message::Ipv4Del { prefix, rib } => {
                (None, IpNet::V4(*prefix), rib)
            }
            Message::Ipv6Add { prefix, rib } | Message::Ipv6Del { prefix, rib } => {
                (None, IpNet::V6(*prefix), rib)
            }
            Message::Ipv4AddVrf { vrf, prefix, rib } | Message::Ipv4DelVrf { vrf, prefix, rib } => {
                (Some(vrf.clone()), IpNet::V4(*prefix), rib)
            }
            Message::Ipv6AddVrf { vrf, prefix, rib } | Message::Ipv6DelVrf { vrf, prefix, rib } => {
                (Some(vrf.clone()), IpNet::V6(*prefix), rib)
            }
            _ => return None,
        };
        // A static add also takes over an earlier run's route at its
        // priority (`Rib::adopt_legacy_static`), so every one counts.
        if !rib.is_protocol() || rib.rtype == RibType::Static {
            return None;
        }
        Some(Self {
            from: env.from,
            vrf,
            prefix,
            rtype: rib.rtype,
        })
    }
}

struct Slot {
    env: RibInbound,
    key: Option<RouteKey>,
}

/// One lane. `head` is the number of slots taken off its front so far,
/// so slot `seq` sits at `slots[seq - head]`. A dropped envelope leaves
/// an empty slot behind.
#[derive(Default)]
struct Queue {
    slots: VecDeque<Option<Slot>>,
    head: u64,
}

impl Queue {
    fn take(&mut self, seq: u64) -> Option<Slot> {
        let index = usize::try_from(seq - self.head).ok()?;
        self.slots.get_mut(index)?.take()
    }
}

/// The envelope queue of the RIB.
#[derive(Default)]
pub struct InboundQueue {
    control: Queue,
    bulk: Queue,
    /// Where the newest queued route add or delete of each key sits.
    latest: BTreeMap<RouteKey, (Lane, u64)>,
    len: usize,
}

impl InboundQueue {
    pub fn new() -> Self {
        Self::default()
    }

    fn queue(&mut self, lane: Lane) -> &mut Queue {
        match lane {
            Lane::Control => &mut self.control,
            Lane::Bulk => &mut self.bulk,
        }
    }

    /// Queue `env` at the end of `lane`, dropping an older route add or
    /// delete it makes pointless.
    pub fn push(&mut self, env: RibInbound, lane: Lane) {
        let key = RouteKey::of(&env);
        let queue = self.queue(lane);
        let seq = queue.head + queue.slots.len() as u64;
        queue.slots.push_back(Some(Slot {
            env,
            key: key.clone(),
        }));
        self.len += 1;
        if let Some(key) = key
            && let Some((older_lane, older)) = self.latest.insert(key, (lane, seq))
            && self.queue(older_lane).take(older).is_some()
        {
            self.len -= 1;
        }
    }

    /// The next envelope to handle: the oldest of the control lane, or
    /// when that is empty, the oldest of the bulk lane.
    pub fn pop(&mut self) -> Option<RibInbound> {
        for lane in [Lane::Control, Lane::Bulk] {
            loop {
                let queue = self.queue(lane);
                let Some(slot) = queue.slots.pop_front() else {
                    break;
                };
                let seq = queue.head;
                queue.head += 1;
                let Some(slot) = slot else {
                    continue;
                };
                self.len -= 1;
                if let Some(key) = slot.key
                    && self.latest.get(&key) == Some(&(lane, seq))
                {
                    self.latest.remove(&key);
                }
                return Some(slot.env);
            }
        }
        None
    }

    /// How many envelopes wait.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use ipnet::{Ipv4Net, Ipv6Net};

    use super::*;
    use crate::rib::entry::RibEntry;
    use crate::rib::inst::IlmEntry;

    const ISIS: ProtoId = ProtoId::from_raw(1);
    const BGP: ProtoId = ProtoId::from_raw(2);
    const VRF_BGP: ProtoId = ProtoId::from_raw(3);

    fn v4(prefix: &str) -> Ipv4Net {
        prefix.parse().unwrap()
    }

    fn route(rtype: RibType, metric: u32) -> RibEntry {
        let mut rib = RibEntry::new(rtype);
        rib.metric = metric;
        rib
    }

    fn add(from: ProtoId, prefix: &str, rtype: RibType, metric: u32) -> RibInbound {
        RibInbound {
            from,
            msg: Message::Ipv4Add {
                prefix: v4(prefix),
                rib: route(rtype, metric),
            },
        }
    }

    fn del(from: ProtoId, prefix: &str, rtype: RibType) -> RibInbound {
        RibInbound {
            from,
            msg: Message::Ipv4Del {
                prefix: v4(prefix),
                rib: route(rtype, 0),
            },
        }
    }

    fn ilm(from: ProtoId, label: u32) -> RibInbound {
        RibInbound {
            from,
            msg: Message::IlmAdd {
                label,
                ilm: IlmEntry::new(RibType::Isis),
            },
        }
    }

    /// What an envelope is, for comparing the order of a whole queue.
    fn describe(env: &RibInbound) -> String {
        let what = match &env.msg {
            Message::Ipv4Add { prefix, rib } => format!("add {prefix} {}", rib.metric),
            Message::Ipv4Del { prefix, .. } => format!("del {prefix}"),
            Message::Ipv6Add { prefix, rib } => format!("add {prefix} {}", rib.metric),
            Message::Ipv4AddVrf { vrf, prefix, rib } => {
                format!("add {vrf} {prefix} {}", rib.metric)
            }
            Message::IlmAdd { label, .. } => format!("ilm {label}"),
            _ => "other".to_string(),
        };
        format!("{} {what}", env.from)
    }

    fn drain(queue: &mut InboundQueue) -> Vec<String> {
        std::iter::from_fn(|| queue.pop())
            .map(|env| describe(&env))
            .collect()
    }

    #[test]
    fn bgp_and_its_vrf_tasks_wait_in_the_bulk_lane() {
        assert_eq!(Lane::of_proto(Some("bgp")), Lane::Bulk);
        assert_eq!(Lane::of_proto(Some("bgp:vrf:INET")), Lane::Bulk);
        for proto in [
            "isis",
            "isis:vrf:a",
            "ospf",
            "ospfv3",
            "pim",
            "static",
            "nd",
        ] {
            assert_eq!(Lane::of_proto(Some(proto)), Lane::Control, "{proto}");
        }
        assert_eq!(Lane::of_proto(None), Lane::Control);
        assert_eq!(Lane::of_proto(Some("bgpx")), Lane::Control);
    }

    #[test]
    fn an_igp_route_goes_before_bgp_routes_queued_earlier() {
        let mut queue = InboundQueue::new();
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 0), Lane::Bulk);
        queue.push(add(BGP, "10.0.2.0/24", RibType::Bgp, 0), Lane::Bulk);
        queue.push(del(ISIS, "10.9.0.0/16", RibType::Isis), Lane::Control);
        assert_eq!(
            drain(&mut queue),
            [
                "proto#1 del 10.9.0.0/16",
                "proto#2 add 10.0.1.0/24 0",
                "proto#2 add 10.0.2.0/24 0",
            ]
        );
    }

    #[test]
    fn each_lane_keeps_the_order_of_arrival() {
        let mut queue = InboundQueue::new();
        queue.push(ilm(ISIS, 16001), Lane::Control);
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 0), Lane::Bulk);
        queue.push(add(ISIS, "10.9.0.0/16", RibType::Isis, 10), Lane::Control);
        queue.push(add(VRF_BGP, "10.0.1.0/24", RibType::Bgp, 0), Lane::Bulk);
        queue.push(ilm(ISIS, 16002), Lane::Control);
        assert_eq!(
            drain(&mut queue),
            [
                "proto#1 ilm 16001",
                "proto#1 add 10.9.0.0/16 10",
                "proto#1 ilm 16002",
                "proto#2 add 10.0.1.0/24 0",
                "proto#3 add 10.0.1.0/24 0",
            ]
        );
    }

    #[test]
    fn a_newer_route_message_drops_the_older_one_and_keeps_its_place() {
        let mut queue = InboundQueue::new();
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 1), Lane::Bulk);
        queue.push(add(BGP, "10.0.2.0/24", RibType::Bgp, 1), Lane::Bulk);
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 2), Lane::Bulk);
        queue.push(add(BGP, "10.0.3.0/24", RibType::Bgp, 1), Lane::Bulk);
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 3), Lane::Bulk);
        assert_eq!(queue.len(), 3);
        assert_eq!(
            drain(&mut queue),
            [
                "proto#2 add 10.0.2.0/24 1",
                "proto#2 add 10.0.3.0/24 1",
                "proto#2 add 10.0.1.0/24 3",
            ]
        );
        assert!(queue.is_empty());
    }

    #[test]
    fn a_delete_drops_a_queued_add_and_an_add_a_queued_delete() {
        let mut queue = InboundQueue::new();
        queue.push(add(ISIS, "10.9.0.0/16", RibType::Isis, 10), Lane::Control);
        queue.push(del(ISIS, "10.9.0.0/16", RibType::Isis), Lane::Control);
        queue.push(del(ISIS, "10.8.0.0/16", RibType::Isis), Lane::Control);
        queue.push(add(ISIS, "10.8.0.0/16", RibType::Isis, 20), Lane::Control);
        assert_eq!(
            drain(&mut queue),
            ["proto#1 del 10.9.0.0/16", "proto#1 add 10.8.0.0/16 20"]
        );
    }

    #[test]
    fn only_the_same_sender_table_prefix_and_protocol_are_merged() {
        let mut queue = InboundQueue::new();
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 1), Lane::Bulk);
        // Another sender, another prefix, another protocol, another
        // family, another VRF: all kept.
        queue.push(add(VRF_BGP, "10.0.1.0/24", RibType::Bgp, 2), Lane::Bulk);
        queue.push(add(BGP, "10.0.1.0/25", RibType::Bgp, 3), Lane::Bulk);
        queue.push(add(BGP, "10.0.1.0/24", RibType::Ospf, 4), Lane::Bulk);
        let v6: Ipv6Net = "2001:db8::/32".parse().unwrap();
        queue.push(
            RibInbound {
                from: BGP,
                msg: Message::Ipv6Add {
                    prefix: v6,
                    rib: route(RibType::Bgp, 5),
                },
            },
            Lane::Bulk,
        );
        for (vrf, metric) in [("a", 6), ("b", 7)] {
            queue.push(
                RibInbound {
                    from: BGP,
                    msg: Message::Ipv4AddVrf {
                        vrf: vrf.to_string(),
                        prefix: v4("10.0.1.0/24"),
                        rib: route(RibType::Bgp, metric),
                    },
                },
                Lane::Bulk,
            );
        }
        assert_eq!(queue.len(), 7);
    }

    #[test]
    fn statics_stale_routes_and_other_messages_are_never_merged() {
        let mut queue = InboundQueue::new();
        // A static add also takes over an earlier run's route at its
        // priority, so every one counts.
        queue.push(add(ISIS, "10.0.1.0/24", RibType::Static, 1), Lane::Control);
        queue.push(add(ISIS, "10.0.1.0/24", RibType::Static, 2), Lane::Control);
        let mut stale = route(RibType::Bgp, 3);
        stale.stale = true;
        for _ in 0..2 {
            queue.push(
                RibInbound {
                    from: BGP,
                    msg: Message::Ipv4Add {
                        prefix: v4("10.0.2.0/24"),
                        rib: stale.clone(),
                    },
                },
                Lane::Bulk,
            );
        }
        queue.push(ilm(ISIS, 16001), Lane::Control);
        queue.push(ilm(ISIS, 16001), Lane::Control);
        assert_eq!(queue.len(), 6);
    }

    #[test]
    fn a_message_already_handed_out_is_not_dropped_by_a_newer_one() {
        let mut queue = InboundQueue::new();
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 1), Lane::Bulk);
        assert_eq!(
            queue.pop().map(|env| describe(&env)).as_deref(),
            Some("proto#2 add 10.0.1.0/24 1")
        );
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 2), Lane::Bulk);
        queue.push(add(BGP, "10.0.2.0/24", RibType::Bgp, 1), Lane::Bulk);
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 3), Lane::Bulk);
        assert_eq!(
            drain(&mut queue),
            ["proto#2 add 10.0.2.0/24 1", "proto#2 add 10.0.1.0/24 3"]
        );
    }

    #[test]
    fn a_sender_that_registers_meanwhile_keeps_its_order() {
        // Its first envelopes came while it was not registered (control
        // lane); the later ones, once it was registered as BGP, wait in
        // the bulk lane. The control lane goes first, so its order holds,
        // and its newer route add still drops the older one.
        let mut queue = InboundQueue::new();
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 1), Lane::Control);
        queue.push(add(BGP, "10.0.2.0/24", RibType::Bgp, 1), Lane::Control);
        queue.push(add(BGP, "10.0.1.0/24", RibType::Bgp, 2), Lane::Bulk);
        assert_eq!(
            drain(&mut queue),
            ["proto#2 add 10.0.2.0/24 1", "proto#2 add 10.0.1.0/24 2"]
        );
    }
}
