//! The `maximum-prefix` counts of one session's IPv4 unicast routes when
//! the pool workers hold them (N>1).
//!
//! The peer's prefixes are spread over every worker by prefix hash, and
//! the workers run beside the main task, so main cannot count them in
//! its own tables. Each worker publishes the peer's counts in its own
//! slot of a [`PoolPrefixGauge`] after every message for that peer, and
//! main reads the sum when it checks the limit: after each UPDATE and
//! after each worker result for the peer.
//!
//! Main alone would let a peer go far over the limit: the workers can
//! work through a long queue of the peer's batches between two of its
//! checks. So the gauge also holds the limit that closes the session
//! (the gate). The worker that takes the sum over the gate closes the
//! gauge, and from then on every worker drops the peer's new routes
//! unread. Main sees the closed gauge at its next check and ends the
//! session, even when withdrawals have taken the sum back under the
//! limit meanwhile. The overshoot is what the workers take in before one
//! of them sees the sum over the gate: at most one batch (the part of one
//! UPDATE that hashes to one worker) per worker.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::bgp::prefix_limit::{OverLimit, PrefixCounting, PrefixCounts, PrefixLimit};

/// One worker's share of the counts.
#[derive(Debug, Default)]
struct Slot {
    received: AtomicU64,
    accepted: AtomicU64,
}

/// The worker's view when it took the sum over the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateTrip {
    pub count: u64,
    pub max: u32,
}

/// No limit closes the session.
const NO_GATE: u64 = u64::MAX;
/// Set in the gate when it is on the received count.
const GATE_RECEIVED: u64 = 1 << 32;

/// See the module docs.
#[derive(Debug)]
pub struct PoolPrefixGauge {
    slots: Box<[Slot]>,
    /// The limit that closes the session, in one word so that a worker
    /// never reads half of a change: `max` in the low 32 bits, and
    /// [`GATE_RECEIVED`]. [`NO_GATE`] for none.
    gate: AtomicU64,
    closed: AtomicBool,
    tripped: OnceLock<GateTrip>,
}

impl PoolPrefixGauge {
    /// A gauge for `workers` workers, all at zero, with no gate.
    pub fn new(workers: usize) -> Self {
        Self {
            slots: (0..workers).map(|_| Slot::default()).collect(),
            gate: AtomicU64::new(NO_GATE),
            closed: AtomicBool::new(false),
            tripped: OnceLock::new(),
        }
    }

    /// The sum over every worker.
    pub fn counts(&self) -> PrefixCounts {
        self.slots
            .iter()
            .fold(PrefixCounts::default(), |sum, slot| PrefixCounts {
                received: sum.received + slot.received.load(Ordering::Relaxed),
                accepted: sum.accepted + slot.accepted.load(Ordering::Relaxed),
            })
    }

    /// Worker `worker`'s counts after a message for the peer. Closes the
    /// gauge when the sum is now over the gate.
    pub fn publish(&self, worker: usize, counts: PrefixCounts) {
        let slot = &self.slots[worker];
        slot.received.store(counts.received, Ordering::Relaxed);
        slot.accepted.store(counts.accepted, Ordering::Relaxed);
        let gate = self.gate.load(Ordering::Relaxed);
        if gate == NO_GATE {
            return;
        }
        let max = gate as u32;
        let counting = if gate & GATE_RECEIVED != 0 {
            PrefixCounting::Received
        } else {
            PrefixCounting::Accepted
        };
        let count = self.counts().counted(counting);
        if count > u64::from(max) {
            let _ = self.tripped.set(GateTrip { count, max });
            self.closed.store(true, Ordering::Release);
        }
    }

    /// Set the gate from the IPv4 unicast limit in force: only a limit
    /// that closes the session gates.
    pub fn set_gate(&self, limit: Option<&PrefixLimit>) {
        let gate = match limit {
            Some(limit) if matches!(limit.over_limit, OverLimit::Teardown { .. }) => {
                let received = match limit.counting {
                    PrefixCounting::Received => GATE_RECEIVED,
                    PrefixCounting::Accepted => 0,
                };
                u64::from(limit.max) | received
            }
            _ => NO_GATE,
        };
        self.gate.store(gate, Ordering::Relaxed);
    }

    /// Stop taking the peer's routes: the session is ending.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Set when a worker closed the gauge, which main has to act on.
    pub fn tripped(&self) -> Option<GateTrip> {
        self.tripped.get().copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn counts(received: u64, accepted: u64) -> PrefixCounts {
        PrefixCounts { received, accepted }
    }

    fn limit(max: u32, counting: PrefixCounting, over_limit: OverLimit) -> PrefixLimit {
        PrefixLimit {
            max,
            threshold: 75,
            counting,
            over_limit,
        }
    }

    #[test]
    fn the_counts_are_the_sum_of_the_latest_per_worker() {
        let gauge = PoolPrefixGauge::new(3);
        assert_eq!(gauge.counts(), counts(0, 0));
        gauge.publish(0, counts(4, 2));
        gauge.publish(2, counts(1, 1));
        assert_eq!(gauge.counts(), counts(5, 3));
        gauge.publish(0, counts(3, 0));
        assert_eq!(gauge.counts(), counts(4, 1), "a slot is replaced");
    }

    #[test]
    fn without_a_gate_the_gauge_stays_open() {
        let gauge = PoolPrefixGauge::new(2);
        gauge.publish(0, counts(1_000_000, 1_000_000));
        assert!(!gauge.is_closed());
        gauge.set_gate(Some(&limit(10, PrefixCounting::Accepted, OverLimit::Warn)));
        gauge.publish(1, counts(1, 1));
        assert!(!gauge.is_closed(), "warning-only does not gate");
    }

    #[test]
    fn the_worker_that_crosses_the_gate_closes_the_gauge() {
        let gauge = PoolPrefixGauge::new(2);
        let teardown = OverLimit::Teardown { restart: None };
        gauge.set_gate(Some(&limit(10, PrefixCounting::Accepted, teardown)));
        gauge.publish(0, counts(20, 6));
        gauge.publish(1, counts(20, 4));
        assert!(!gauge.is_closed(), "at the limit");
        assert_eq!(gauge.tripped(), None);
        gauge.publish(1, counts(20, 5));
        assert!(gauge.is_closed(), "11 accepted");
        let trip = GateTrip { count: 11, max: 10 };
        assert_eq!(gauge.tripped(), Some(trip));
        gauge.publish(1, counts(0, 0));
        assert!(gauge.is_closed(), "it stays closed");
        gauge.publish(0, counts(40, 40));
        assert_eq!(gauge.tripped(), Some(trip), "the first trip is kept");
    }

    #[test]
    fn force_gates_on_the_received_count() {
        let gauge = PoolPrefixGauge::new(1);
        let restart = Some(Duration::from_secs(60));
        let teardown = OverLimit::Teardown { restart };
        gauge.set_gate(Some(&limit(10, PrefixCounting::Received, teardown)));
        gauge.publish(0, counts(11, 0));
        assert!(gauge.is_closed());
        assert_eq!(gauge.tripped(), Some(GateTrip { count: 11, max: 10 }));
    }

    #[test]
    fn main_closes_the_gauge_and_a_new_gate_reopens_nothing() {
        let gauge = PoolPrefixGauge::new(1);
        gauge.close();
        assert!(gauge.is_closed());
        assert_eq!(gauge.tripped(), None, "main does not trip itself");
        gauge.set_gate(None);
        assert!(gauge.is_closed());
    }
}
