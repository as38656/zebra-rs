//! Per-neighbor, per-family maximum-prefix: FRR's `neighbor X
//! maximum-prefix N [THRESHOLD] [force] [restart MINUTES | warning-only]`.
//!
//! [`PrefixLimitConfig`] holds the leaves of `afi-safi <name>
//! maximum-prefix` as configured, and [`PrefixLimitConfig::limit`] turns
//! them into the [`PrefixLimit`] in force. At run time
//! [`PrefixLimitState`] decides from one count what happens to a session,
//! and [`PrefixOverflow`] keeps a peer down after it went over its limit.
//! The counts are [`PrefixCounts`]; the shard tables keep them.

use std::time::{Duration, Instant};

use bgp_packet::{Afi, AfiSafi, Safi};

use crate::context::Timer;

/// FRR's default warning threshold, in percent of the limit.
pub const THRESHOLD_DEFAULT: u8 = 75;

/// Whether the prefixes of `afi_safi` are counted: the families the shard
/// tables hold. A limit on another family is refused at commit.
pub fn counted_family(afi_safi: AfiSafi) -> bool {
    matches!(
        (afi_safi.afi, afi_safi.safi),
        (
            Afi::Ip | Afi::Ip6,
            Safi::Unicast | Safi::MplsLabel | Safi::MplsVpn
        )
    )
}

/// The leaves of `afi-safi <name> maximum-prefix`, as configured.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PrefixLimitConfig {
    /// `max`: the limit. The other leaves do nothing without it.
    pub max: Option<u32>,
    /// `threshold`, in percent of `max`.
    pub threshold: Option<u8>,
    /// `warning-only`. The commit check refuses it together with a
    /// non-zero `restart`.
    pub warning_only: bool,
    /// `restart`, in minutes. Absent or 0 keeps the peer down until
    /// `clear bgp`.
    pub restart: Option<u16>,
    /// `force`: count every received prefix, not only the accepted ones.
    pub force: bool,
}

impl PrefixLimitConfig {
    /// The limit in force, or `None` when `max` is not set.
    pub fn limit(&self) -> Option<PrefixLimit> {
        let max = self.max?;
        let counting = if self.force {
            PrefixCounting::Received
        } else {
            PrefixCounting::Accepted
        };
        let over_limit = if self.warning_only {
            OverLimit::Warn
        } else {
            OverLimit::Teardown {
                restart: self
                    .restart
                    .filter(|&minutes| minutes > 0)
                    .map(|minutes| Duration::from_secs(u64::from(minutes) * 60)),
            }
        };
        Some(PrefixLimit {
            max,
            threshold: self.threshold.unwrap_or(THRESHOLD_DEFAULT),
            counting,
            over_limit,
        })
    }
}

/// Which prefixes of a family count against the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixCounting {
    /// Prefixes that passed the inbound policy and the RFC 8212 check:
    /// the peer's rows in the Loc-RIB.
    Accepted,
    /// Every prefix received, before policy: the peer's Adj-RIB-In
    /// (`force`).
    Received,
}

/// What happens when the count goes over the limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverLimit {
    /// Send Cease / Maximum Number of Prefixes Reached and keep the peer
    /// down, until `clear bgp` or, when set, until `restart` has passed.
    Teardown { restart: Option<Duration> },
    /// Log a warning and keep the session (`warning-only`).
    Warn,
}

/// An enabled maximum-prefix for one family of one neighbor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixLimit {
    pub max: u32,
    /// Percent of `max` above which a warning is logged.
    pub threshold: u8,
    pub counting: PrefixCounting,
    pub over_limit: OverLimit,
}

impl PrefixLimit {
    /// The count above which the threshold warning is logged.
    pub fn threshold_count(&self) -> u64 {
        u64::from(self.max) * u64::from(self.threshold) / 100
    }

    /// How the session of `afi_safi` ends at `count`, when this limit
    /// closes it; `None` for a `warning-only` limit.
    pub fn exceeded(&self, afi_safi: AfiSafi, count: u64) -> Option<PrefixLimitExceeded> {
        match self.over_limit {
            OverLimit::Teardown { restart } => Some(PrefixLimitExceeded {
                afi_safi,
                count,
                max: self.max,
                restart,
            }),
            OverLimit::Warn => None,
        }
    }
}

/// The prefix counts of one peer in one family.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PrefixCounts {
    /// Prefixes in the peer's Adj-RIB-In.
    pub received: u64,
    /// Prefixes with a Loc-RIB row from the peer.
    pub accepted: u64,
}

impl PrefixCounts {
    /// The count `counting` selects.
    pub fn counted(&self, counting: PrefixCounting) -> u64 {
        match counting {
            PrefixCounting::Accepted => self.accepted,
            PrefixCounting::Received => self.received,
        }
    }
}

/// What one count means for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixLimitEvent {
    /// The count went above the threshold.
    ThresholdReached,
    /// The count went above a `warning-only` limit.
    LimitWarning,
    /// The count went above the limit; the session must close.
    Exceeded,
}

/// The warnings already given for one family of one session. Each
/// warning is given once when the count goes above its mark, and again
/// only after the count has come back down to it (FRR
/// `bgp_maximum_prefix_overflow`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PrefixLimitState {
    threshold_reached: bool,
    limit_reached: bool,
}

impl PrefixLimitState {
    /// Record `count` against `limit` and say what it means, if anything
    /// new.
    pub fn observe(&mut self, limit: &PrefixLimit, count: u64) -> Option<PrefixLimitEvent> {
        if count > u64::from(limit.max) {
            if self.limit_reached {
                return None;
            }
            self.limit_reached = true;
            return Some(match limit.over_limit {
                OverLimit::Warn => PrefixLimitEvent::LimitWarning,
                OverLimit::Teardown { .. } => PrefixLimitEvent::Exceeded,
            });
        }
        self.limit_reached = false;
        if count > limit.threshold_count() {
            if self.threshold_reached {
                return None;
            }
            self.threshold_reached = true;
            return Some(PrefixLimitEvent::ThresholdReached);
        }
        self.threshold_reached = false;
        None
    }
}

/// A family of a session that went over its limit, and how the session
/// ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixLimitExceeded {
    pub afi_safi: AfiSafi,
    pub count: u64,
    pub max: u32,
    /// When the peer may connect again; `None` waits for `clear bgp`.
    pub restart: Option<Duration>,
}

/// A peer kept down because it went over its limit: FRR's
/// `PEER_STATUS_PREFIX_OVERFLOW`. The peer neither dials nor accepts a
/// connection until `clear bgp`, or until the restart timer fires.
#[derive(Debug)]
pub struct PrefixOverflow {
    pub afi_safi: AfiSafi,
    pub since: Instant,
    /// Fires `Event::PrefixLimitRestart`. `None` waits for `clear bgp`.
    pub restart: Option<Timer>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(max: u32, threshold: u8, over_limit: OverLimit) -> PrefixLimit {
        PrefixLimit {
            max,
            threshold,
            counting: PrefixCounting::Accepted,
            over_limit,
        }
    }

    fn teardown() -> OverLimit {
        OverLimit::Teardown { restart: None }
    }

    #[test]
    fn only_the_shard_families_are_counted() {
        for (afi, safi) in [
            (Afi::Ip, Safi::Unicast),
            (Afi::Ip6, Safi::Unicast),
            (Afi::Ip, Safi::MplsLabel),
            (Afi::Ip6, Safi::MplsLabel),
            (Afi::Ip, Safi::MplsVpn),
            (Afi::Ip6, Safi::MplsVpn),
        ] {
            assert!(counted_family(AfiSafi::new(afi, safi)), "{afi} {safi}");
        }
        for (afi, safi) in [
            (Afi::L2vpn, Safi::Evpn),
            (Afi::Ip, Safi::Flowspec),
            (Afi::Ip, Safi::Rtc),
            (Afi::LinkState, Safi::LinkState),
        ] {
            assert!(!counted_family(AfiSafi::new(afi, safi)), "{afi} {safi}");
        }
    }

    #[test]
    fn no_limit_without_max() {
        let config = PrefixLimitConfig {
            threshold: Some(50),
            warning_only: true,
            force: true,
            ..Default::default()
        };
        assert_eq!(config.limit(), None);
    }

    #[test]
    fn max_alone_takes_the_frr_defaults() {
        let config = PrefixLimitConfig {
            max: Some(1000),
            ..Default::default()
        };
        assert_eq!(config.limit(), Some(limit(1000, 75, teardown())));
    }

    #[test]
    fn every_leaf_reaches_the_limit() {
        let config = PrefixLimitConfig {
            max: Some(10),
            threshold: Some(90),
            restart: Some(5),
            force: true,
            ..Default::default()
        };
        assert_eq!(
            config.limit(),
            Some(PrefixLimit {
                max: 10,
                threshold: 90,
                counting: PrefixCounting::Received,
                over_limit: OverLimit::Teardown {
                    restart: Some(Duration::from_secs(300))
                },
            })
        );
        let config = PrefixLimitConfig {
            max: Some(10),
            warning_only: true,
            ..Default::default()
        };
        assert_eq!(config.limit().unwrap().over_limit, OverLimit::Warn);
    }

    #[test]
    fn restart_zero_keeps_the_peer_down() {
        let config = PrefixLimitConfig {
            max: Some(10),
            restart: Some(0),
            ..Default::default()
        };
        assert_eq!(config.limit().unwrap().over_limit, teardown());
    }

    #[test]
    fn threshold_count_is_a_share_of_max_without_overflow() {
        assert_eq!(limit(1000, 75, teardown()).threshold_count(), 750);
        assert_eq!(limit(10, 75, teardown()).threshold_count(), 7);
        assert_eq!(
            limit(u32::MAX, 100, teardown()).threshold_count(),
            u64::from(u32::MAX)
        );
    }

    #[test]
    fn counted_selects_the_count() {
        let counts = PrefixCounts {
            received: 12,
            accepted: 3,
        };
        assert_eq!(counts.counted(PrefixCounting::Accepted), 3);
        assert_eq!(counts.counted(PrefixCounting::Received), 12);
    }

    #[test]
    fn under_and_at_the_limit_nothing_but_the_threshold() {
        let limit = limit(10, 75, teardown());
        let mut state = PrefixLimitState::default();
        assert_eq!(state.observe(&limit, 0), None);
        assert_eq!(state.observe(&limit, 7), None, "7 is not above 7.5");
        assert_eq!(
            state.observe(&limit, 8),
            Some(PrefixLimitEvent::ThresholdReached)
        );
        assert_eq!(state.observe(&limit, 10), None, "at the limit is allowed");
    }

    #[test]
    fn over_the_limit_exceeds() {
        let limit = limit(10, 75, teardown());
        let mut state = PrefixLimitState::default();
        assert_eq!(state.observe(&limit, 11), Some(PrefixLimitEvent::Exceeded));
    }

    #[test]
    fn the_threshold_warning_is_given_once_per_crossing() {
        let limit = limit(100, 50, teardown());
        let mut state = PrefixLimitState::default();
        assert_eq!(
            state.observe(&limit, 51),
            Some(PrefixLimitEvent::ThresholdReached)
        );
        assert_eq!(state.observe(&limit, 60), None);
        assert_eq!(state.observe(&limit, 51), None);
        assert_eq!(state.observe(&limit, 50), None, "back at the mark");
        assert_eq!(
            state.observe(&limit, 70),
            Some(PrefixLimitEvent::ThresholdReached),
            "a new crossing warns again"
        );
    }

    #[test]
    fn a_warning_only_limit_warns_once_per_crossing() {
        let limit = limit(10, 100, OverLimit::Warn);
        let mut state = PrefixLimitState::default();
        assert_eq!(
            state.observe(&limit, 11),
            Some(PrefixLimitEvent::LimitWarning)
        );
        assert_eq!(state.observe(&limit, 20), None);
        assert_eq!(state.observe(&limit, 10), None, "back at the limit");
        assert_eq!(
            state.observe(&limit, 12),
            Some(PrefixLimitEvent::LimitWarning)
        );
    }

    #[test]
    fn only_a_teardown_limit_ends_the_session() {
        let v4 = AfiSafi::new(Afi::Ip, Safi::Unicast);
        let restart = Some(Duration::from_secs(60));
        assert_eq!(
            limit(10, 75, OverLimit::Teardown { restart }).exceeded(v4, 11),
            Some(PrefixLimitExceeded {
                afi_safi: v4,
                count: 11,
                max: 10,
                restart,
            })
        );
        assert_eq!(limit(10, 75, OverLimit::Warn).exceeded(v4, 11), None);
    }

    #[test]
    fn a_threshold_of_100_never_warns_before_the_limit() {
        let limit = limit(10, 100, teardown());
        let mut state = PrefixLimitState::default();
        assert_eq!(state.observe(&limit, 10), None);
    }
}
