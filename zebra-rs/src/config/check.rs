//! Commit-time checks on leaf values the schema cannot constrain.
//!
//! A protocol's config callback cannot reject a value. By the time it
//! runs the commit has been dispatched, and its return is ignored. A
//! value the schema lets through therefore lands in the running config
//! while the protocol quietly keeps its previous setting. Any constraint
//! YANG cannot carry here is checked below, before anything is
//! dispatched: a step (YANG has none), or a decimal64 range or
//! `fraction-digits` (libyang extracts neither).

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use super::Args;
use crate::bgp::ethernet_segment::check_es_esi;
use crate::bgp::prefix_limit::counted_family;
use crate::flex_algo::check_max_link_loss;
use crate::stamp::session::{check_loss_interval, check_loss_percent};

/// The E-Tree leaf-AC list (`router bgp afi-safi evpn etree
/// leaf-interface <name>`), as a callback path.
pub const ETREE_LEAF_PATH: &str = "/router/bgp/afi-safi/etree/leaf-interface";

/// The leaves that turn the cradle data plane on: the managed engine, or
/// the tee to an external one.
const CRADLE_ENABLED_PATHS: [&str; 2] = ["/system/ebpf/enabled", "/system/cradle/enabled"];

/// Whether a config line can carry a leaf [`etree_backend`] reads, so the
/// caller parses only those.
pub fn etree_backend_line(line: &str) -> bool {
    line.contains(" etree leaf-interface ")
        || line.starts_with("system ebpf enabled ")
        || line.starts_with("system cradle enabled ")
}

/// An E-Tree leaf AC needs the cradle data plane: only cradle keeps a leaf
/// from another leaf. The kernel bridge cannot drop by a remote MAC's
/// colour, and a leaf left unisolated is a leak of what E-Tree exists to
/// keep apart (RFC 8317 §7). `leaves` are a whole config's
/// [`etree_backend_line`]s as (callback path, arguments); the result is
/// one error per leaf AC when neither switch is on.
pub fn etree_backend(leaves: &[(String, Vec<String>)]) -> Vec<String> {
    let cradle = leaves.iter().any(|(path, args)| {
        CRADLE_ENABLED_PATHS.contains(&path.as_str())
            && args.last().map(String::as_str) == Some("true")
    });
    if cradle {
        return Vec::new();
    }
    leaves
        .iter()
        .filter(|(path, _)| path == ETREE_LEAF_PATH)
        .filter_map(|(_, args)| args.last())
        .map(|name| {
            format!(
                "etree leaf-interface {name}: E-Tree needs the cradle data plane \
                 (`system ebpf enabled` or `system cradle enabled`); the kernel \
                 bridge cannot keep leaves apart"
            )
        })
        .collect()
}

/// Whether a config line can carry a leaf [`prefix_limit`] reads, so the
/// caller parses only those.
pub fn prefix_limit_line(line: &str) -> bool {
    line.contains(" maximum-prefix ")
}

/// The `maximum-prefix` statements among a whole config's
/// [`prefix_limit_line`]s, as (callback path, arguments), that cannot be
/// applied: a limit on a family whose prefixes are not counted, and
/// `warning-only true` with a non-zero `restart`, which ask for opposite
/// things. One error per neighbor family and problem.
pub fn prefix_limit(leaves: &[(String, Vec<String>)]) -> Vec<String> {
    let mut families = BTreeMap::<PrefixLimitOwner, PrefixLimitLeaves>::new();
    for (path, args) in leaves {
        let Some((owner, leaf, value)) = PrefixLimitOwner::of(path, args) else {
            continue;
        };
        let family = families.entry(owner).or_default();
        match leaf {
            "warning-only" => family.warning_only = value == "true",
            "restart" => family.restart = value != "0",
            _ => {}
        }
    }
    let mut errors = Vec::new();
    for (owner, family) in families {
        let counted = Args(VecDeque::from([owner.afi_safi.clone()]))
            .afi_safi()
            .is_some_and(counted_family);
        if !counted {
            errors.push(format!(
                "{owner}: {} prefixes are not counted; use ipv4, ipv6, \
                 label-v4, label-v6, vpnv4 or vpnv6",
                owner.afi_safi
            ));
        }
        if family.warning_only && family.restart {
            errors.push(format!(
                "{owner}: warning-only and restart cannot be used together"
            ));
        }
    }
    errors
}

const NEIGHBOR_PREFIX_LIMIT_PATH: &str = "/router/bgp/neighbor/afi-safi/maximum-prefix/";
const VRF_NEIGHBOR_PREFIX_LIMIT_PATH: &str = "/router/bgp/vrf/neighbor/afi-safi/maximum-prefix/";

/// One `afi-safi <name> maximum-prefix` container: of a global neighbor
/// when `vrf` is `None`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PrefixLimitOwner {
    vrf: Option<String>,
    neighbor: String,
    afi_safi: String,
}

impl PrefixLimitOwner {
    /// The owner, leaf name and value of a `maximum-prefix` leaf.
    fn of<'a>(path: &'a str, args: &'a [String]) -> Option<(Self, &'a str, &'a str)> {
        let (vrf, leaf, args) = if let Some(leaf) = path.strip_prefix(NEIGHBOR_PREFIX_LIMIT_PATH) {
            (None, leaf, args)
        } else {
            let leaf = path.strip_prefix(VRF_NEIGHBOR_PREFIX_LIMIT_PATH)?;
            let (vrf, args) = args.split_first()?;
            (Some(vrf.clone()), leaf, args)
        };
        let [neighbor, afi_safi, value] = args else {
            return None;
        };
        let owner = Self {
            vrf,
            neighbor: neighbor.clone(),
            afi_safi: afi_safi.clone(),
        };
        Some((owner, leaf, value.as_str()))
    }
}

impl fmt::Display for PrefixLimitOwner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "router bgp")?;
        if let Some(vrf) = &self.vrf {
            write!(f, " vrf {vrf}")?;
        }
        write!(
            f,
            " neighbor {} afi-safi {} maximum-prefix",
            self.neighbor, self.afi_safi
        )
    }
}

/// The leaves of one owner that can conflict.
#[derive(Default)]
struct PrefixLimitLeaves {
    warning_only: bool,
    restart: bool,
}

/// A leaf value check: `Err` holds the reason, shown after the line.
pub type ValueCheck = fn(&str) -> Result<(), String>;

/// The check for the leaf at `path`, the callback path with keys
/// removed (`/router/isis/interface/te-metric/…`), if it has one.
pub fn value_check(path: &str) -> Option<ValueCheck> {
    if path == "/router/isis/flex-algo/exclude-max-link-loss" {
        return Some(|v| check_max_link_loss(v).map(drop));
    }
    // `te-metric measurement loss`, in IS-IS, OSPFv2 and OSPFv3 alike.
    let (_, leaf) = path
        .strip_prefix("/router/")?
        .split_once("/te-metric/measurement/loss/")?;
    match leaf {
        "interval" => Some(|v| check_loss_interval(v).map(drop)),
        "minimum-change" | "accelerated-threshold" | "anomaly-threshold" | "reuse-threshold" => {
            Some(|v| check_loss_percent(v).map(drop))
        }
        _ => None,
    }
}

/// The check for a leaf at `path`, as for [`value_check`], whose values
/// an earlier release took unchecked. A commit setting a bad one is
/// refused like any other, but the startup config is only warned about,
/// as for the MPLS label checks (`config::label_check`): a file an earlier
/// release loaded must not leave the router unconfigured. The protocol's
/// setter ignores the value instead.
pub fn startup_tolerant_check(path: &str) -> Option<ValueCheck> {
    match path {
        "/router/bgp/afi-safi/ethernet-segment/esi" => Some(|v| check_es_esi(v).map(drop)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_leaves_are_checked_in_every_igp() {
        for prefix in [
            "/router/isis/interface",
            "/router/ospf/area/interface",
            "/router/ospfv3/area/interface",
        ] {
            let path = format!("{prefix}/te-metric/measurement/loss/interval");
            let check = value_check(&path).expect(&path);
            assert!(check("60").is_ok());
            assert!(check("45").is_err(), "{path}");
            for leaf in [
                "minimum-change",
                "accelerated-threshold",
                "anomaly-threshold",
                "reuse-threshold",
            ] {
                let path = format!("{prefix}/te-metric/measurement/loss/{leaf}");
                let check = value_check(&path).expect(&path);
                assert!(check("0.5").is_ok());
                assert!(check("100.5").is_err(), "{path}");
            }
        }
        // Leaves YANG already bounds need nothing more.
        assert!(
            value_check("/router/isis/interface/te-metric/measurement/loss/threshold").is_none()
        );
        assert!(value_check("/router/isis/interface/te-metric/measurement/interval").is_none());
    }

    /// The link-loss constraint is bounded by what the wire can carry,
    /// 50.331642 %, not 100 %.
    #[test]
    fn flex_algo_max_link_loss_is_checked() {
        let check = value_check("/router/isis/flex-algo/exclude-max-link-loss").expect("checked");
        assert!(check("5").is_ok());
        assert!(check("50.331642").is_ok());
        assert!(check("50.331643").is_err());
        assert!(check("5.1234567").is_err());
    }

    fn leaf(path: &str, args: &[&str]) -> (String, Vec<String>) {
        (
            path.to_string(),
            args.iter().map(|a| a.to_string()).collect(),
        )
    }

    /// A leaf AC is refused unless the cradle data plane is on, through
    /// either switch, and set to true rather than merely present.
    #[test]
    fn etree_leaf_needs_cradle() {
        let leaf_ac = leaf(ETREE_LEAF_PATH, &["evpn", "ce1"]);
        let errors = etree_backend(std::slice::from_ref(&leaf_ac));
        assert_eq!(errors.len(), 1);
        assert!(
            errors[0].starts_with("etree leaf-interface ce1:"),
            "{errors:?}"
        );
        for path in CRADLE_ENABLED_PATHS {
            assert!(etree_backend(&[leaf_ac.clone(), leaf(path, &["true"])]).is_empty());
            assert_eq!(
                etree_backend(&[leaf_ac.clone(), leaf(path, &["false"])]).len(),
                1,
                "{path} false"
            );
        }
        // No leaf AC, nothing to refuse.
        assert!(etree_backend(&[leaf("/system/ebpf/enabled", &["false"])]).is_empty());
        assert!(etree_backend_line(
            "router bgp afi-safi evpn etree leaf-interface ce1"
        ));
        assert!(etree_backend_line("system ebpf enabled true"));
        assert!(etree_backend_line("system cradle enabled true"));
        assert!(!etree_backend_line("system cradle grpc-endpoint unix:x"));
    }

    const NBR_LIMIT: &str = "/router/bgp/neighbor/afi-safi/maximum-prefix";
    const VRF_LIMIT: &str = "/router/bgp/vrf/neighbor/afi-safi/maximum-prefix";

    /// `warning-only` keeps the session and `restart` restarts a session
    /// that was closed, so one family of one neighbor cannot have both.
    /// `restart 0` means no restart and goes with anything.
    #[test]
    fn prefix_limit_warning_only_excludes_restart() {
        let global = [
            leaf(&format!("{NBR_LIMIT}/max"), &["10.0.0.1", "ipv4", "10"]),
            leaf(
                &format!("{NBR_LIMIT}/warning-only"),
                &["10.0.0.1", "ipv4", "true"],
            ),
            leaf(&format!("{NBR_LIMIT}/restart"), &["10.0.0.1", "ipv4", "5"]),
        ];
        assert_eq!(
            prefix_limit(&global),
            vec![
                "router bgp neighbor 10.0.0.1 afi-safi ipv4 maximum-prefix: \
                 warning-only and restart cannot be used together"
                    .to_string()
            ]
        );
        let vrf = [
            leaf(
                &format!("{VRF_LIMIT}/warning-only"),
                &["red", "10.0.0.2", "ipv6", "true"],
            ),
            leaf(
                &format!("{VRF_LIMIT}/restart"),
                &["red", "10.0.0.2", "ipv6", "1"],
            ),
        ];
        assert_eq!(
            prefix_limit(&vrf),
            vec![
                "router bgp vrf red neighbor 10.0.0.2 afi-safi ipv6 maximum-prefix: \
                 warning-only and restart cannot be used together"
                    .to_string()
            ]
        );

        // Different families, or neighbors, do not meet.
        assert!(
            prefix_limit(&[
                leaf(
                    &format!("{NBR_LIMIT}/warning-only"),
                    &["10.0.0.1", "ipv4", "true"],
                ),
                leaf(&format!("{NBR_LIMIT}/restart"), &["10.0.0.1", "ipv6", "5"]),
                leaf(&format!("{NBR_LIMIT}/restart"), &["10.0.0.3", "ipv4", "5"]),
            ])
            .is_empty()
        );
        // `restart 0` and `warning-only false` ask for nothing.
        assert!(
            prefix_limit(&[
                leaf(
                    &format!("{NBR_LIMIT}/warning-only"),
                    &["10.0.0.1", "ipv4", "true"],
                ),
                leaf(&format!("{NBR_LIMIT}/restart"), &["10.0.0.1", "ipv4", "0"]),
            ])
            .is_empty()
        );
        assert!(
            prefix_limit(&[
                leaf(
                    &format!("{NBR_LIMIT}/warning-only"),
                    &["10.0.0.1", "ipv4", "false"],
                ),
                leaf(&format!("{NBR_LIMIT}/restart"), &["10.0.0.1", "ipv4", "5"]),
            ])
            .is_empty()
        );
    }

    /// Only the families the shard tables hold are counted; a limit on
    /// any other would silently do nothing.
    #[test]
    fn prefix_limit_needs_a_counted_family() {
        for family in ["ipv4", "ipv6", "label-v4", "label-v6", "vpnv4", "vpnv6"] {
            assert!(
                prefix_limit(&[leaf(
                    &format!("{NBR_LIMIT}/max"),
                    &["10.0.0.1", family, "10"]
                )])
                .is_empty(),
                "{family}"
            );
        }
        assert_eq!(
            prefix_limit(&[leaf(
                &format!("{NBR_LIMIT}/max"),
                &["10.0.0.1", "evpn", "10"]
            )]),
            vec![
                "router bgp neighbor 10.0.0.1 afi-safi evpn maximum-prefix: \
                 evpn prefixes are not counted; use ipv4, ipv6, label-v4, \
                 label-v6, vpnv4 or vpnv6"
                    .to_string()
            ]
        );
        assert!(prefix_limit_line(
            "router bgp neighbor 10.0.0.1 afi-safi ipv4 maximum-prefix max 10"
        ));
        assert!(!prefix_limit_line(
            "router bgp neighbor 10.0.0.1 afi-safi ipv4 prefix-sid send true"
        ));
    }

    /// An Ethernet Segment's ESI: well-formed and not reserved (RFC 7432
    /// §5). Only the startup config tolerates a bad one.
    #[test]
    fn es_esi_is_checked() {
        let path = "/router/bgp/afi-safi/ethernet-segment/esi";
        assert!(value_check(path).is_none());
        let check = startup_tolerant_check(path).expect("checked");
        assert!(check("00:11:22:33:44:55:66:77:88:99").is_ok());
        assert!(check("00000000000000000001").is_ok());
        assert!(check("fe:ff:ff:ff:ff:ff:ff:ff:ff:ff").is_ok());
        for bad in [
            "00:00:00:00:00:00:00:00:00:00",
            "00000000000000000000",
            "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff",
            "FFFFFFFFFFFFFFFFFFFF",
            "00:11:22",
            "zz:11:22:33:44:55:66:77:88:99",
        ] {
            assert!(check(bad).is_err(), "{bad}");
        }
    }
}
