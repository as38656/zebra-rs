use crate::policy::{PolicyList, PrefixSet};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InOut {
    Input,
    Output,
}

#[derive(Default, Debug)]
pub struct InOuts<T> {
    pub input: T,
    pub output: T,
}

impl<T> InOuts<T> {
    pub fn get(&self, direct: &InOut) -> &T {
        match direct {
            InOut::Input => &self.input,
            InOut::Output => &self.output,
        }
    }

    pub fn get_mut(&mut self, direct: &InOut) -> &mut T {
        match direct {
            InOut::Input => &mut self.input,
            InOut::Output => &mut self.output,
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct PrefixSetValue {
    pub name: Option<String>,
    pub prefix_set: Option<PrefixSet>,
}

#[derive(Default, Debug, Clone)]
pub struct PolicyListValue {
    pub name: Option<String>,
    pub policy_list: Option<PolicyList>,
}

/// A peer's *outbound* policy as an owned, thread-crossable snapshot —
/// the resolved prefix-set + policy-list for the Output direction. Cached
/// on the `Peer` (rebuilt only when the out-policy resolves, in
/// `process_policy_msg`) and carried behind an `Arc` in
/// [`super::route::SyncCtx`], so the egress policy evaluation
/// (`route_apply_policy_out`) runs without the full `Peer`: from a
/// `SyncCtx` on the main task today, and from the same `SyncCtx` broadcast
/// into a shard worker later (A2 DumpV4). The `next-hop self` router-id
/// anchor isn't duplicated here — `SyncCtx` already carries it.
#[derive(Default, Debug, Clone)]
pub struct OutPolicy {
    pub prefix_set: PrefixSetValue,
    pub policy_list: PolicyListValue,
}

/// What one direction of a session does with a route when no route-policy
/// and no prefix-set is bound to it.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnboundPolicy {
    /// The route passes unchanged.
    #[default]
    Permit,
    /// The route is dropped: RFC 8212 §3 for an external session under
    /// `ebgp-requires-policy`.
    Deny,
}

/// `ebgp-requires-policy` (RFC 8212), set per BGP instance (`router bgp`
/// and each `router bgp vrf`). RFC 8212 §3 asks for "on" as the default;
/// the default here is off so existing configs keep working.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EbgpRequiresPolicy(pub bool);

impl EbgpRequiresPolicy {
    /// The verdict for a route on a session of `peer_type` when no
    /// policy is bound in its direction.
    pub fn unbound_policy(self, peer_type: super::peer::PeerType) -> UnboundPolicy {
        if self.0 && peer_type.is_ebgp() {
            UnboundPolicy::Deny
        } else {
            UnboundPolicy::Permit
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::peer::PeerType;
    use super::*;

    #[test]
    fn the_default_is_off_so_existing_configs_keep_working() {
        assert_eq!(EbgpRequiresPolicy::default(), EbgpRequiresPolicy(false));
    }

    #[test]
    fn rfc8212_denies_unbound_routes_on_external_sessions_only() {
        let on = EbgpRequiresPolicy(true);
        assert_eq!(on.unbound_policy(PeerType::EBGP), UnboundPolicy::Deny);
        assert_eq!(on.unbound_policy(PeerType::IBGP), UnboundPolicy::Permit);
    }

    #[test]
    fn ebgp_requires_policy_false_permits_unbound_routes() {
        let off = EbgpRequiresPolicy(false);
        assert_eq!(off.unbound_policy(PeerType::EBGP), UnboundPolicy::Permit);
        assert_eq!(off.unbound_policy(PeerType::IBGP), UnboundPolicy::Permit);
    }
}
