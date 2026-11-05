use std::collections::BTreeSet;

use bgp_packet::{BgpAttr, LargeCommunityValue};

use super::{LargeCommunityMatcher, match_large_community_set};

#[derive(Default, Clone, Debug, PartialEq)]
pub struct LargeCommunitySet {
    pub vals: BTreeSet<LargeCommunityMatcher>,
    pub delete: bool,
}

impl LargeCommunitySet {
    pub fn matches(&self, bgp_attr: &BgpAttr) -> bool {
        self.vals
            .iter()
            .any(|m| match_large_community_set(m, bgp_attr))
    }

    /// Whether the large community `value` matches a member.
    pub fn has(&self, value: &LargeCommunityValue) -> bool {
        self.vals.iter().any(|m| m.matches(value))
    }
}
