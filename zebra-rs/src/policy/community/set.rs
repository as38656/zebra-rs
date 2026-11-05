// CommunitySet

use std::collections::BTreeSet;

use bgp_packet::BgpAttr;

use super::{CommunityMatcher, match_community_set};

#[derive(Default, Clone, Debug, PartialEq)]
pub struct CommunitySet {
    pub vals: BTreeSet<CommunityMatcher>,
    pub delete: bool,
}

impl CommunitySet {
    pub fn matches(&self, bgp_attr: &BgpAttr) -> bool {
        self.vals.iter().any(|x| match_community_set(x, bgp_attr))
    }

    /// Whether the standard community `value` matches a member: an exact
    /// value, a `*` pattern or a regex.
    pub fn has_standard(&self, value: u32) -> bool {
        self.vals.iter().any(|m| match m {
            CommunityMatcher::Standard(standard) => standard.matches(value),
            CommunityMatcher::Extended(_) => false,
        })
    }
}
