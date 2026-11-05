// Large-community matcher.
//
// A `large-community-set` member is one of:
//   - an exact value `A:B:C` (three colon-separated u32s, RFC 8092),
//   - a pattern `A:B:C` where a field may be `*` for any value, such as
//     `64500:*:*`,
//   - a regex pattern matched against the textual `A:B:C` form of
//     each LARGE_COMMUNITIES element on the route.
//
// Parsing tries the exact form first, then the `*` pattern; anything
// else compiles as regex. (Bare patterns without regex metacharacters still parse as
// regex if they aren't valid literal triples — that mirrors how the
// legacy community-set treats fallthrough.)

use std::str::FromStr;

use bgp_packet::{BgpAttr, LargeCommunityValue};

use crate::policy::community::{
    CompiledRegex, parse_pattern_field, pattern_field_matches, pattern_fields,
};

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum LargeCommunityMatcher {
    Exact(LargeCommunityValue),
    Regex(CompiledRegex),
    /// `A:B:C` with `*` for any field, such as `64500:*:*`.
    Wildcard(LargeCommunityPattern),
}

/// A large community pattern: each field is a value or `None` for `*`.
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct LargeCommunityPattern {
    pub global: Option<u32>,
    pub local1: Option<u32>,
    pub local2: Option<u32>,
}

impl std::fmt::Display for LargeCommunityPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::policy::community::fmt_pattern_field;
        write!(
            f,
            "{}:{}:{}",
            fmt_pattern_field(&self.global),
            fmt_pattern_field(&self.local1),
            fmt_pattern_field(&self.local2)
        )
    }
}

impl FromStr for LargeCommunityPattern {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let fields = pattern_fields(input, 3).ok_or(())?;
        Ok(Self {
            global: parse_pattern_field(fields[0])?,
            local1: parse_pattern_field(fields[1])?,
            local2: parse_pattern_field(fields[2])?,
        })
    }
}

impl LargeCommunityPattern {
    pub fn matches(&self, value: &LargeCommunityValue) -> bool {
        pattern_field_matches(self.global, value.global)
            && pattern_field_matches(self.local1, value.local1)
            && pattern_field_matches(self.local2, value.local2)
    }
}

impl LargeCommunityMatcher {
    /// Whether the large community `value` is a member.
    pub fn matches(&self, value: &LargeCommunityValue) -> bool {
        match self {
            LargeCommunityMatcher::Exact(target) => target == value,
            LargeCommunityMatcher::Regex(compiled) => compiled.is_match(&value.to_str()),
            LargeCommunityMatcher::Wildcard(pattern) => pattern.matches(value),
        }
    }
}

fn parse_literal(s: &str) -> Option<LargeCommunityValue> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return None;
    }
    let global = parts[0].parse::<u32>().ok()?;
    let local1 = parts[1].parse::<u32>().ok()?;
    let local2 = parts[2].parse::<u32>().ok()?;
    Some(LargeCommunityValue {
        global,
        local1,
        local2,
    })
}

impl FromStr for LargeCommunityMatcher {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Some(v) = parse_literal(input) {
            return Ok(LargeCommunityMatcher::Exact(v));
        }
        if pattern_fields(input, 3).is_some() {
            return input.parse().map(LargeCommunityMatcher::Wildcard);
        }
        let compiled = CompiledRegex::new(input).map_err(|_| ())?;
        Ok(LargeCommunityMatcher::Regex(compiled))
    }
}

pub fn match_large_community_set(matcher: &LargeCommunityMatcher, bgp_attr: &BgpAttr) -> bool {
    let Some(ref lcom) = bgp_attr.lcom else {
        return false;
    };
    lcom.0.iter().any(|value| matcher.matches(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bgp_packet::LargeCommunity;

    #[test]
    fn parse_exact_triple() {
        let m = LargeCommunityMatcher::from_str("65001:100:200").unwrap();
        let LargeCommunityMatcher::Exact(v) = m else {
            panic!("expected exact");
        };
        assert_eq!(v.global, 65001);
        assert_eq!(v.local1, 100);
        assert_eq!(v.local2, 200);
    }

    #[test]
    fn parse_regex_when_not_a_triple() {
        let m = LargeCommunityMatcher::from_str("^65001:.*:.*$").unwrap();
        let LargeCommunityMatcher::Regex(c) = m else {
            panic!("expected regex");
        };
        assert_eq!(c.pattern(), "^65001:.*:.*$");
    }

    #[test]
    fn match_exact() {
        let mut attr = BgpAttr::new();
        attr.lcom = Some(LargeCommunity::from_str("65001:100:200 65002:300:400").unwrap());

        let m = LargeCommunityMatcher::from_str("65001:100:200").unwrap();
        assert!(match_large_community_set(&m, &attr));

        let m = LargeCommunityMatcher::from_str("65001:100:201").unwrap();
        assert!(!match_large_community_set(&m, &attr));
    }

    #[test]
    fn match_regex() {
        let mut attr = BgpAttr::new();
        attr.lcom = Some(LargeCommunity::from_str("65001:100:200 65002:300:400").unwrap());

        let m = LargeCommunityMatcher::from_str("^65001:.*:.*$").unwrap();
        assert!(match_large_community_set(&m, &attr));

        let m = LargeCommunityMatcher::from_str("^99999:.*").unwrap();
        assert!(!match_large_community_set(&m, &attr));
    }

    #[test]
    fn no_lcom_attr_never_matches() {
        let attr = BgpAttr::new();
        let m = LargeCommunityMatcher::from_str("65001:100:200").unwrap();
        assert!(!match_large_community_set(&m, &attr));
    }

    fn lc(value: &str) -> LargeCommunityValue {
        parse_literal(value).unwrap()
    }

    #[test]
    fn a_star_field_parses_as_a_wildcard() {
        assert_eq!(
            LargeCommunityMatcher::from_str("64500:*:*").unwrap(),
            LargeCommunityMatcher::Wildcard(LargeCommunityPattern {
                global: Some(64500),
                local1: None,
                local2: None,
            })
        );
        assert_eq!(
            LargeCommunityMatcher::from_str("*:1:*").unwrap(),
            LargeCommunityMatcher::Wildcard(LargeCommunityPattern {
                global: None,
                local1: Some(1),
                local2: None,
            })
        );
    }

    #[test]
    fn a_wildcard_compares_each_field() {
        let m = LargeCommunityMatcher::from_str("64500:*:7").unwrap();
        assert!(m.matches(&lc("64500:1:7")));
        assert!(m.matches(&lc("64500:99:7")));
        assert!(!m.matches(&lc("64500:1:8")));
        assert!(!m.matches(&lc("1:64500:7")));
    }

    #[test]
    fn a_large_community_set_wildcard_matches_a_route() {
        let mut attr = BgpAttr::new();
        attr.lcom = Some(LargeCommunity::from_str("65001:100:200").unwrap());
        let m = LargeCommunityMatcher::from_str("*:100:*").unwrap();
        assert!(match_large_community_set(&m, &attr));
        let m = LargeCommunityMatcher::from_str("*:200:*").unwrap();
        assert!(!match_large_community_set(&m, &attr));
    }
}
