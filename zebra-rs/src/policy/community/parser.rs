// BGP Community Matcher Implementation
//
// This module provides parsing and matching functionality for BGP community-set
// policy configuration. Community-sets can match either standard BGP communities
// or extended communities (route-target, site-of-origin).
//
// # Supported Formats
//
// ## Extended Community Matching
//
// Route Target (exact match):
// ```
// community-set TENANT-A {
//   member {
//     rt:62692:100;        // ASN:value format
//     rt:1.2.3.4:100;      // IP:value format
//   };
// }
// ```
//
// Route Target (regex match):
// ```
// community-set TENANT-A-REGEX {
//   member {
//     rt:^62692:.*$;       // Match all communities from AS 62692
//     rt:62692:.*0$;       // Match communities ending with 0
//   };
// }
// ```
//
// Site of Origin:
// ```
// community-set TENANT-B {
//   member {
//     soo:62692:100;       // Exact match
//     soo:^100:.*$;        // Regex match
//   };
// }
// ```
//
// ## Standard Community Matching
//
// Well-known communities:
// ```
// community-set WELL-KNOWN {
//   member {
//     no-export;           // Well-known community value
//     no-advertise;        // Another well-known value
//   };
// }
// ```
//
// Standard community exact match:
// ```
// community-set TENANT-A-COM {
//   member {
//     100:200;             // Exact match for AS:value format
//     65000:100;           // Another exact match
//   };
// }
// ```
//
// Standard community regex match:
// ```
// community-set TENANT-A-REGEX {
//   member {
//     ^100:.*$;            // Match all communities from AS 100
//     .*:200$;             // Match all communities with value 200
//   };
// }
// ```
//
// Standard community pattern match (`*` is any value of a whole field):
// ```
// community-set FROM-64500 {
//   member {
//     64500:*;             // Every community of AS 64500
//     *:1001;              // Every community with value 1001
//   };
// }
// ```
//
// # Implementation Details
//
// - Extended communities support both exact and regex pattern matching
// - Regex patterns are applied to the value portion after the prefix (rt:/soo:)
// - Subtype filtering ensures rt: patterns only match route-target communities
// - Invalid regex patterns return false without panicking

use std::str::FromStr;

use bgp_packet::*;
use regex::Regex;

/// A pre-compiled regex pattern for efficient matching.
/// Stores both the pattern string (for comparison/display) and compiled regex.
#[derive(Clone)]
pub struct CompiledRegex {
    pattern: String,
    regex: Regex,
}

impl CompiledRegex {
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        let regex = Regex::new(pattern)?;
        Ok(Self {
            pattern: pattern.to_string(),
            regex,
        })
    }

    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }

    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

impl std::fmt::Debug for CompiledRegex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRegex")
            .field("pattern", &self.pattern)
            .finish()
    }
}

impl PartialEq for CompiledRegex {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for CompiledRegex {}

impl PartialOrd for CompiledRegex {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CompiledRegex {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.pattern.cmp(&other.pattern)
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum StandardMatcher {
    Exact(CommunityValue),
    Regex(CompiledRegex),
    /// `ASN:VALUE` with `*` for any field, such as `64500:*`.
    Wildcard(CommunityPattern),
}

/// A standard community pattern: each field is a value or `None` for
/// `*`. It compares whole fields, unlike a regex over the text form.
#[derive(Debug, Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
pub struct CommunityPattern {
    pub asn: Option<u16>,
    pub value: Option<u16>,
}

/// One field of a community pattern: a value, or `*` for any.
pub(crate) fn fmt_pattern_field<T: std::fmt::Display>(field: &Option<T>) -> String {
    match field {
        Some(value) => value.to_string(),
        None => "*".to_string(),
    }
}

impl std::fmt::Display for CommunityPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            fmt_pattern_field(&self.asn),
            fmt_pattern_field(&self.value)
        )
    }
}

/// The fields of a community pattern such as `64500:*`: `count` fields
/// split by `:`, each `*` or a decimal number, at least one `*`. `None`
/// when `input` has another shape. A field is `None` for `*`.
pub(crate) fn pattern_fields(input: &str, count: usize) -> Option<Vec<Option<&str>>> {
    let fields: Vec<&str> = input.split(':').collect();
    let is_number = |f: &str| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit());
    let shaped = fields.len() == count
        && fields.iter().all(|f| *f == "*" || is_number(f))
        && fields.contains(&"*");
    shaped.then(|| {
        fields
            .into_iter()
            .map(|f| (f != "*").then_some(f))
            .collect()
    })
}

/// One field of a pattern: `None` for `*`, else a value that must fit `T`.
pub(crate) fn parse_pattern_field<T: FromStr>(field: Option<&str>) -> Result<Option<T>, ()> {
    field.map(|f| f.parse::<T>().map_err(|_| ())).transpose()
}

/// Whether a pattern field accepts `value`.
pub(crate) fn pattern_field_matches<T: PartialEq>(field: Option<T>, value: T) -> bool {
    field.is_none_or(|f| f == value)
}

impl FromStr for CommunityPattern {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let fields = pattern_fields(input, 2).ok_or(())?;
        Ok(Self {
            asn: parse_pattern_field(fields[0])?,
            value: parse_pattern_field(fields[1])?,
        })
    }
}

impl CommunityPattern {
    pub fn matches(&self, value: u32) -> bool {
        pattern_field_matches(self.asn, (value >> 16) as u16)
            && pattern_field_matches(self.value, value as u16)
    }
}

impl StandardMatcher {
    /// Whether the community `value` is a member.
    pub fn matches(&self, value: u32) -> bool {
        match self {
            StandardMatcher::Exact(target) => target.0 == value,
            StandardMatcher::Regex(compiled) => compiled.is_match(&CommunityValue(value).to_str()),
            StandardMatcher::Wildcard(pattern) => pattern.matches(value),
        }
    }
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum ExtendedMatcher {
    Exact(ExtCommunityValue),
    Regex(ExtCommunitySubType, CompiledRegex),
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub enum CommunityMatcher {
    Standard(StandardMatcher),
    Extended(ExtendedMatcher),
}

impl FromStr for CommunityMatcher {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if let Some(value_str) = input.strip_prefix("rt:") {
            // Try to parse as exact route target (e.g., "rt:100:200" or "rt:1.2.3.4:100")
            if let Ok(ext_com) = ExtCommunity::from_str(input) {
                // Successfully parsed as exact extended community
                if let Some(first) = ext_com.0.first() {
                    return Ok(CommunityMatcher::Extended(ExtendedMatcher::Exact(
                        first.clone(),
                    )));
                }
            }

            // If exact parse failed, treat as regex pattern (e.g., "rt:^62692:.*$")
            let Ok(compiled) = CompiledRegex::new(value_str) else {
                return Err(());
            };
            return Ok(CommunityMatcher::Extended(ExtendedMatcher::Regex(
                ExtCommunitySubType::RouteTarget,
                compiled,
            )));
        }

        if let Some(value_str) = input.strip_prefix("soo:") {
            // Try to parse as exact site of origin (e.g., "soo:100:200")
            if let Ok(ext_com) = ExtCommunity::from_str(input)
                && let Some(first) = ext_com.0.first()
            {
                return Ok(CommunityMatcher::Extended(ExtendedMatcher::Exact(
                    first.clone(),
                )));
            }

            // If exact parse failed, treat as regex pattern
            let Ok(compiled) = CompiledRegex::new(value_str) else {
                return Err(());
            };
            return Ok(CommunityMatcher::Extended(ExtendedMatcher::Regex(
                ExtCommunitySubType::RouteOrigin,
                compiled,
            )));
        }

        if pattern_fields(input, 2).is_some() {
            let pattern = input.parse()?;
            return Ok(CommunityMatcher::Standard(StandardMatcher::Wildcard(
                pattern,
            )));
        }

        // Check if input looks like a regex pattern (contains special regex chars)
        let has_regex_chars = input.contains('^')
            || input.contains('$')
            || input.contains('*')
            || input.contains('.')
            || input.contains('[')
            || input.contains(']')
            || input.contains('(')
            || input.contains(')')
            || input.contains('|')
            || input.contains('+')
            || input.contains('?');

        if has_regex_chars {
            // Definitely a regex pattern
            let Ok(compiled) = CompiledRegex::new(input) else {
                return Err(());
            };
            return Ok(CommunityMatcher::Standard(StandardMatcher::Regex(compiled)));
        }

        // Try to parse as standard community (e.g., "100:200")
        if let Some(com_val) = CommunityValue::from_readable_str(input) {
            return Ok(CommunityMatcher::Standard(StandardMatcher::Exact(com_val)));
        }

        // If it doesn't parse as exact value and no regex chars, treat as simple regex
        let Ok(compiled) = CompiledRegex::new(input) else {
            return Err(());
        };
        Ok(CommunityMatcher::Standard(StandardMatcher::Regex(compiled)))
    }
}

pub fn match_community_set(matcher: &CommunityMatcher, bgp_attr: &BgpAttr) -> bool {
    match matcher {
        CommunityMatcher::Standard(standard_matcher) => {
            // Check standard community attribute
            let Some(ref community) = bgp_attr.com else {
                return false;
            };
            community
                .0
                .iter()
                .any(|value| standard_matcher.matches(*value))
        }
        CommunityMatcher::Extended(extended_matcher) => {
            // Check extended community attribute
            let Some(ref ecom) = bgp_attr.ecom else {
                return false;
            };

            match extended_matcher {
                ExtendedMatcher::Exact(target_value) => {
                    // Check if any extended community matches exactly
                    // tracing::info!("{} <=> {}", ecom, target_value);

                    for ext_com_val in &ecom.0 {
                        if ext_com_val.high_type == target_value.high_type
                            && ext_com_val.low_type == target_value.low_type
                            && ext_com_val.val == target_value.val
                        {
                            // tracing::info!(" -> true");
                            return true;
                        }
                    }
                    // tracing::info!(" -> false");
                    false
                }
                ExtendedMatcher::Regex(sub_type, compiled) => {
                    // Filter by subtype and match against pre-compiled regex
                    // Use IntoPrimitive derive to convert ExtCommunitySubType to u8
                    let target_low_type: u8 = (*sub_type).into();

                    for ext_com_val in &ecom.0 {
                        // Only match communities of the correct subtype
                        if ext_com_val.low_type == target_low_type {
                            let ext_com_str = ext_com_val.to_string();
                            // Remove the prefix (e.g., "rt:" or "soo:") before matching
                            // The to_string() produces "rt:100:200", but pattern is "^100:.*"
                            if let Some(value_part) = ext_com_str.split_once(':')
                                && compiled.is_match(value_part.1)
                            {
                                return true;
                            }
                        }
                    }
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_parse_no_export() {
        let result = CommunityMatcher::from_str("no-export");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Standard(StandardMatcher::Exact(val))) = result {
            assert_eq!(val, CommunityValue::NO_EXPORT);
        } else {
            panic!("Expected Standard exact match for no-export");
        }
    }

    #[test]
    fn test_parse_rt_exact_asn() {
        let result = CommunityMatcher::from_str("rt:100:200");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Extended(ExtendedMatcher::Exact(val))) = result {
            assert_eq!(val.low_type, 0x02); // Route Target
        } else {
            panic!("Expected Extended exact match for rt:100:200");
        }
    }

    #[test]
    fn test_parse_rt_exact_ip() {
        let result = CommunityMatcher::from_str("rt:1.2.3.4:100");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Extended(ExtendedMatcher::Exact(val))) = result {
            assert_eq!(val.low_type, 0x02); // Route Target
        } else {
            panic!("Expected Extended exact match for rt:1.2.3.4:100");
        }
    }

    #[test]
    fn test_parse_rt_regex() {
        let result = CommunityMatcher::from_str("rt:62692:.*");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Extended(ExtendedMatcher::Regex(sub_type, compiled))) = result {
            assert_eq!(sub_type, ExtCommunitySubType::RouteTarget);
            assert_eq!(compiled.pattern(), "62692:.*");
        } else {
            panic!("Expected Extended regex match for rt:62692:.*");
        }
    }

    #[test]
    fn test_parse_soo_exact() {
        let result = CommunityMatcher::from_str("soo:62692:100");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Extended(ExtendedMatcher::Exact(val))) = result {
            assert_eq!(val.low_type, 0x03); // Site of Origin
        } else {
            panic!("Expected Extended exact match for soo:62692:100");
        }
    }

    #[test]
    fn test_parse_soo_regex() {
        let result = CommunityMatcher::from_str("soo:100:.*");
        assert!(result.is_ok());
        if let Ok(CommunityMatcher::Extended(ExtendedMatcher::Regex(sub_type, compiled))) = result {
            assert_eq!(sub_type, ExtCommunitySubType::RouteOrigin);
            assert_eq!(compiled.pattern(), "100:.*");
        } else {
            panic!("Expected Extended regex match for soo:100:.*");
        }
    }

    #[test]
    fn test_match_standard_community_exact() {
        // Create a BGP attribute with standard community
        let mut bgp_attr = BgpAttr::new();
        bgp_attr.com = Some(Community::from([
            CommunityValue::from_readable_str("100:200").unwrap().0,
            CommunityValue::from_readable_str("300:400").unwrap().0,
        ]));

        // Test exact match - should find 100:200
        let matcher = CommunityMatcher::from_str("100:200").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test exact match - should find 300:400
        let matcher = CommunityMatcher::from_str("300:400").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test no match - different value
        let matcher = CommunityMatcher::from_str("500:600").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test with no-export
        let matcher = CommunityMatcher::from_str("no-export").unwrap();
        let mut bgp_attr_export = BgpAttr::new();
        bgp_attr_export.com = Some(Community::from([CommunityValue::NO_EXPORT.0]));
        assert!(match_community_set(&matcher, &bgp_attr_export));

        // Test no match
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_standard_community_regex() {
        // Create a BGP attribute with standard communities
        let mut bgp_attr = BgpAttr::new();
        bgp_attr.com = Some(Community::from([
            CommunityValue::from_readable_str("100:200").unwrap().0,
            CommunityValue::from_readable_str("100:300").unwrap().0,
            CommunityValue::from_readable_str("200:400").unwrap().0,
        ]));

        // Test regex match - should match 100:*
        let matcher = CommunityMatcher::from_str("^100:.*").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test regex match with end anchor
        let matcher = CommunityMatcher::from_str("100:.*0$").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test regex no match
        let matcher = CommunityMatcher::from_str("^300:.*").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test regex partial match (without anchors) - matches substring
        let matcher = CommunityMatcher::from_str(":200").unwrap();
        // This should match "100:200" because it contains ":200"
        assert!(match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_exact_rt() {
        // Create a BGP attribute with extended community (route target)
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("rt:100:200").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Test exact match - should find rt:100:200
        let matcher = CommunityMatcher::from_str("rt:100:200").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test no match - different value
        let matcher = CommunityMatcher::from_str("rt:100:300").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test no match - different type (soo instead of rt)
        let matcher = CommunityMatcher::from_str("soo:100:200").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_exact_ip() {
        // Create a BGP attribute with IP-based extended community
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("rt:1.2.3.4:100").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Test exact match
        let matcher = CommunityMatcher::from_str("rt:1.2.3.4:100").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test no match - different IP
        let matcher = CommunityMatcher::from_str("rt:1.2.3.5:100").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_regex_rt() {
        // Create a BGP attribute with multiple route targets (using actual values, not regex)
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("rt:62692:100 rt:62692:200 soo:100:300").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Test regex match - pattern should match rt:62692:*
        let matcher = CommunityMatcher::from_str("rt:^62692:.*").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test regex no match - different ASN pattern
        let matcher = CommunityMatcher::from_str("rt:99999:.*").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test that soo regex doesn't match rt values
        let matcher = CommunityMatcher::from_str("soo:62692:.*").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test that rt regex matches with $.
        let matcher = CommunityMatcher::from_str("rt:62692:.*$").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test that rt regex matches with $.
        let matcher = CommunityMatcher::from_str("rt:62692:.*0$").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test that rt regex matches with $.
        let matcher = CommunityMatcher::from_str("rt:62692:.*1$").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test that rt regex matches with $.
        let matcher = CommunityMatcher::from_str("rt:692:.*$").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test that rt regex matches with $.
        let matcher = CommunityMatcher::from_str("rt:^692:.*$").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_regex_soo() {
        // Create a BGP attribute with site of origin (using actual values, not regex)
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("soo:100:200 soo:100:300").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Test regex match - pattern should match soo:100:*
        let matcher = CommunityMatcher::from_str("soo:100:.*").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Test regex no match
        let matcher = CommunityMatcher::from_str("soo:200:.*").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_no_community_attribute() {
        // Create a BGP attribute without any communities
        let bgp_attr = BgpAttr::new();

        // Test standard community matcher - should return false
        let matcher = CommunityMatcher::from_str("no-export").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));

        // Test extended community matcher - should return false
        let matcher = CommunityMatcher::from_str("rt:100:200").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_multiple_values() {
        // Create a BGP attribute with multiple different extended communities
        let mut bgp_attr = BgpAttr::new();
        let ecom = ExtCommunity::from_str("rt:100:200 rt:1.2.3.4:300 soo:400:500").unwrap();
        bgp_attr.ecom = Some(ecom);

        // Should match first rt
        let matcher = CommunityMatcher::from_str("rt:100:200").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Should match second rt (IP-based)
        let matcher = CommunityMatcher::from_str("rt:1.2.3.4:300").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Should match soo
        let matcher = CommunityMatcher::from_str("soo:400:500").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));

        // Should not match non-existent value
        let matcher = CommunityMatcher::from_str("rt:999:999").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }

    #[test]
    fn test_match_extended_community_invalid_regex() {
        // Test that invalid regex pattern fails at parse time
        let result = CommunityMatcher::from_str("rt:[invalid(regex");
        assert!(result.is_err());
    }

    fn standard(input: &str) -> StandardMatcher {
        match CommunityMatcher::from_str(input) {
            Ok(CommunityMatcher::Standard(m)) => m,
            other => panic!("{input}: expected a standard matcher, got {other:?}"),
        }
    }

    fn com(value: &str) -> u32 {
        CommunityValue::from_readable_str(value).unwrap().0
    }

    #[test]
    fn a_star_field_parses_as_a_wildcard() {
        assert_eq!(
            standard("64500:*"),
            StandardMatcher::Wildcard(CommunityPattern {
                asn: Some(64500),
                value: None,
            })
        );
        assert_eq!(
            standard("*:1001"),
            StandardMatcher::Wildcard(CommunityPattern {
                asn: None,
                value: Some(1001),
            })
        );
        assert_eq!(
            standard("*:*"),
            StandardMatcher::Wildcard(CommunityPattern {
                asn: None,
                value: None,
            })
        );
    }

    #[test]
    fn a_wildcard_with_a_field_out_of_range_is_rejected() {
        assert!(CommunityMatcher::from_str("65536:*").is_err());
        assert!(CommunityMatcher::from_str("*:65536").is_err());
    }

    #[test]
    fn a_wildcard_compares_whole_fields() {
        let m = standard("64500:*");
        assert!(m.matches(com("64500:1")));
        assert!(m.matches(com("64500:65535")));
        assert!(!m.matches(com("1:64500")), "not a substring match");
        assert!(!m.matches(com("645:1")));

        let m = standard("*:1001");
        assert!(m.matches(com("65000:1001")));
        assert!(!m.matches(com("1001:1")));
    }

    #[test]
    fn exact_and_regex_members_match_values_as_before() {
        assert!(standard("100:200").matches(com("100:200")));
        assert!(!standard("100:200").matches(com("100:201")));
        assert!(standard("^100:.*$").matches(com("100:7")));
        assert!(!standard("^100:.*$").matches(com("1000:7")));
    }

    #[test]
    fn a_community_set_wildcard_matches_a_route() {
        let mut bgp_attr = BgpAttr::new();
        bgp_attr.com = Some(Community::from([com("65000:1001")]));
        let matcher = CommunityMatcher::from_str("*:1001").unwrap();
        assert!(match_community_set(&matcher, &bgp_attr));
        let matcher = CommunityMatcher::from_str("64500:*").unwrap();
        assert!(!match_community_set(&matcher, &bgp_attr));
    }
}
