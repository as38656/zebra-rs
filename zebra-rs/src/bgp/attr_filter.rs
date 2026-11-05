//! Per-neighbor path-attribute filters.
//!
//! Route-policy decides what a route looks like; these decide which
//! attributes may cross one session at all, from neighbor configuration
//! (`afi-safi <name> send-community`, `afi-safi <name> prefix-sid`) and
//! from where the neighbor sits (a VRF CE peer is outside the provider's
//! VPN). They are plain values so the update-group signature can carry
//! them: two peers whose filters differ never share encoded UPDATEs.

use bgp_packet::BgpAttr;

/// `afi-safi <name> send-community` (FRR `neighbor X send-community`):
/// which community attributes are sent to the neighbor. Each kind is
/// sent unless turned off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SendCommunity {
    /// COMMUNITIES (RFC 1997).
    pub standard: bool,
    /// EXT_COMMUNITIES (RFC 4360) and IPv6 Address Specific Extended
    /// Communities (RFC 5701).
    pub extended: bool,
    /// LARGE_COMMUNITY (RFC 8092).
    pub large: bool,
}

impl Default for SendCommunity {
    fn default() -> Self {
        Self {
            standard: true,
            extended: true,
            large: true,
        }
    }
}

/// One of the community attributes [`SendCommunity`] controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityKind {
    Standard,
    Extended,
    Large,
}

impl SendCommunity {
    pub fn set(&mut self, kind: CommunityKind, send: bool) {
        match kind {
            CommunityKind::Standard => self.standard = send,
            CommunityKind::Extended => self.extended = send,
            CommunityKind::Large => self.large = send,
        }
    }
}

/// `afi-safi <name> prefix-sid` (RFC 8669 §4, §5.1; RFC 9252 §9.2):
/// whether the BGP Prefix-SID attribute may cross this session when it
/// is external. Both directions are closed unless configured.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrefixSidBoundary {
    /// Send the attribute on routes of this family.
    pub send: bool,
    /// Keep the attribute on routes of this family when received.
    pub accept: bool,
}

/// The attribute rules applied to a route after outbound policy: the
/// last change before the route is encoded for one neighbor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PostPolicyFilter {
    pub send_community: SendCommunity,
    /// Remove every Route Target. Route Targets are VPN-internal, so a
    /// VRF CE peer never receives them.
    pub strip_route_targets: bool,
}

impl PostPolicyFilter {
    pub fn apply(&self, attr: &mut BgpAttr) {
        if !self.send_community.standard {
            attr.com = None;
        }
        if !self.send_community.extended {
            attr.remove_extended_communities();
        } else if self.strip_route_targets {
            attr.remove_route_targets();
        }
        if !self.send_community.large {
            attr.lcom = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use bgp_packet::{
        Community, ExtCommunity, ExtCommunitySubType, ExtIpv6CommunityValue,
        IPV6_EXT_COMMUNITY_TYPE_CODE, LargeCommunity, UnknownAttr,
    };
    use bytes::BytesMut;

    use super::*;

    fn ipv6_route_target() -> UnknownAttr {
        let mut value = BytesMut::new();
        ExtIpv6CommunityValue::new(Ipv6Addr::LOCALHOST, 100).encode(&mut value);
        UnknownAttr::new(0xc0, IPV6_EXT_COMMUNITY_TYPE_CODE, value.to_vec())
    }

    fn every_community() -> BgpAttr {
        BgpAttr {
            com: Some(Community::from([0xfde8_0001])),
            ecom: Some(ExtCommunity::from_str("rt:65000:100 soo:65000:7").unwrap()),
            lcom: Some(LargeCommunity::from_str("65000:1:2").unwrap()),
            unknown: vec![ipv6_route_target()],
            ..Default::default()
        }
    }

    fn sending(standard: bool, extended: bool, large: bool) -> PostPolicyFilter {
        PostPolicyFilter {
            send_community: SendCommunity {
                standard,
                extended,
                large,
            },
            strip_route_targets: false,
        }
    }

    #[test]
    fn the_default_filter_changes_nothing() {
        let mut attr = every_community();
        PostPolicyFilter::default().apply(&mut attr);
        assert_eq!(attr, every_community());
    }

    #[test]
    fn standard_off_removes_only_communities() {
        let mut attr = every_community();
        sending(false, true, true).apply(&mut attr);
        assert_eq!(attr.com, None);
        assert_eq!(attr.ecom, every_community().ecom);
        assert_eq!(attr.lcom, every_community().lcom);
    }

    #[test]
    fn extended_off_removes_both_extended_community_attributes() {
        let mut attr = every_community();
        sending(true, false, true).apply(&mut attr);
        assert_eq!(attr.ecom, None);
        assert!(
            attr.unknown.is_empty(),
            "the IPv6 Address Specific Extended Communities go too (RFC 5701)"
        );
        assert_eq!(attr.com, every_community().com);
        assert_eq!(attr.lcom, every_community().lcom);
    }

    #[test]
    fn large_off_removes_only_large_communities() {
        let mut attr = every_community();
        sending(true, true, false).apply(&mut attr);
        assert_eq!(attr.lcom, None);
        assert_eq!(attr.com, every_community().com);
        assert_eq!(attr.ecom, every_community().ecom);
    }

    #[test]
    fn route_target_strip_keeps_other_extended_communities() {
        let mut attr = every_community();
        PostPolicyFilter {
            strip_route_targets: true,
            ..Default::default()
        }
        .apply(&mut attr);
        let kept: Vec<u8> = attr
            .ecom
            .as_ref()
            .unwrap()
            .0
            .iter()
            .map(|v| v.low_type)
            .collect();
        assert_eq!(kept, vec![ExtCommunitySubType::RouteOrigin as u8]);
        assert!(attr.unknown.is_empty(), "the IPv6 Route Target goes");
        assert_eq!(attr.com, every_community().com);
        assert_eq!(attr.lcom, every_community().lcom);
    }
}
