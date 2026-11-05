@serial
@l3vpn_srv6_ce_boundary
Feature: A VRF CE gets no Route Target and no Prefix-SID
  As a service provider running L3VPN over SRv6
  I want the routes a PE sends to a CE to carry no Route Target and no
  BGP Prefix-SID, so that VPN-internal values and SIDs do not leave the
  provider network (RFC 4360, RFC 8669 §5.1, RFC 9252 §9.2).

  A Route Target is never sent to a VRF CE. The Prefix-SID crosses an
  external plain-unicast session only when `prefix-sid send` is set on
  the sending side and `prefix-sid accept` on the receiving side.

  Test Topology:
  ```
   a ---------------- b ---------------- ce
   PE, AS 65000       PE, AS 65000       CE, AS 65100
   exports from       VRF cust:          10.1.0.2, 2001:db8:1e::2
   VRF cust:          10.1.0.1, 2001:db8:1e::1
   192.0.2.64/26
   2001:db8:e1::/48
  ```
  - a-b: IS-IS SRv6 core, iBGP VPNv4/VPNv6. The VPN routes carry
    RT 65000:100 and the End.DT46 service SID of a.
  - b-ce: eBGP in VRF cust, one IPv4 and one IPv6 session. On IPv4, b
    sets `prefix-sid send`; on IPv6 it keeps the default.

  Scenario: Build the topology and bring up every session
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "ce"
    And I connect namespace "a" interface "t-b" to namespace "b" interface "t-a"
    And I connect namespace "b" interface "t-ce" to namespace "ce" interface "t-b"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "ce"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "ce.yaml" to namespace "ce"
    And I wait 30 seconds for BGP to operate
    Then isis neighbor in namespace "b" at level 2 on interface "t-a" should be up
    And BGP session in "b" to "2001:db8::1" should eventually be "Established"
    And BGP session in "ce" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce" to "2001:db8:1e::1" should eventually be "Established"

  Scenario: In VRF cust on b the routes carry the Route Target and the SID
    Given the test topology exists
    Then show command "show bgp vrf cust 192.0.2.64/26" in namespace "b" should eventually contain "SID"
    And show command "show bgp vrf cust 192.0.2.64/26" in namespace "b" should contain "rt:65000:100"
    And show command "show bgp vrf cust ipv6 2001:db8:e1::/48" in namespace "b" should eventually contain "SID"
    And show command "show bgp vrf cust ipv6 2001:db8:e1::/48" in namespace "b" should contain "rt:65000:100"

  Scenario: The CE gets the routes without the Route Target and the SID
    Given the test topology exists
    Then BGP route in "ce" should eventually have "192.0.2.64/26"
    And BGP route in "ce" has "192.0.2.64/26" without "ext_community"
    And show command "show bgp ipv4 192.0.2.64/26" in namespace "ce" should not contain "SID"
    And show command "show bgp ipv6" in namespace "ce" should eventually contain "2001:db8:e1::/48"
    And BGP route in "ce" has "2001:db8:e1::/48" without "ext_community"
    And show command "show bgp ipv6 2001:db8:e1::/48" in namespace "ce" should not contain "SID"

  Scenario: The CE drops the Prefix-SID that b sends on IPv4
    Given the test topology exists
    Then show command "show bgp neighbor 10.1.0.1" in namespace "ce" should contain "Prefix-SID discarded from"
    And show command "show bgp neighbor 2001:db8:1e::1" in namespace "ce" should not contain "Prefix-SID discarded"

  Scenario: With prefix-sid accept the next IPv4 session keeps the SID
    Given the test topology exists
    When I apply command "set router bgp neighbor 10.1.0.1 afi-safi ipv4 prefix-sid accept true" in namespace "ce"
    # The accept knob is read when the session starts.
    And I run "clear bgp ipv4 neighbor 10.1.0.1" in namespace "ce"
    Then BGP session in "ce" to "10.1.0.1" should eventually be "Established"
    And show command "show bgp ipv4 192.0.2.64/26" in namespace "ce" should eventually contain "SID"
    And BGP route in "ce" has "192.0.2.64/26" without "ext_community"
    And show command "show bgp ipv6 2001:db8:e1::/48" in namespace "ce" should not contain "SID"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "ce"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "ce"
    Then the test environment should be clean
