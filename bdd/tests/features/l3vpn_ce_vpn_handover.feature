@serial
@l3vpn_ce_vpn_handover
Feature: The VRF table moves to the VPN route when the CE route goes
  As a service provider with the same prefixes on a local CE and behind
  another PE, like two upstream sessions on two PEs
  I want the kernel VRF table of a PE to point at the other PE's SRv6 SID
  when the local CE route goes, and back at the CE when it returns
  So that customer traffic follows the BGP best path, whichever route
  arrived first.

  On b the CE route arrives first and the VPN route second, so the VPN
  route is not best when it arrives. When the CE route then went away (a
  withdraw, or the CE session going down), BGP selected the VPN route but
  b installed nothing for it: the transport of an import was kept only
  while the import was best.

  Test Topology:
  ```
   x -------------- a ---------------- b -------------- ce
   CE, AS 65200     PE, AS 65000       PE, AS 65000     CE, AS 65100
   10.2.0.2         VRF cust           VRF cust         10.1.0.2
   2001:db8:2e::2   RD 65000:1         RD 65000:2       2001:db8:1e::2
  ```
  - a-b: IS-IS SRv6 core, iBGP VPNv4/VPNv6. a exports with RT 65000:100
    and the End.DT46 SID of its locator fcbb:bbbb:1::/48; b imports it.
  - x-a and b-ce: eBGP in VRF cust, one IPv4 and one IPv6 session each.
  - ce and x announce 192.0.2.64/26 and 2001:db8:e1::/48. The AS paths
    have the same length, so on b the CE route wins as eBGP over iBGP.
  - b exports with RT 65000:200, which a does not import. If a imported
    it, each change on b would make x send its route again and a send it
    to b again; that new copy goes through the import path on b, which
    hid the bug. The waits before each change let earlier copies arrive.

  Scenario: Build the topology and bring up every session
    Given a clean test environment
    When I create namespace "x"
    And I create namespace "a"
    And I create namespace "b"
    And I create namespace "ce"
    And I connect namespace "x" interface "t-a" to namespace "a" interface "t-x"
    And I connect namespace "a" interface "t-b" to namespace "b" interface "t-a"
    And I connect namespace "b" interface "t-ce" to namespace "ce" interface "t-b"
    And I start zebra-rs in namespace "x"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "ce"
    And I apply config "x.yaml" to namespace "x"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "ce.yaml" to namespace "ce"
    And I wait 30 seconds for BGP to operate
    Then isis neighbor in namespace "b" at level 2 on interface "t-a" should be up
    And BGP session in "b" to "2001:db8::1" should eventually be "Established"
    And BGP session in "x" to "10.2.0.1" should eventually be "Established"
    And BGP session in "x" to "2001:db8:2e::1" should eventually be "Established"
    And BGP session in "ce" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce" to "2001:db8:1e::1" should eventually be "Established"

  Scenario: The CE route comes first and is installed
    Given the test topology exists
    Then kernel route "192.0.2.64/26" in vrf "cust" in namespace "b" should eventually contain "via 10.1.0.2"
    And kernel route "2001:db8:e1::/48" in vrf "cust" in namespace "b" should eventually contain "via 2001:db8:1e::2"

  Scenario: The VPN route comes second and the CE route stays best
    Given the test topology exists
    When I apply command "set router bgp afi-safi ipv4 network 192.0.2.64/26" in namespace "x"
    And I apply command "set router bgp afi-safi ipv6 network 2001:db8:e1::/48" in namespace "x"
    Then show command "show bgp vrf cust 192.0.2.64/26" in namespace "b" should eventually contain "65200"
    And show command "show bgp vrf cust ipv6 2001:db8:e1::/48" in namespace "b" should eventually contain "65200"
    And kernel route "192.0.2.64/26" in vrf "cust" in namespace "b" should eventually contain "via 10.1.0.2"
    And kernel route "2001:db8:e1::/48" in vrf "cust" in namespace "b" should eventually contain "via 2001:db8:1e::2"

  # A failed step skips the rest of its scenario, so each family is
  # checked in its own scenario.
  Scenario: The CE withdraws its IPv4 route and b installs the VPN route
    Given the test topology exists
    When I wait 5 seconds
    And I apply command "delete router bgp afi-safi ipv4 network 192.0.2.64/26" in namespace "ce"
    Then kernel route "192.0.2.64/26" in vrf "cust" in namespace "b" should eventually contain "fcbb:bbbb:1"

  Scenario: The CE withdraws its IPv6 route and b installs the VPN route
    Given the test topology exists
    When I apply command "delete router bgp afi-safi ipv6 network 2001:db8:e1::/48" in namespace "ce"
    Then kernel route "2001:db8:e1::/48" in vrf "cust" in namespace "b" should eventually contain "fcbb:bbbb:1"

  Scenario: The CE announces its routes again and b moves back to them
    Given the test topology exists
    When I apply command "set router bgp afi-safi ipv4 network 192.0.2.64/26" in namespace "ce"
    And I apply command "set router bgp afi-safi ipv6 network 2001:db8:e1::/48" in namespace "ce"
    Then kernel route "192.0.2.64/26" in vrf "cust" in namespace "b" should eventually contain "via 10.1.0.2"
    And kernel route "2001:db8:e1::/48" in vrf "cust" in namespace "b" should eventually contain "via 2001:db8:1e::2"

  Scenario: The CE session goes down and b installs the IPv4 VPN route
    Given the test topology exists
    When I wait 5 seconds
    And I stop zebra-rs in namespace "ce"
    Then kernel route "192.0.2.64/26" in vrf "cust" in namespace "b" should eventually contain "fcbb:bbbb:1"

  Scenario: The CE session went down and b installs the IPv6 VPN route
    Given the test topology exists
    Then kernel route "2001:db8:e1::/48" in vrf "cust" in namespace "b" should eventually contain "fcbb:bbbb:1"

  Scenario: The CE session comes back and b moves back to the CE route
    Given the test topology exists
    When I start zebra-rs in namespace "ce"
    And I wait 5 seconds
    And I apply config "ce.yaml" to namespace "ce"
    Then BGP session in "ce" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce" to "2001:db8:1e::1" should eventually be "Established"
    And kernel route "192.0.2.64/26" in vrf "cust" in namespace "b" should eventually contain "via 10.1.0.2"
    And kernel route "2001:db8:e1::/48" in vrf "cust" in namespace "b" should eventually contain "via 2001:db8:1e::2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "x"
    And I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "ce"
    And I delete namespace "x"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "ce"
    Then the test environment should be clean
