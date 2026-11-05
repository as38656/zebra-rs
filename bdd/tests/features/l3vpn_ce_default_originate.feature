@serial
@l3vpn_ce_default_originate
Feature: A VRF CE neighbor with default-originate gets only a default route
  As a service provider running L3VPN over SRv6
  I want `afi-safi <ipv4|ipv6> default-originate` on a VRF CE neighbor to
  send the CE a default route with the PE as next hop, as FRR's
  `neighbor X default-originate` does, so that a CE can be given a default
  route without one in the VRF.

  The route is sent to that CE only. It is not put in the VRF table, so it
  is not exported to the VPN, and the other PE never learns it. As in FRR,
  the outbound policy does not apply to it: the CE has a policy that
  denies every route, and still gets the default route.

  Test Topology:
  ```
   a ---------------- b ---------------- ce
   PE, AS 65000       PE, AS 65000       CE, AS 65100
   exports from       VRF cust:          10.1.0.2, 2001:db8:1e::2
   VRF cust:          10.1.0.1, 2001:db8:1e::1
   192.0.2.64/26
   2001:db8:e1::/48
  ```
  - a-b: IS-IS SRv6 core, iBGP VPNv4/VPNv6.
  - b-ce: eBGP in VRF cust, one IPv4 and one IPv6 session. Each has
    `default-originate` and the outbound policy DENY-ALL.

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

  Scenario: The CE gets the IPv4 default route and nothing else
    Given the test topology exists
    Then show command "show bgp vrf cust" in namespace "b" should eventually contain "192.0.2.64/26"
    And BGP route in "ce" should eventually have "0.0.0.0/0"
    And BGP route in "ce" has "0.0.0.0/0" with "as_path" value "65000"
    And BGP route in "ce" has "0.0.0.0/0" with "next_hop" value "10.1.0.1"
    And BGP route in "ce" does not have "192.0.2.64/26"

  Scenario: The CE gets the IPv6 default route and nothing else
    Given the test topology exists
    Then show command "show bgp vrf cust ipv6" in namespace "b" should eventually contain "2001:db8:e1::/48"
    And show command "show bgp ipv6" in namespace "ce" should eventually contain "::/0"
    And BGP route in "ce" has "::/0" with "as_path" value "65000"
    And BGP route in "ce" has "::/0" with "next_hop" value "2001:db8:1e::1"
    And show command "show bgp ipv6" in namespace "ce" should not contain "2001:db8:e1::/48"

  Scenario: b shows that the default route was sent
    Given the test topology exists
    Then show command "show bgp vrf cust neighbor" in namespace "b" should eventually contain "Default information originate, default sent"
    And show command "show bgp vrf cust neighbor" in namespace "b" should not contain "default not sent"

  Scenario: The default route is in no table and does not reach the other PE
    Given the test topology exists
    Then show command "show bgp vrf cust" in namespace "b" should not contain "0.0.0.0/0"
    And show command "show bgp vrf cust ipv6" in namespace "b" should not contain "::/0"
    And show command "show bgp vpnv4" in namespace "b" should not contain "0.0.0.0/0"
    And show command "show bgp vpnv6" in namespace "b" should not contain "::/0"
    And show command "show bgp vpnv4" in namespace "a" should eventually contain "192.0.2.64/26"
    And show command "show bgp vpnv4" in namespace "a" should not contain "0.0.0.0/0"
    And show command "show bgp vpnv6" in namespace "a" should not contain "::/0"
    And show command "show bgp vrf cust" in namespace "a" should not contain "0.0.0.0/0"
    And show command "show bgp vrf cust ipv6" in namespace "a" should not contain "::/0"

  Scenario: default-originate is refused on a family without a default route
    Given the test topology exists
    Then applying command "set router bgp neighbor 2001:db8::1 afi-safi vpnv4 default-originate" in namespace "b" should be rejected with "vpnv4 takes no default route"

  Scenario: Deleting the statement withdraws the default route
    Given the test topology exists
    When I apply command "delete router bgp vrf cust neighbor 10.1.0.2 afi-safi ipv4 default-originate" in namespace "b"
    And I apply command "delete router bgp vrf cust neighbor 2001:db8:1e::2 afi-safi ipv6 default-originate" in namespace "b"
    Then BGP route in "ce" should eventually not have "0.0.0.0/0"
    And show command "show bgp ipv6" in namespace "ce" should eventually not contain "::/0"
    And BGP session in "ce" to "10.1.0.1" should eventually be "Established"
    And BGP session in "ce" to "2001:db8:1e::1" should eventually be "Established"
    And show command "show bgp vrf cust neighbor" in namespace "b" should not contain "Default information originate"
    And BGP route in "ce" does not have "192.0.2.64/26"

  Scenario: Adding the statement again sends the default route again
    Given the test topology exists
    When I apply command "set router bgp vrf cust neighbor 10.1.0.2 afi-safi ipv4 default-originate" in namespace "b"
    And I apply command "set router bgp vrf cust neighbor 2001:db8:1e::2 afi-safi ipv6 default-originate" in namespace "b"
    Then BGP route in "ce" should eventually have "0.0.0.0/0"
    And show command "show bgp ipv6" in namespace "ce" should eventually contain "::/0"
    And show command "show bgp vpnv4" in namespace "a" should not contain "0.0.0.0/0"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "ce"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "ce"
    Then the test environment should be clean
