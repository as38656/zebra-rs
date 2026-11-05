@serial
@bgp_ebgp_requires_policy
Feature: eBGP needs a policy before routes move (RFC 8212)
  As a network operator
  I want an external session with no policy in one direction to move no
  route in that direction, so that a missing policy does not leak or
  accept a full table by accident (RFC 8212 §3).

  `router bgp ebgp-requires-policy true` turns the rule on. It is checked
  per family and per direction. The session itself stays up, and binding
  a policy or turning the knob off brings the routes in without a session
  reset. The default is off, so a config without the knob keeps
  exchanging routes without policy.

  Test Topology (one veth link, an IPv4 and an IPv6 session):
  ```
   z1 (AS 65001) ------------------ z2 (AS 65002)
   192.168.0.1                      192.168.0.2
   2001:db8:12::1                   2001:db8:12::2
   10.0.0.1/32, 2001:db8:1::/64     10.0.0.2/32, 2001:db8:2::/64
  ```
  - z1 sets `ebgp-requires-policy true` and binds no policy at start.
  - z2 has no policy and does not set the knob (default).

  Scenario: Build the topology and bring up both sessions
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z2" to namespace "z2" interface "z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    # RFC 8212 does not stop the session, only the routes.
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP session in "z1" to "2001:db8:12::2" should eventually be "Established"
    And BGP session in "z2" to "192.168.0.1" should eventually be "Established"
    And BGP session in "z2" to "2001:db8:12::1" should eventually be "Established"

  Scenario: Without a policy z1 takes no route and sends no route
    Given the test topology exists
    When I wait 5 seconds for BGP to operate
    Then BGP route in "z1" does not have "10.0.0.2/32"
    And show command "show bgp ipv6" in namespace "z1" should not contain "2001:db8:2::/64"
    And BGP route in "z2" does not have "10.0.0.1/32"
    And show command "show bgp ipv6" in namespace "z2" should not contain "2001:db8:1::/64"
    And show command "show bgp summary" in namespace "z1" should contain "(Policy)"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "No policy (RFC 8212)"
    # z2 is at the default, so nothing is closed on its side.
    And show command "show bgp summary" in namespace "z2" should not contain "(Policy)"

  Scenario: An IPv4 inbound policy opens only IPv4 inbound
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 policy in PERMIT-ALL" in namespace "z1"
    Then BGP route in "z1" should eventually have "10.0.0.2/32"
    # The outbound direction and the IPv6 session still have no policy.
    When I wait 3 seconds for BGP to operate
    Then BGP route in "z2" does not have "10.0.0.1/32"
    And show command "show bgp ipv6" in namespace "z1" should not contain "2001:db8:2::/64"
    And show command "show bgp ipv6" in namespace "z2" should not contain "2001:db8:1::/64"

  Scenario: Turning the knob off opens every direction without a session reset
    Given the test topology exists
    When I apply command "set router bgp ebgp-requires-policy false" in namespace "z1"
    # z2 has no policy and no knob, and still takes the routes.
    Then BGP route in "z2" should eventually have "10.0.0.1/32"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:1::/64"
    And show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:2::/64"
    And show command "show bgp summary" in namespace "z1" should not contain "(Policy)"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should not contain "Last reset"
    And show command "show bgp neighbor 2001:db8:12::2" in namespace "z1" should not contain "Last reset"
    And show command "show bgp neighbor 192.168.0.1" in namespace "z2" should not contain "Last reset"
    And show command "show bgp neighbor 2001:db8:12::1" in namespace "z2" should not contain "Last reset"

  Scenario: Turning the knob on again closes the directions with no policy
    Given the test topology exists
    When I apply command "set router bgp ebgp-requires-policy true" in namespace "z1"
    Then BGP route in "z2" should eventually not have "10.0.0.1/32"
    And show command "show bgp ipv6" in namespace "z2" should eventually not contain "2001:db8:1::/64"
    And show command "show bgp ipv6" in namespace "z1" should eventually not contain "2001:db8:2::/64"
    # The IPv4 inbound policy is still bound.
    And BGP route in "z1" has "10.0.0.2/32"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should not contain "Last reset"
    And show command "show bgp neighbor 2001:db8:12::2" in namespace "z1" should not contain "Last reset"

  Scenario: Deleting the knob returns to the default and every direction opens
    Given the test topology exists
    When I apply command "delete router bgp ebgp-requires-policy" in namespace "z1"
    Then BGP route in "z2" should eventually have "10.0.0.1/32"
    And show command "show bgp ipv6" in namespace "z2" should eventually contain "2001:db8:1::/64"
    And show command "show bgp ipv6" in namespace "z1" should eventually contain "2001:db8:2::/64"
    And show command "show bgp summary" in namespace "z1" should not contain "(Policy)"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should not contain "Last reset"
    And show command "show bgp neighbor 2001:db8:12::2" in namespace "z1" should not contain "Last reset"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
