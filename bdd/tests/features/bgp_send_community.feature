@serial
@bgp_send_community
Feature: Per-neighbor send-community and community delete by pattern
  As a network operator
  I want to choose per neighbor and family which community attributes are
  sent (`afi-safi <name> send-community standard|extended|large`), after
  the outbound policy has run, and I want `set community ... delete` to
  remove every value that matches a pattern such as `*:2`.

  Test Topology (one veth link, IPv4 eBGP):
  ```
   z1 (AS 65001) ------------------ z2 (AS 65002)
   192.168.0.1                      192.168.0.2
  ```
  - z1 advertises 10.0.0.1/32. Its outbound policy sets the communities
    65001:1 65001:2, the extended community soo:65001:7 and the large
    communities 65001:1:1 65001:1:9.
  - z2's inbound policy deletes the standard communities that match `*:2`
    and the large communities that match `*:*:9`.

  Scenario: Build the topology and bring up the session
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "z2"
    And I connect namespace "z1" interface "z2" to namespace "z2" interface "z1"
    And I start zebra-rs in namespace "z1"
    And I start zebra-rs in namespace "z2"
    And I apply config "z1.yaml" to namespace "z1"
    And I apply config "z2.yaml" to namespace "z2"
    And I wait 5 seconds for BGP to operate
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP session in "z2" to "192.168.0.1" should eventually be "Established"

  Scenario: Every kind arrives and the pattern delete removes the matching values
    Given the test topology exists
    Then BGP route in "z2" should eventually have "10.0.0.1/32"
    And BGP route in "z2" has "10.0.0.1/32" with "community" value "65001:1"
    And BGP route in "z2" has "10.0.0.1/32" with "ext_community" value "soo:65001:7"
    And BGP route in "z2" has "10.0.0.1/32" with "large_community" value "65001:1:1"

  Scenario: send-community standard false drops only the standard communities
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 send-community standard false" in namespace "z1"
    Then show command "show bgp ipv4 10.0.0.1/32" in namespace "z2" should eventually not contain "Community: 65001:1"
    And BGP route in "z2" has "10.0.0.1/32" with "ext_community" value "soo:65001:7"
    And BGP route in "z2" has "10.0.0.1/32" with "large_community" value "65001:1:1"

  Scenario: send-community extended false drops the extended communities
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 send-community extended false" in namespace "z1"
    Then show command "show bgp ipv4 10.0.0.1/32" in namespace "z2" should eventually not contain "Extended community:"
    And BGP route in "z2" has "10.0.0.1/32" with "large_community" value "65001:1:1"

  Scenario: send-community large false drops the large communities
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 send-community large false" in namespace "z1"
    Then show command "show bgp ipv4 10.0.0.1/32" in namespace "z2" should eventually not contain "Large community:"
    And BGP route in "z2" has "10.0.0.1/32" without "community"
    And BGP route in "z2" has "10.0.0.1/32" without "ext_community"

  Scenario: Deleting the knobs sends every kind again
    Given the test topology exists
    When I apply command "delete router bgp neighbor 192.168.0.2 afi-safi ipv4 send-community standard" in namespace "z1"
    And I apply command "delete router bgp neighbor 192.168.0.2 afi-safi ipv4 send-community extended" in namespace "z1"
    And I apply command "delete router bgp neighbor 192.168.0.2 afi-safi ipv4 send-community large" in namespace "z1"
    Then show command "show bgp ipv4 10.0.0.1/32" in namespace "z2" should eventually contain "Large community: 65001:1:1"
    And BGP route in "z2" has "10.0.0.1/32" with "community" value "65001:1"
    And BGP route in "z2" has "10.0.0.1/32" with "ext_community" value "soo:65001:7"
    And BGP route in "z2" has "10.0.0.1/32" with "large_community" value "65001:1:1"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should not contain "Last reset"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
