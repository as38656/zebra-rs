@serial
@bgp_maximum_prefix
Feature: Per-neighbor maximum-prefix
  As a network operator
  I want to limit how many prefixes a neighbor may send me per family
  (`afi-safi <name> maximum-prefix max N`), so that a leak or a wrong
  filter on the far side cannot fill my tables.

  Over the limit, zebra-rs sends Cease / Maximum Number of Prefixes
  Reached (RFC 4486 §4), drops the routes and keeps the peer down: it
  does not dial and it refuses the peer's connections. Only `clear bgp`
  or the `restart` timer brings the peer back. With `warning-only` it
  only logs and keeps the session. A new or lower limit is checked at
  once.

  Test Topology (one veth link, IPv4 eBGP):
  ```
   z1 (AS 65001) ------------------ z2 (AS 65002)
   192.168.0.1                      192.168.0.2
                                    10.0.2.1/32 .. 10.0.2.5/32
  ```
  - z2 sends five routes. It traces NOTIFICATION messages.
  - z1 sets the limit on its session to z2 at run time.

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
    And BGP route in "z1" should eventually have "10.0.2.5/32"

  Scenario: Under the limit the session stays up
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 maximum-prefix max 10" in namespace "z1"
    Then show command "show bgp neighbor 192.168.0.2" in namespace "z1" should eventually contain "Maximum prefixes allowed 10"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "5 accepted prefixes, 5 received"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "Threshold for warning message 75%"
    And BGP session in "z1" to "192.168.0.2" should be "Established"

  Scenario: warning-only logs and keeps the session over the limit
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 maximum-prefix warning-only true" in namespace "z1"
    And I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 maximum-prefix max 3" in namespace "z1"
    Then daemon log in namespace "z1" should eventually contain "maximum-prefix exceeded (warning-only, the session stays up)"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "Maximum prefixes allowed 3 (warning-only)"
    When I wait 5 seconds
    Then BGP session in "z1" to "192.168.0.2" should be "Established"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should not contain "Last reset"
    And BGP route in "z1" has "10.0.2.5/32"

  Scenario: Without warning-only the session closes at once with Cease and stays down
    Given the test topology exists
    When I apply command "delete router bgp neighbor 192.168.0.2 afi-safi ipv4 maximum-prefix warning-only" in namespace "z1"
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Idle"
    And daemon log in namespace "z2" should eventually contain "Maximum Number of Prefixes Reached — IPv4 Unicast, limit 3"
    And show command "show bgp summary" in namespace "z1" should contain "Idle (PfxCt)"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "due to Reached received prefix count"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "Peer had exceeded the max. no. of prefixes configured."
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "clear bgp 192.168.0.2 to restore peering"
    And BGP route in "z1" should eventually not have "10.0.2.1/32"
    # z2 dials every 3 seconds; z1 neither dials nor takes the connection.
    When I wait 10 seconds
    Then BGP session in "z1" to "192.168.0.2" should be "Idle"
    And BGP session in "z2" to "192.168.0.1" should not be "Established"

  Scenario: A higher limit does not bring the peer back but clear bgp does
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 maximum-prefix max 10" in namespace "z1"
    And I wait 8 seconds
    Then BGP session in "z1" to "192.168.0.2" should be "Idle"
    When I run "clear bgp ipv4 neighbor 192.168.0.2" in namespace "z1"
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And BGP route in "z1" should eventually have "10.0.2.5/32"
    And show command "show bgp summary" in namespace "z1" should not contain "PfxCt"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should not contain "Peer had exceeded"

  Scenario: The restart timer brings the peer back
    Given the test topology exists
    When I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 maximum-prefix restart 1" in namespace "z1"
    And I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 maximum-prefix max 3" in namespace "z1"
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Idle"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "Threshold for warning message 75%, restart interval 1 min"
    And show command "show bgp neighbor 192.168.0.2" in namespace "z1" should contain "will restart in"
    When I apply command "set router bgp neighbor 192.168.0.2 afi-safi ipv4 maximum-prefix max 10" in namespace "z1"
    And I wait 45 seconds
    Then BGP session in "z1" to "192.168.0.2" should eventually be "Established"
    And daemon log in namespace "z1" should eventually contain "maximum-prefix restart time passed"
    And BGP route in "z1" should eventually have "10.0.2.5/32"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "z1"
    And I stop zebra-rs in namespace "z2"
    And I delete namespace "z1"
    And I delete namespace "z2"
    Then the test environment should be clean
