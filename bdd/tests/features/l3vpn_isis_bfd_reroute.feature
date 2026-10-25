@serial
@l3vpn_isis_bfd_reroute
Feature: SRv6 L3VPN routes stay installed while IS-IS reroutes after BFD down
  As an operator of an SRv6 L3VPN core with BFD on every IS-IS link
  I want a PE to keep the VPN routes of a remote PE when the direct link to
  that PE fails silently and the remote PE is still reachable another way
  So that customer traffic stops only for the BFD detection time, and BGP
  does not withdraw the routes from customers and install them again.

  The a-b link drops every frame in both directions (netem loss 100%), so
  the link stays up and only BFD sees the failure. a stays reachable from b
  through c (metric 20 instead of 10), so the SRv6 SID of a never becomes
  unreachable and the VPN routes on b only need a new transport.

  Test Topology (point-to-point veth, IS-IS over link-local, BFD on all):
  ```
        a ------- b        a exports 192.0.2.64/26 and 2001:db8:e1::/48
         \       /         from VRF cust over iBGP VPNv4/VPNv6 to b.
          \     /
             c
  ```

  Scenario: Build the topology and bring up the core
    Given a clean test environment
    When I create namespace "a"
    And I create namespace "b"
    And I create namespace "c"
    And I connect namespace "a" interface "t-b" to namespace "b" interface "t-a"
    And I connect namespace "a" interface "t-c" to namespace "c" interface "t-a"
    And I connect namespace "b" interface "t-c" to namespace "c" interface "t-b"
    And I start zebra-rs in namespace "a"
    And I start zebra-rs in namespace "b"
    And I start zebra-rs in namespace "c"
    And I apply config "a.yaml" to namespace "a"
    And I apply config "b.yaml" to namespace "b"
    And I apply config "c.yaml" to namespace "c"
    And I wait 30 seconds for BGP to operate
    Then isis neighbor in namespace "b" at level 2 on interface "t-a" should be up
    And isis neighbor in namespace "b" at level 2 on interface "t-c" should be up
    And bfd session in namespace "b" on interface "t-a" should be up
    And BGP session in "b" to "2001:db8::1" should be "Established"
    And kernel route "192.0.2.64/26" in vrf "cust" in namespace "b" should eventually contain "fcbb:bbbb:1"
    And kernel route "2001:db8:e1::/48" in vrf "cust" in namespace "b" should eventually contain "fcbb:bbbb:1"

  Scenario: A silent failure of the a-b link only moves the VPN routes on b
    Given the test topology exists
    When I start recording kernel route changes in namespace "b"
    And I execute "tc qdisc add dev t-b root netem loss 100%" in namespace "a"
    And I execute "tc qdisc add dev t-a root netem loss 100%" in namespace "b"
    Then bfd session in namespace "b" on interface "t-a" should be down
    When I wait 10 seconds
    Then kernel route "192.0.2.64/26" in vrf "cust" in namespace "b" should eventually contain "dev t-c"
    And kernel route "192.0.2.64/26" in namespace "b" should not have been missing for more than 100 ms
    And kernel route "2001:db8:e1::/48" in namespace "b" should not have been missing for more than 100 ms
    When I execute "tc qdisc del dev t-b root" in namespace "a"
    And I execute "tc qdisc del dev t-a root" in namespace "b"
    And I wait 20 seconds
    Then bfd session in namespace "b" on interface "t-a" should be up

  Scenario: Teardown topology
    Given the test topology exists
    When I stop zebra-rs in namespace "a"
    And I stop zebra-rs in namespace "b"
    And I stop zebra-rs in namespace "c"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "c"
    Then the test environment should be clean
