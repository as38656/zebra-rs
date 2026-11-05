# The harness leaves the host loopback alone

## Overview

The bridge of a topology lives in the host namespace, but the global
addresses on the host `lo` do not belong to the harness: WSL keeps the
address of its DNS server there, for example. The harness must not delete
them. Such an address must not disturb a test either. By default the kernel
answers ARP on any interface for any address of the host, and a reply from
the host would send a namespace's packets to the bridge instead of the
neighbor they are for.

The kernel only sends that reply when the bridge has rp_filter and
arp_filter off. On a host with either one on, the ARP check passes with or
without the harness's `arp_ignore`, so run this feature with both off to test
it.

## Test Topology

```
   z1 (vz1ns 192.0.2.1/24) ── br0
   host lo: 192.0.2.77/32
```

## Test Scenarios

| Scenario | Result |
|----------|--------|
| An address on the host lo stays and answers no ARP on the bridge | |
