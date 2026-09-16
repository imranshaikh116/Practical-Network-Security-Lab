# 08 — DHCP Abuse: Rogue Configurations and Layer-2 Trust Failure

This module covers one of the simplest and most effective ways to manipulate a local network: supplying a rogue DHCP lease that directs clients toward a malicious gateway or DNS path.

## Learning objective

Students should be able to:

- explain how DHCP influences the network path and trust decisions
- identify the risks of rogue or unexpected configuration assignments
- connect DHCP abuse to broader MITM or credential collection paths
- describe the defensive controls that should prevent it

## Prerequisites and difficulty

- Prerequisites: modules 01–07
- Difficulty: Intermediate

## Expected deliverable

Submit a DHCP abuse summary containing:

- normal DHCP lease baseline
- rogue or unexpected lease behavior
- risk to host traffic and trust
- recommended controls such as DHCP snooping or port security

## Time estimate

1.5 hours

## Offensive flow

1. Observe the current lease behavior
2. Trigger a DHCP request or rogue server response
3. Determine what network settings are being changed
4. Confirm the effect on the client path and trust assumptions
5. Document the impact and stop before spreading into unrelated systems

## Defensive flow

1. Review expected DHCP behavior on the segment
2. Validate the source and lease inventory
3. Detect multiple DHCP servers or unexpected lease offerings
4. Confirm switch protections and network segmentation are in place

## Command focus

- `dhclient`
- `ip addr`
- `tcpdump -vv 'udp port 67 or udp port 68'`
- `ip route`

## Exact expected output examples

```bash
ip route
default via 192.168.56.1 dev eth0
```

If a rogue DHCP server supplies a different gateway or DNS server, the route and name resolution path may silently change.

## What each command proves

- `dhclient` proves the lease acquisition process can be manipulated in a local network
- `tcpdump` proves the DHCP exchange and server identity
- `ip route` proves whether the client now sends traffic through a different gateway
- `ip addr` proves whether the lease details changed the host configuration

## Evidence to capture

- DHCP offer/ack sequence
- gateway and DNS assignments before and after the event
- route table changes
- notes about the trust effect on the client

## Red-team decision point

If the client receives a malicious gateway or DNS server from a rogue source, note it as a high-risk trust issue. This is already enough to establish the attack path without more invasive testing.

## When to stop and document

Stop once the client is clearly redirected by a rogue DHCP path and the impact is explained. Further escalation is optional only if it supports a more direct attack path.

## SOC/detection interpretation

The defender should observe:

- multiple DHCP announcements on the same segment
- unexpected leases or duplicate address assignments
- clients sending traffic to unapproved gateways or resolvers
- abnormal DHCP activity near switch ports or guest networks

## Pass/fail criteria

Pass if the student can explain how a rogue DHCP process changes the network path and trust assumptions.

Fail if the student cannot connect the lease outcome to the actual risk to the client.

## Final capstone objective

This module supports the final objective by showing how a network can be silently redirected before the victim even sends meaningful traffic. In the capstone, students should recognize when the environment has been altered and explain how that changes the trust model.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
