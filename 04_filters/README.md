# 04 — Filters, Access Control, and Identity Trust

This module addresses the common mistake of trusting local identity or a simplistic allowlist. The lab explores how filtering rules and identity assumptions fail when an attacker changes the apparent source or bypasses the expected trust boundary.

## Learning objective

Students should be able to:

- inspect a host or router for network identity and access policy
- explain why MAC and local trust are weak identity controls
- validate whether a router or switch accepts a spoofed or changed client identity
- identify the defensive controls that should replace weak filtering logic

## Prerequisites and difficulty

- Prerequisites: modules 01–03, basic Linux networking
- Difficulty: Intermediate

## Expected deliverable

Submit a short lab note that includes:

- interface and MAC baseline
- the changed identity or access condition
- the observed policy result
- the defense that should be implemented to prevent bypass

## Time estimate

1.5 hours

## Offensive flow

1. Measure the baseline identity data on the network
2. Change the apparent identity in a lab-safe manner
3. Investigate whether the policy follows the changed identity
4. Confirm how the network reacts to the mismatch
5. Record the findings and stop before escalating outside the scope

## Defensive flow

1. Review what identity or access policy is actually in use
2. Test for weak or duplicate trust assumptions
3. Validate the effect of port security, ACLs, and segmentation
4. Hardening recommendations based on the observed weakness

## Command focus

- `ip link`, `ip addr`, `ip neigh`
- `tcpdump -i any -nn 'arp or udp port 67 or udp port 68'`
- `ip link set ... address ...`

## Exact expected output examples

```bash
ip link show eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000
    link/ether 02:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff
```

If the interface now presents a different MAC than the expected inventory, the trust model behind the access control is likely weak.

## What each command proves

- `ip link` proves the current identity at layer 2
- `ip neigh` proves which peer is currently trusted by the host
- `tcpdump` proves whether the system is receiving unexpected identity or DHCP behavior
- `ip link set ... address` proves how quickly a local identity can be altered in a permissive environment

## Evidence to capture

- MAC address baseline before and after spoofing
- ARP or DHCP output showing the changed identity
- router or firewall behavior when the change occurs
- notes on whether the access policy depended on an identity that should not be trusted

## Red-team decision point

If the router or network policy accepts the changed local identity without stronger authentication, stop and explicitly document the trust failure. This is a policy issue, not just a technical quirk.

## When to stop and document

Stop once you have proven whether the control is identity-based, weak, or bypassable. At that point, the risk is already clear enough for reporting.

## SOC/detection interpretation

Defenders should watch for:

- MAC changes on approved hosts
- unexpected DHCP leases or duplicate addresses
- new ARP mappings tied to unknown devices
- policy changes triggered by local identity shifts

## Pass/fail criteria

Pass if the student can explain that a MAC or local identifier is not a secure trust anchor and can describe the resulting risk clearly.

Fail if the student treats a local identity as a real authentication mechanism without explaining the bypass.

## Final capstone objective

This module prepares the student for the final capstone by showing how weak local trust assumptions can be abused at the edge of the network. In the final assessment, the student must explain how identity and access controls fail when the trust model is too weak.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
