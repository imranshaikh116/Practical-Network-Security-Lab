# 02 — Networking: Traffic Flow, Routing, and Trust Boundaries

This module teaches how traffic moves through a network, how a device decides where to send packets, and how route or protocol confusion creates attack paths.

## Learning objective

Students should be able to:

- read network interfaces and route tables
- understand packet flow and the difference between a host route and a default route
- identify what information is exposed through local traffic inspection
- explain how routing and neighbor mapping create trust assumptions

## Prerequisites and difficulty

- Prerequisites: module 01, basic IP and subnet understanding
- Difficulty: Beginner to Intermediate

## Expected deliverable

Create a short network map that includes:

- interfaces and IP assignments
- default gateway and route information
- observed neighbor relationships
- summary of what traffic is visible on the segment

## Time estimate

1–2 hours

## Offensive flow

1. Capture interface and route information
2. Observe local traffic patterns
3. Identify unusual or exposed network paths
4. Explain how the traffic path supports an attack
5. Record the evidence and stop before active abuse transitions to exploitation

## Defensive flow

1. Confirm expected routes and interfaces
2. Validate that traffic stays within approved boundaries
3. Look for host misconfiguration, route leaks, or suspicious ARP entries
4. Apply segmentation or traffic filtering where necessary

## Command focus

- `ip addr`, `ip route`, `ip neigh`
- `ss -lntup`
- `tcpdump -i any -nn`
- `dig`, `curl`, `ping`

## Exact expected output examples

```bash
ip route
default via 192.168.56.1 dev eth0
192.168.56.0/24 dev eth0 proto kernel scope link src 192.168.56.10
```

This proves the host will send outbound traffic through the gateway and also indicates the local network segment.

## What each command proves

- `ip route` proves the path used for traffic delivery
- `ip neigh` proves which MAC address owns a nearby IP
- `tcpdump` proves what packets are actually traversing the segment
- `dig` proves how name resolution works and whether the target is trustworthy
- `curl` proves whether an HTTP service responds and how the app behaves

## Evidence to capture

- route table output
- neighbor mapping output
- packet capture excerpts
- HTTP or DNS request/response examples
- notes on what is visible to the attacker and what should be hidden

## Red-team decision point

If an interface is exposed, a route is wrong, or a host is resolving through an unexpected path, pause and document the trust boundary problem before escalating into active interception or service abuse.

## When to stop and document

Stop when you have identified the route path, mapped the relevant neighbors, and confirmed the traffic trust assumptions. Do not continue into MITM or exploitation unless the network path itself is already understood.

## SOC/detection interpretation

The defender should question:

- Are there unexpected routes or interfaces?
- Are there new ARP entries or unexpected gateways?
- Are there unusual DNS or HTTP requests from a host?
- Is there traffic going to an unknown destination?

## Pass/fail criteria

Pass if the student can explain the route path and show how local traffic exposure changes the attack surface.

Fail if the student cannot explain why a packet leaves a host or why a route matters to trust.

## Final capstone objective

This module supports the final objective by teaching how traffic routes and trust boundaries affect an entire attack chain. In the capstone, the student must understand where the traffic is going and why the path is exposed before escalating deeper.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
