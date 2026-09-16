# 05 — MITM: ARP Poisoning, Traffic Relay, and Interception

This module shows how an attacker can control the path of traffic by poisoning the local trust relationship between a victim and a gateway. It highlights the difference between intercepting traffic and forwarding it without detection.

## Learning objective

Students should be able to:

- explain how ARP poisoning alters local trust
- validate whether a host is silently forwarding traffic
- identify the difference between passive observation and active relay
- connect the attack to the risk of plaintext traffic and weak local trust assumptions

## Prerequisites and difficulty

- Prerequisites: modules 01–04, IP and ARP understanding
- Difficulty: Intermediate

## Expected deliverable

Provide a short MITM analysis with:

- baseline ARP mapping
- the poisoned or intercepted path
- the traffic observed while the relay was active
- the mitigation required to stop it

## Time estimate

1.5–2 hours

## Offensive flow

1. Confirm the true ARP mapping for victim and gateway
2. Poison the ARP cache in both directions
3. Enable forwarding if needed to maintain path continuity
4. Capture relevant traffic from the relay point
5. Confirm the effect and document the evidence

## Defensive flow

1. Monitor for unexpected ARP changes
2. Validate whether forwarding is unexpectedly enabled
3. Review packet capture for suspicious relay activity
4. Restrict local network trust with switch protections and segmentation

## Command focus

- `ip neigh`
- `sudo arpspoof -i eth0 -t <client> <gateway>`
- `cat /proc/sys/net/ipv4/ip_forward`
- `sudo sysctl -w net.ipv4.ip_forward=1`
- `tcpdump -i eth0 -nn -A tcp port 80`

## Exact expected output examples

```bash
ip neigh
192.168.56.1 dev eth0 lladdr 08:00:27:xx:xx:xx REACHABLE
192.168.56.20 dev eth0 lladdr 08:00:27:yy:yy:yy REACHABLE
```

If the mapping changes to the attacker’s MAC, the local network trust has been manipulated.

## What each command proves

- `ip neigh` proves the current trusted mapping between IP and MAC
- `arpspoof` proves the attacker can change the local path without modifying the network itself
- `ip_forward` proves whether the host is forwarding traffic in a relay configuration
- `tcpdump` proves whether the attacker can see plaintext or modified traffic

## Evidence to capture

- ARP table before and after poisoning
- packet capture from the relay point
- notes showing the switched traffic path
- log or system state proving relay was active

## Red-team decision point

If the victim remains reachable and traffic can be observed or intercepted in real time, stop and document the impact. A successful MITM is already a major network trust failure.

## When to stop and document

Stop once the attack path is visible and proven. No further escalation is necessary unless the objective is to inspect or manipulate a service beyond local interception.

## SOC/detection interpretation

The SOC should look for:

- repeated ARP announcements from unauthorized MACs
- unexpected gateway or neighbor changes
- hosts forwarding traffic unexpectedly
- suspicious packet capture or relay behavior on internal network segments

## Pass/fail criteria

Pass if the student can explain how local ARP trust creates a path for manipulation and can identify the defensive control that reduces the risk.

Fail if the student cannot explain why the route changed or how the attacker became the effective relay.

## Final capstone objective

This module contributes directly to the final objective by demonstrating how a trusted path can be silently replaced. The capstone requires students to recognize and document when a local path has been manipulated and how defenders can detect that change.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
