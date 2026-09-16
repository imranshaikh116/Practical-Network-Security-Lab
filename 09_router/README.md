# 09 — Router Attacks: Control Plane Exposure and Misconfiguration

This module focuses on the weak points in infrastructure devices that manage traffic, access, and policy. A compromised router can redirect flow and expose the entire internal environment to the attacker.

## Learning objective

Students should be able to:

- profile the management plane of a router or gateway device
- identify whether the control plane is unintentionally exposed
- understand how default settings or weak access controls create attack paths
- connect infrastructure weaknesses to broader network compromise

## Prerequisites and difficulty

- Prerequisites: modules 01–08, Linux and routing familiarity
- Difficulty: Advanced

## Expected deliverable

Submit a router attack brief with:

- service or management exposure summary
- proof of reachable admin paths
- issue and impact statement
- recommended control or configuration fix

## Time estimate

2 hours

## Offensive flow

1. Scan the router for exposed services and control-plane interfaces
2. Verify what is reachable on the internal network
3. Attempt a controlled validation of a weak admin path or default configuration
4. Record the proof and impact
5. Stop before causing broad disruption to the network

## Defensive flow

1. Check which ports and administrative interfaces are reachable
2. Validate whether management access is restricted
3. Confirm whether default credentials or weak settings are present
4. Harden the control plane and re-test the same path

## Command focus

- `nmap -sV`, `nmap -A`
- `curl http://<router>`
- `ssh -v <router>`
- `ip route`

## Exact expected output examples

```bash
nmap -sV 192.168.56.1
80/tcp open  http
23/tcp open  telnet?
22/tcp open  ssh
```

If the router exposes administrative or management interfaces unexpectedly, the infrastructure itself has become a target.

## What each command proves

- `nmap` proves the router’s reachable services and versions
- `curl` proves whether an admin interface is exposed or responding
- `ssh -v` proves whether the management path is accessible and whether auth controls are present
- `ip route` proves how the internal network expects traffic to move through the gateway device

## Evidence to capture

- router scan output
- service banners or admin interface responses
- network path proof showing how the device sits in the path
- notes on the consequence of allowing the access path

## Red-team decision point

If the router is reachable and misconfigured, document that the control plane itself is at risk. A gateway is a central trust point, so this is not a minor issue.

## When to stop and document

Stop once the exposed administrative or control-plane path is clearly proven and the downstream impact is explained. Additional testing should only continue if it directly supports higher-risk exploitation.

## SOC/detection interpretation

The SOC should watch for:

- new management or admin services on network gateways
- repeated access attempts or failed logins on router interfaces
- unexpected changes in routing or gateway behavior
- unusual traffic flowing directly through the infrastructure device

## Pass/fail criteria

Pass if the student can explain why exposure of the management plane is a critical network issue and identify the fix.

Fail if the student focuses on the service but cannot explain the broader risk to the network.

## Final capstone objective

This module aligns with the final capstone by representing the type of infrastructure reachability that can turn a small exposure into a major network compromise. The final assessment expects students to explain the broader impact of infrastructure trust failure, not just the individual port.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
