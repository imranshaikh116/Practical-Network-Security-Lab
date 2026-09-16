# 07 — Protocols, Service Discovery, and Controlled Exploitation

This module focuses on understanding what a service really offers, how it speaks to the network, and how a red teamer decides whether a service is worth exploitation. The emphasis is on validation, not blind exploitation.

## Learning objective

Students should be able to:

- profile services and versions using active probing
- understand how protocol behavior reveals risk
- decide whether a service is worth escalation or exploitation
- explain the difference between detection and validation

## Prerequisites and difficulty

- Prerequisites: modules 01–06, Linux basics, networking and package analysis
- Difficulty: Intermediate to Advanced

## Expected deliverable

Create a protocol vulnerability brief that includes:

- service inventory
- version or behavior findings
- explanation of the exposure
- a controlled validation result and risk note

## Time estimate

2 hours

## Offensive flow

1. Map services and likely protocol versions
2. Test the service behavior and handshake
3. Confirm the vulnerability or weakness under lab-safe conditions
4. Record the evidence and stop before a reckless exploit path
5. Explain the impact and the next escalation decision

## Defensive flow

1. Review exposed services for unnecessary exposure
2. Check whether software versions are outdated or poorly managed
3. Validate whether the protocol should be restricted or upgraded
4. Confirm the service is hardened and not silently exposing more than required

## Command focus

- `nmap -sV`, `nmap -p-`
- `nc`, `openssl s_client`
- `curl -I`, `curl -v`

## Exact expected output examples

```bash
nmap -sV 192.168.56.20
22/tcp open  ssh OpenSSH 7.4
80/tcp open  http Apache httpd 2.4.6
```

This output proves the versions and indicates likely upgrade or hardening needs.

## What each command proves

- `nmap -sV` proves the service and version the target is advertising
- `curl` proves how the service responds to HTTP requests
- `openssl s_client` proves whether TLS is present and how the certificate or protocol is behaving
- `nc` proves if the service accepts raw protocol input or reveals a risky handshake

## Evidence to capture

- service scan output
- version data and banner metadata
- conversation or handshake details
- notes explaining why the service is vulnerable or high risk

## Red-team decision point

If the version or banner reveals a known weakness but no exploit is required to prove the issue, stop and document the risk. The validation point is reached when the service behavior clearly supports the finding.

## When to stop and document

Stop once the service risk is proven through version, behavior, or controlled validation. Continuing past that point without a clear objective adds risk without adding value.

## SOC/detection interpretation

The defender should check for:

- unexpected exposed service versions
- increased connection attempts or banners gathered by scanners
- new handshake activity to suspicious or unsupported ports
- mistakes between expected service versions and actual running versions

## Pass/fail criteria

Pass if the student can profile a service, explain what the protocol reveals, and document a valid risk or vulnerability hypothesis.

Fail if the student can only run the scanner but cannot explain why the service matters.

## Final capstone objective

This module is essential to the final capstone because it teaches how to validate a real service exposure and decide whether it is worth escalation. The final assessment expects students to select the correct path based on evidence and to stop when the risk is proven.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
