# Course Progression: Beginner to Advanced

This course is designed as a progression from basic network understanding to full adversary simulation.

## Stage 1 — Beginner: Understand the environment

Target skills:
- identify hosts, IPs, routes, and interfaces
- understand normal traffic and socket states
- build a secure lab baseline
- document evidence properly

Modules:
- 01 Foundations
- 02 Networking

Exercises focus on:
- baseline collection
- recon and discovery
- understanding packet flow
- logging and evidence discipline

## Stage 2 — Intermediate: Exploit trust assumptions

Target skills:
- abuse weak local trust boundaries
- analyze service exposure
- detect routing and DNS manipulation
- understand DoS and connection exhaustion
- identify weak identity controls

Modules:
- 03 DoS
- 04 Router filters and identity abuse
- 05 MITM and ARP poisoning
- 06 DNS abuse
- 07 Protocol exploitation
- 08 DHCP abuse

Exercises focus on:
- trust failures
- service exposure
- net-path manipulation
- layer-2 and layer-3 abuse

## Stage 3 — Advanced: Service and application exploitation

Target skills:
- validate vulnerability preconditions
- test web application trust failures
- understand TLS and cryptographic misuse
- inspect app request flows
- identify risk from weak crypto and insecure protocols

Modules:
- 09 Router management plane
- 10 Cryptography and TLS review
- 11 Web exploitation

Exercises focus on:
- application trust boundaries
- request tampering
- privilege assumptions
- weak crypto and certificate issues

## Stage 4 — Red-team operations: full attack path

Target skills:
- chain attacks into a coherent operation
- perform recon through exploitation
- elevate privileges
- pivot laterally
- collect evidence and timeline data
- work with detection engineering and SOC response

Modules:
- 12 Defense and detection engineering
- 13 Red-team capstone

Exercises focus on:
- privilege escalation
- lateral movement
- evidence gathering
- explaining what the defender would see
- reinforcing the fix and retesting

## Red-team workflow you must repeat in every module

```text
1. Define scope and objective
2. Discover assets and services
3. Profile behavior and trust boundaries
4. Hypothesize weakness
5. Validate with minimal evidence
6. Exploit only in the isolated lab
7. Escalate or pivot if needed
8. Preserve logs and PCAPs
9. Detect and explain the defender view
10. Apply control
11. Retest
12. Write the report
```

## Success checklist

By the end of the course, you should be able to:

- explain the attack path from recon to impact
- identify the weakest trust assumption
- prove the vulnerability safely in the lab
- state what the defender would observe
- recommend and validate a fix
- produce a clean technical report

After module 13, do the full capstone without reading from the solution first and write your report as if it were a real engagement.
