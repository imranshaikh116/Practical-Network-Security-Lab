# 01 — Foundations: Recon, Baseline, and Lab Discipline

This module establishes the mindset and method behind every later attack path. The goal is not to memorize a command list, but to learn how a tester builds a reliable baseline, profiles the environment, and decides what to do next.

## Learning objective

Students should be able to:

- identify live hosts and key network components
- confirm the current privilege level and host identity
- understand what each reconnaissance command proves
- establish a clean lab baseline before moving into exploitation
- capture evidence and maintain disciplined investigation notes

## Prerequisites and difficulty

- Prerequisites: basic Linux shell use, simple networking, curiosity and patience
- Difficulty: Beginner

## Expected deliverable

Submit a short baseline report with:

- host inventory
- discovered network routes
- current privilege context
- list of relevant services
- notes on what the environment looks like before any active attack path begins

## Time estimate

1–2 hours

## Offensive flow

1. Identify the host, OS, and privilege level
2. Discover the local network and route behavior
3. Check active services and open ports
4. Map likely high-value targets
5. Record the evidence and stop before escalating further

## Defensive flow

1. Confirm what should be running
2. Review logs and service status
3. Compare the host baseline to the expected configuration
4. Detect unauthorized listeners or suspicious drift
5. Validate the environment before moving to the next module

## Command focus

- `whoami`, `id`, `hostname`, `uname -a`
- `ip addr`, `ip route`, `ss -lntup`
- `nmap -sn`, `nmap -sV`
- `journalctl --since "10 minutes ago"`

## Exact expected output examples

A healthy baseline may look like:

```bash
whoami
root

ip -br addr
lo UNKNOWN
eth0 UP 192.168.56.10/24

ss -lntup
LISTEN 0.0.0.0:22
LISTEN 0.0.0.0:80
```

If an unexpected service appears, it is a red flag and should be investigated.

## What each command proves

- `whoami` proves current privilege level
- `ip addr` proves the host identity and address assignment
- `ss -lntup` proves which services are exposed locally
- `nmap -sV` proves what service is actually responding on a port
- `journalctl` proves whether the system already logged suspicious events

## Evidence to capture

- screenshots of host identity and IP information
- scan output from `nmap`
- relevant log lines showing service status or suspicious activity
- notes about which ports are expected and which are not

## Red-team decision point

If the target reveals ports or services that align with an obvious exploit path, stop and document the vulnerability hypothesis before attempting exploitation. This prevents reckless escalation and preserves investigative discipline.

## When to stop and document

Stop once you have:

- a valid host inventory
- a baseline of reachable services
- a likely attack path
- enough evidence to write the finding

Do not continue to exploitation until the risk is clearly explained.

## SOC/detection interpretation

A defender should watch for:

- unexpected scans on internal segments
- unusual service startups
- changes in listening ports
- repeated failed or unexpected logins
- drift from the baseline image or host profile

## Pass/fail criteria

Pass if the student can identify the system baseline, explain the purpose of the reconnaissance commands, and write a concise report based on evidence.

Fail if the student only runs commands without explaining what each proved or why it matters.

## Final capstone objective

This module prepares the student for the final objective: building a structured, evidence-backed attack chain across the lab environment. The ability to establish a reliable baseline is the foundation for later escalation, detection review, and reporting.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
