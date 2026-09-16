# 03 — Denial of Service and Resource Exhaustion

This module covers how a system can be overwhelmed, how availability is attacked, and what defenders should monitor when a service starts failing under load.

## Learning objective

Students should be able to:

- recognize resource exhaustion patterns
- validate service strain with controlled load
- explain why availability failures are often caused by abused capacity, not just a single bug
- document the evidence showing an attack or outage pattern

## Prerequisites and difficulty

- Prerequisites: modules 01–02, Linux basics, service awareness
- Difficulty: Intermediate

## Expected deliverable

Provide a short impact summary with:

- service status before and during load
- evidence of CPU, memory, or connection pressure
- description of the failure mode
- a defensive recommendation for capacity and rate limiting

## Time estimate

1–2 hours

## Offensive flow

1. Baseline normal service behavior
2. Generate controlled load against a target service
3. Observe resource strain, queue buildup, or connection saturation
4. Compare the failure pattern to the expected baseline
5. Capture evidence and stop before harming the environment unnecessarily

## Defensive flow

1. Review service health and saturation indicators
2. Check logs, queue state, and resource usage
3. Identify the break point for overload
4. Apply rate limiting or capacity controls
5. Re-test under the same load

## Command focus

- `uptime`, `free -h`, `vmstat`, `ss -s`
- `ab -n`, `curl`, `tcpdump`
- `journalctl`

## Exact expected output examples

```bash
uptime
 10:12:00 up 50 min,  2 users,  load average: 1.42, 1.36, 1.24

ss -s
Total: 492 (kernel 0.0)
TCP:   123 (estab 80, closed 0, orphaned 0)
```

This proves the system has load and is handling connection pressure that may degrade responsiveness.

## What each command proves

- `uptime` proves the system is under strain or near its baseline limits
- `free -h` proves memory availability and pressure
- `ss -s` proves connection saturation and backlog pressure
- `ab` proves how the service responds to a targeted load pattern
- `journalctl` proves whether system logs record the stress or related failures

## Evidence to capture

- before/after resource snapshots
- connection count and service response time
- packet or TCP capture showing the load pattern
- logs showing failure or denial symptoms

## Red-team decision point

If the lab service fails under controlled load, document the condition and stop. The goal is to understand the resource ceiling and the effect, not to turn the lab into a destructive test.

## When to stop and document

Stop once you have captured a convincing before/after proof of outage or degradation and explained what control would reduce the risk.

## SOC/detection interpretation

Defenders should look for:

- rising connection counts
- CPU or memory saturation
- queue buildup or slow responses
- repeated connection resets
- service restarts or timeouts

## Pass/fail criteria

Pass if the student can show a resource exhaustion path, justify the impact, and explain what the defender would monitor.

Fail if the student cannot explain the cause of the outage or the evidence behind it.

## Final capstone objective

This module contributes to the final objective by reinforcing the difference between normal service behavior and failure under adversarial load. The capstone requires students to recognize when the environment is failing under pressure and explain what evidence proves it.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
