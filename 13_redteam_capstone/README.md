# 13 — Red Team Capstone: Full Attack Chain, Detection, and Professional Reporting

This module integrates the course into a realistic adversary simulation. The student does not simply run commands; they move through a bounded attack chain that mirrors a real internal security review and then explain how defenders would respond.

## Learning objective

Students should be able to:

- plan and execute a structured attack path across a controlled lab environment
- combine reconnaissance, service profiling, exploitation logic, and evidence capture
- explain the attack chain from attacker perspective and defender perspective
- produce a report that reads like a real security assessment or red-team deliverable

## Prerequisites and difficulty

- Prerequisites: all prior modules
- Difficulty: Advanced

## Expected deliverable

Submit a final capstone package with:

- engagement summary
- host and service inventory
- attack path and trust failures identified
- evidence and logs collected
- defender detection notes
- remediation recommendations
- final report in professional style

## Time estimate

3–5 hours

## Offensive flow

1. Discover the environment and identify likely targets
2. Profile the services and their trust boundaries
3. Choose the most realistic attack path
4. Validate the issue with controlled commands and evidence
5. Document the impact and stop at the proper escalation point
6. Prepare the final evidence-based report

## Defensive flow

1. Review the lab from the SOC perspective
2. Identify the detection gap for each step in the chain
3. Determine which logs or telemetry would have caught the activity
4. Explain how a defender would respond and what control would block the next step
5. Re-test the fix and summarize the lessons learned

## Command focus

- `nmap`, `whoami`, `id`, `sudo -l`
- `find / -perm -4000`
- `tcpdump`, `journalctl`
- `ss`, `ps aux`, `ip route`

## Exact expected output examples

```bash
whoami
root

sudo -l
User root may run the following commands:
    /usr/bin/python3 /opt/target_script.py
```

This proves privilege or access opportunities exist and should trigger immediate escalation analysis and evidence capture.

## What each command proves

- `whoami` proves current identity and privilege
- `sudo -l` proves possible privilege escalation paths
- `find / -perm -4000` proves SUID or privilege-bearing binaries may exist
- `journalctl` proves what the system logged during the activity
- `tcpdump` proves the live traffic path and whether the activity is visible on the segment

## Evidence to capture

- full command log from reconnaissance through validation
- logs showing the relevant system events
- packet captures or trace data when possible
- screenshots or notes of the final exploit or abuse state
- summary of the final compromised path and its impact

## Red-team decision point

At the capstone level, the point is not to keep escalating until something breaks. The correct decision is to stop when the attack chain is proven, the impact is explained, and the defended response is documented. This is the professional discipline expected in red-team work.

## When to stop and document

Stop once you have:

- a valid service or host path
- clear evidence of compromise or abuse
- a risk statement with impact
- a defense and detection explanation
- enough information to prepare the report

If you continue beyond this, the exercise becomes noisy rather than professional.

## SOC/detection interpretation

The SOC should be able to identify:

- unexpected scanning behavior
- new service exposure or privilege changes
- suspicious login or authentication events
- protocol or process anomalies tied to the attack chain
- unusual outbound traffic or hidden relay behavior

## Pass/fail criteria

Pass if the student can build an end-to-end attack path, explain the attacker and defender views, and submit a professional report with evidence and risk assessment.

Fail if the student can only list tools or show isolated commands without a coherent chain of events or a defensible report.

## Final capstone objective

The final objective is to complete a realistic offensive security assessment against the isolated lab environment and present findings in the form of a professional report. The student should demonstrate:

- attack path reasoning
- command-level validation
- evidence preservation
- defense and detection awareness
- remediation and retest logic
- final reporting quality

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
