# 12 — Defense, Detection, and Attack Surface Reduction

This module is the blue-team counterpart to the previous offensive work. The goal is not to avoid the attack path in theory; it is to reduce exposure, detect the behavior, and prove that the control works under the same conditions.

## Learning objective

Students should be able to:

- reduce the exposed attack surface on a system or network
- explain the security value of filtering, service reduction, and log review
- identify which controls are effective against the module attack path
- re-test the exact same path after the change to confirm value

## Prerequisites and difficulty

- Prerequisites: all prior modules, Linux service management, basic network policy knowledge
- Difficulty: Intermediate to Advanced

## Expected deliverable

Submit a hardening report that includes:

- the original vulnerable state
- the control applied
- the change in system exposure or detection
- evidence from the re-test and final recommendation

## Time estimate

2 hours

## Offensive flow

1. Map the current exposure of the target
2. Identify the weakness or gap in policy or configuration
3. Validate the actual attack path in a controlled manner
4. Explain the security consequence in a clear technical statement

## Defensive flow

1. Reduce access or service exposure
2. Confirm the change with firewall and service status checks
3. Review logs for attack behavior
4. Re-test the same path after the fix
5. Confirm the issue is closed without breaking legitimate service

## Command focus

- `ufw status`, `nft list ruleset`
- `systemctl --type=service --state=running`
- `journalctl --since "1 hour ago"`
- `ss -lntup`, `nmap -sV`

## Exact expected output examples

```bash
ufw status verbose
Status: active
To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere
80/tcp                     ALLOW IN    Anywhere
```

This proves the firewall is deliberately controlling access. A defender should then validate whether the allowed exposure matches the operational requirement.

## What each command proves

- `ufw` proves the base policy and allowed access paths
- `nft` proves the actual implemented filter behavior
- `systemctl` proves which services remain exposed and active
- `journalctl` proves whether suspicious activity is being logged
- `nmap` proves whether the attack surface changed after the fix

## Evidence to capture

- firewall policy before and after
- service status before and after
- logs showing detection or blocking of suspicious activity
- re-test results proving the attack path is reduced or blocked

## Red-team decision point

If the issue is reduced or blocked, stop and document the fix. The quality of the defense is proven by the re-test, not by a theoretical claim.

## When to stop and document

Stop once the control has been validated against the same attack path. The goal is to prove the fix, not to keep expanding the scope.

## SOC/detection interpretation

Defenders should answer:

- Are there unexplained blocked attempts?
- Are services no longer exposed when they should not be?
- Do the logs show denial or policy enforcement events?
- Did the attack path fail after control changes?

## Pass/fail criteria

Pass if the student can explain the control, apply it to the relevant module attack path, and re-test successfully.

Fail if the student cannot prove that the defense actually changes the exposure or detection outcome.

## Final capstone objective

This module is the defensive preparation for the final capstone. Students must be able to explain what a defender would detect, what control would stop the issue, and how to re-test the path to confirm the fix in an evidence-based way.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
