# 06 — DNS Abuse: Resolution Trust and Name Poisoning

This module covers the trust model behind domain resolution. The issue is not simply that a name resolves incorrectly; it is that a system may trust a malicious or manipulated response without verifying the identity or integrity of the answer.

## Learning objective

Students should be able to:

- inspect DNS behavior and query flow
- explain what a DNS response proves and what it does not prove
- identify malicious or misleading resolution paths
- connect the issue to user trust, application trust, and web security

## Prerequisites and difficulty

- Prerequisites: modules 01–05, networking basics, basic DNS knowledge
- Difficulty: Intermediate

## Expected deliverable

Provide a final DNS analysis with:

- query and answer flow
- domain resolution behavior under test
- the trust issue discovered
- the recommended protection or verification step

## Time estimate

1.5–2 hours

## Offensive flow

1. Baseline normal resolution behavior
2. Query the target domain or resolver behavior
3. Identify whether the response is trustworthy or manipulated
4. Explain how an attacker could exploit the trust relationship
5. Record the evidence and stop before broad abuse

## Defensive flow

1. Validate expected resolver behavior
2. Review whether the system uses secure DNS practices or trusted upstreams
3. Check for open or misconfigured resolvers
4. Recommend DNSSEC or filtering controls where appropriate

## Command focus

- `dig`, `nslookup`, `resolvectl status`
- `tcpdump -nn port 53`
- `curl http://<host>`

## Exact expected output examples

```bash
dig google.com +short
172.217.10.46
```

If a different or unexpected answer appears than expected from a trusted resolver, the trust model has been manipulated or the query path is not controlled.

## What each command proves

- `dig` proves the actual DNS answer the client received
- `resolvectl` proves which resolver is in use
- `tcpdump port 53` proves which DNS traffic is crossing the network
- `curl` proves how the resolved name is being used by the application layer

## Evidence to capture

- query and answer examples
- resolver configuration and upstream relation
- packet capture showing the DNS transaction
- notes on whether the answer matches expectations

## Red-team decision point

If the resolved name is not tied to the expected source or if a malicious answer is accepted, document that the trust chain is broken. This is a business risk because user trust is being redirected without validation.

## When to stop and document

Stop once the DNS trust issue is evidenced and explained. No additional escalation is necessary unless the objective directly requires a web or service pivot.

## SOC/detection interpretation

The SOC should monitor for:

- unexpected domains or resolvers
- abnormal DNS queries from internal hosts
- repeated failures or reply mismatches
- clients sending traffic to suspicious or newly observed domains

## Pass/fail criteria

Pass if the student can explain the difference between a trusted resolution and a manipulated one and explain the impact clearly.

Fail if the student cannot articulate the trust failure or the resulting risk.

## Final capstone objective

This module helps prepare the student for the final capstone by illustrating how user trust is redirected when resolution is manipulated. In the end-to-end scenario, students should be able to recognize abnormal DNS trust and explain how that changes the attack path.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
