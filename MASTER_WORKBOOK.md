# Master Workbook

For every exercise, fill this out completely. This workbook is meant to capture attack evidence, the reasoning behind the exploit, the defender view, and the final remediation.

## Exercise

Name:

Date:

VM snapshot:

## Scope

Attacker:

Target:

Network:

Rules of engagement:

## Objective

What are you trying to prove?

What is the end state of the attack?

## Baseline

What does normal behavior look like?

Host information:

Services running:

Network path:

Observed normal logs:

## Threat model

What is the asset being protected?

What trust boundary is being tested?

What assumptions does the target make?

## Attack

What did you change or manipulate?

Commands used:

Payloads or inputs:

Step-by-step attack path:

## Evidence

PCAP:

Logs:

Screenshots:

Command transcript:

Observed results:

## Analysis

Why did the target accept the traffic/input?

What trust assumption was broken?

Was this a configuration issue, protocol issue, service issue, validation issue, or identity issue?

## Detection and SOC angle

What would a defender see?

Which log source would reveal this?

What alert or correlation could catch it?

Which indicators matter?

- source IP
- destination IP
- port
- account used
- process name
- timestamp
- anomaly pattern

## Defensive control

What control did you add or simulate?

Firewall rule:

Service change:

Detection rule:

Patch or config fix:

## Retest

Did the exact same test still work?

What changed after the control?

## Impact assessment

Impact level:

- low
- medium
- high
- critical

Why:

## Final result

```text
Vulnerable → Exploited → Detected → Fixed → Retested
```

That five-step cycle is the core of this entire course.

## Short report format

Use the following summary format in your final note:

```text
Summary:
- What was tested
- What was vulnerable
- What was the impact

Attack path:
- Recon
- Enumeration
- Exploit/abuse
- Post-exploitation
- Evidence

Defense:
- detection point
- control added
- retest result

Conclusion:
- final risk and recommendation
```
