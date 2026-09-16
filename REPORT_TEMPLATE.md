# Final Security Report Template

## 1. Executive Summary

Project / Lab Name:

Date:

Assessor:

Scope:

Summary of finding:

Overall risk level:

- Low
- Medium
- High
- Critical

## 2. Scope and Environment

Target environment:

Hosts in scope:

Network range:

Rules of engagement:

## 3. Objective

What the exercise was meant to prove:

What the expected result was before the test:

## 4. Attack Path and Evidence

### Reconnaissance

- Hosts identified:
- Services identified:
- Relevant ports:
- Initial observations:

### Enumeration

- Service versions or banners:
- Protocol behavior:
- Trust assumptions discovered:

### Exploit or Abuse Validation

- Command sequence used:
- Result observed:
- Impact of the abuse:
- Evidence captured:

### Privilege / Lateral Movement (if applicable)

- Additional access obtained:
- Additional assets reached:
- Evidence captured:

## 5. Why the Issue Exists

Trust assumption that failed:

Root cause:

- misconfiguration
- weak identity model
- unpatched service
- bad validation
- unsafe default
- poor detection

## 6. Defensive and SOC Interpretation

What a defender would likely observe:

Relevant log source:

- auth log
- firewall log
- DNS log
- system journal
- packet capture
- SIEM alert

Detection idea:

Alert or correlation logic:

Indicators to monitor:

- source IP
- destination IP
- port
- process name
- account used
- event correlation

## 7. Remediation

Recommended fix:

Control added or simulated:

- firewall rule
- service disablement
- patch
- config hardening
- segmentation
- DNS change
- credential policy update

## 8. Retest Result

Did the original attack still work after remediation?

Yes / No

Observed result after patch or control:

## 9. Final Risk Assessment

Impact:

Likelihood:

Overall risk:

Recommended priority:

- Immediate
- High
- Medium
- Low

## 10. Conclusion

Short conclusion paragraph:

Recommended next action:

## 11. Appendix

Command transcript:

PCAP or packet snippets:

Screenshots or log excerpts:

---

## Short report format

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
