# Capstone Instructor Rubric

This rubric is used to evaluate the final red-team capstone. The goal is to assess whether the student can reason, validate, document, and defend their findings in a realistic lab scenario.

## 1. Overall scoring scale

- 5 = Excellent / fully demonstrates professional-level behavior
- 4 = Strong / meets expectations with minor gaps
- 3 = Adequate / basic competency with some weak explanations
- 2 = Weak / major gaps in reasoning or evidence
- 1 = Poor / does not demonstrate the skill reliably

## 2. Criteria and scoring

### A. Methodology and workflow

How well the student follows a structured red-team flow.

- Scope and rules are clear
- Recon is methodical and evidence-based
- The student profiles services before escalating
- The path chosen makes technical sense
- The student knows when to stop and document

Score: /5

### B. Technical execution

How well the student executes commands and validates findings.

- Commands are appropriate to the objective
- Outputs are interpreted correctly
- The student explains what each command proves
- The attack path is validated, not guessed
- The student maintains control of the lab environment

Score: /5

### C. Evidence quality

How well the student collects and preserves proof.

- Logs are captured
- Terminal output is retained
- Packet or traffic evidence is included when relevant
- Screenshots or notes are clear
- Evidence connects directly to the finding

Score: /5

### D. Defensive and SOC reasoning

How well the student explains the defender perspective.

- The student identifies a realistic log source
- The student explains what a SOC would see
- Detection logic is coherent and relevant
- The student names the likely alert or correlation trigger
- The student can explain how the control would stop the path

Score: /5

### E. Risk analysis and impact

How clearly the student explains the risk and effect.

- Attack impact is estimated realistically
- The trust failure is clearly explained
- Consequences are tied to the asset or service at risk
- The issue is framed in operational terms
- The assessment shows professional risk judgment

Score: /5

### F. Remediation and retest

How well the student closes the loop on defense.

- A real control is proposed
- The fix is tied to the root cause
- The same path is retested or logically validated
- The student compares before and after behavior
- The result proves the control had an impact

Score: /5

### G. Reporting quality

How professional the final report reads.

- Findings are clearly written
- The report uses a logical format
- Evidence supports the claims
- Risk, impact, and remediation are covered
- The report reads like a serious assessment or lab report

Score: /5

## 3. Final weighted score

Add the category scores:

- A + B + C + D + E + F + G = total /35

## 4. Grade interpretation

- 31–35: Outstanding
- 26–30: Strong pass
- 21–25: Adequate pass
- 16–20: Borderline / incomplete
- 10–15: Weak / below expected standard
- 0–9: Fail

## 5. Pass/fail decision

A student passes the capstone when they can:

- follow a disciplined workflow
- explain the attack path clearly
- provide evidence that supports the findings
- describe how defenders would detect the activity
- recommend a relevant fix and explain the retest logic
- deliver a clear final report

A student fails if they:

- only run commands without interpretation
- cannot explain the root cause or risk
- provide weak or missing evidence
- cannot distinguish attacker logic from defender logic
- produce a report with no operational relevance

## 6. Instructor notes

Use the following comments to guide evaluation:

- Did the student stop when the issue was proven?
- Did the student keep the environment safe and contained?
- Did the report show attack reasoning and not just tool output?
- Did the student demonstrate both offensive and defensive understanding?
- Did the evidence support the claims without speculation?
