# 10 — Crypto, Hashes, Passwords, and Trust in Secrets

This module covers why secrets and trust are often weaker than expected. Instead of treating cryptography as theoretical only, the focus is on how weak algorithms, poor randomness, and exposed credentials create demonstrable risk.

## Learning objective

Students should be able to:

- explain the difference between hashing, encryption, and randomness
- identify weak or reused secrets
- understand how password cracking and poor key handling lead to compromise
- justify why cryptographic trust depends on implementation quality, not only theory

## Prerequisites and difficulty

- Prerequisites: modules 01–09, Linux basics, basic data handling
- Difficulty: Intermediate to Advanced

## Expected deliverable

Submit a crypto and credentials brief with:

- the hash or secret material reviewed
- the weak point discovered
- the method used to validate the issue
- the mitigation recommended

## Time estimate

1.5–2 hours

## Offensive flow

1. Identify candidate password, hash, or secret material
2. Check whether weak hashing or poor storage practices are present
3. Test the credential or hash under controlled conditions
4. Confirm the break and document the impact
5. Stop once the weakness is proven and explained

## Defensive flow

1. Review password and storage practices
2. Confirm whether hashing or encryption is appropriate
3. Check for weak defaults or exposed secrets
4. Apply hardened controls and re-test the same path

## Command focus

- `md5sum`, `sha256sum`, `openssl rand`
- `john`, `openssl s_client`
- `openssl x509 -in cert.pem -text`

## Exact expected output examples

```bash
sha256sum file.txt
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

This proves a hash is produced, but a defender should also question whether the hashed input is being stored securely and whether password quality is enforced.

## What each command proves

- `sha256sum` proves the material has become a deterministic digest
- `openssl rand` proves whether the system is generating output that has sufficient entropy
- `john` proves whether a weak or reused credential can be recovered offline
- `openssl s_client` proves how the service presents TLS and whether trust assumptions are working as intended

## Evidence to capture

- hash or credential material reviewed
- password-cracking or token-validation results
- evidence of weak or reused secrets
- notes on the resulting impact on the host or service

## Red-team decision point

If a weak hash or exposed secret is identified, stop and document the impact. The risk is real even before the exploitation path is expanded further.

## When to stop and document

Stop once the issue is validated and its impact is understood. There is no need to continue beyond a clear proof of the credential or trust failure.

## SOC/detection interpretation

Defenders should investigate:

- weak or repeated password patterns
- signs of credential reuse across hosts
- unexpected key generation or insecure certificate use
- changes in service trust or certificate presentation

## Pass/fail criteria

Pass if the student can explain how weak crypto or credentials create a trust failure and what the correct protection is.

Fail if the student only lists commands without linking the issue to real operational risk.

## Final capstone objective

This module supports the final objective by teaching that trust is only as strong as the secrets and implementation behind it. In the capstone, students should be able to connect a credential or trust failure to a broader path of compromise and explain the impact.

## Module structure

- `attack_analysis.md` — conceptual explanation, red-team reasoning, and defensive interpretation
- `commands.md` — operational command flow with offensive and defensive notes
- `README.md` — overview, objective, evidence expectations, and grading context

## Start here

Start with `attack_analysis.md`, then use `commands.md` while working inside the lab VM.
