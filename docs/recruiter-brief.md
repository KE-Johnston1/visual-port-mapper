# Recruiter Brief

## What this project demonstrates

This lab demonstrates how I approach network-security findings as an analyst rather than treating technical observations as automatic verdicts.

### Investigation workflow

```text
Network discovery
      ↓
Asset identification
      ↓
Service baseline comparison
      ↓
Evidence review
      ↓
Evidence gaps
      ↓
Risk assessment
      ↓
Analyst decision
      ↓
Recommended next action
```

## Example question

> An authorised network scan identifies SSH on an internal asset. Is that a security incident?

**Not necessarily.**

The analyst should establish:

- who owns the asset;
- what the asset is used for;
- whether SSH is an approved service;
- whether the observed service matches the expected baseline;
- whether the exposure is expected for that asset's role;
- what additional evidence is required; and
- whether the organisation's policy requires escalation or remediation.

## Why the lab uses evidence gaps

An unknown asset or service does not automatically mean compromise. If the available evidence cannot support a defensible conclusion, the correct result may be **Insufficient Evidence** with a clear next action.

This is intentional human-in-the-loop analysis. The software organises evidence; the analyst makes the decision.

## Portfolio safety

All scenarios are synthetic or based on systems for which testing is authorised. The project is not intended to encourage scanning of public or third-party infrastructure without permission.

## Framework alignment

The project is informed by NIST Cybersecurity Framework 2.0 concepts including asset management, authorised network communications, asset criticality and risk assessment. It is an educational implementation, not a claim of formal compliance.
