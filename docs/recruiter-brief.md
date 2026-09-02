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
SIEM / EDR / SOAR-assisted enrichment
      ↓
Analyst validation
      ↓
Risk assessment
      ↓
Analyst decision
      ↓
Recommended next action / escalation
```

The tooling is there to **speed up evidence gathering and correlation**, not to replace analyst judgement. In a production SOC, investigation priority also depends on severity, asset criticality, business impact and applicable response targets such as SLAs/OLAs and escalation procedures.

## Security operations and investigation efficiency

In a real SOC environment:

- **SIEM** can centralise and correlate logs and security events across multiple sources.
- **EDR** can provide endpoint telemetry such as processes, users, files and network connections.
- **SOAR** can automate repetitive enrichment and investigation/response playbook steps.

Used appropriately, these capabilities can reduce manual investigation time and help analysts respond consistently. The analyst still needs to validate the evidence, understand its limitations and make the final defensible assessment.

The business reason matters: time is an operational security concern. A delayed response to a high-severity event can increase disruption, exposure and potential business impact. This is why security teams use severity, asset criticality, business impact and organisation-specific response requirements to prioritise investigations.

This project does **not** claim to operate a live SIEM, EDR or SOAR integration. These are represented as production SOC concepts that inform the investigation workflow.

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

If SIEM or EDR telemetry is available, it can accelerate correlation with authentication, endpoint and network activity. SOAR can assist with repeatable enrichment. The resulting evidence still requires analyst validation before a stronger disposition is recorded.

## Why the lab uses evidence gaps

An unknown asset or service does not automatically mean compromise. If the available evidence cannot support a defensible conclusion, the correct result may be **Insufficient Evidence** with a clear next action.

This is intentional human-in-the-loop analysis. The software organises evidence; security tooling can accelerate evidence gathering; **the analyst makes the decision**.

## Portfolio safety

All scenarios are synthetic or based on systems for which testing is authorised. The project is not intended to encourage scanning of public or third-party infrastructure without permission.

## Framework alignment

The project is informed by NIST Cybersecurity Framework 2.0 concepts including asset management, authorised network communications, asset criticality and risk assessment. It is an educational implementation, not a claim of formal compliance.
