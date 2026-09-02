# Recruiter Brief

## What this project demonstrates

This lab demonstrates how I approach network-security findings as an analyst rather than treating technical observations as automatic verdicts.

### Investigation workflow

```text
Network discovery / alert
      ↓
Triage
      ↓
Severity + asset criticality + business impact
      ↓
SIEM / EDR / SOAR-assisted enrichment
      ↓
Evidence review + verification
      ↓
Analyst validation
      ↓
Defensible assessment
      ↓
Recommended next action / escalation
      ↓
Documentation against applicable response requirements
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

## Prioritisation without fake precision

The lab deliberately avoids an invented universal risk formula. Instead, it demonstrates the factors an analyst should consider when deciding what needs attention first:

- severity and available evidence;
- asset criticality;
- business impact;
- evidence confidence and gaps; and
- organisational response, escalation and SLA/OLA requirements.

This means a high-severity event affecting a critical asset may need rapid escalation even when some investigation questions remain open, while an expected service on a known asset can follow normal verification.

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

## Example analyst communication

A concise escalation should make the decision understandable to another analyst without requiring the investigation to be repeated from scratch. A useful structure is:

```text
Priority: High / Medium / Low according to organisational criteria
Asset / User / Service: What is affected?
Finding: What was observed?
Evidence: What supports the finding?
Evidence gaps: What is still unknown?
Business impact: Why does it matter?
Assessment: What can currently be defended?
Next action: What should happen next?
Escalation: Who needs to know or act?
Response requirement: What SLA/OLA or procedure applies?
```

## Why the lab uses evidence gaps

An unknown asset or service does not automatically mean compromise. If the available evidence cannot support a defensible conclusion, the correct result may be **Insufficient Evidence** with a clear next action.

This is intentional human-in-the-loop analysis. The software organises evidence; security tooling can accelerate evidence gathering; **the analyst makes the decision**.

## MITRE ATT&CK

Where supporting behavioural evidence exists, the analyst can use MITRE ATT&CK as an analytical aid rather than automatically mapping a port or service to a technique. The intended reasoning is:

```text
Observed behaviour → potential technique → supporting evidence → confidence/uncertainty → next step
```

## Portfolio safety

All scenarios are synthetic or based on systems for which testing is authorised. The project is not intended to encourage scanning of public or third-party infrastructure without permission.

## Framework alignment

The project is informed by NIST Cybersecurity Framework 2.0 concepts including asset management, authorised network communications, asset criticality and risk assessment. It is an educational implementation, not a claim of formal compliance.

## Design rationale

The project intentionally prioritises **reasoning over feature count**. The key question is not simply whether software can identify an exposed service, but whether an analyst can establish context, challenge assumptions, verify important claims, account for business impact and document a defensible decision.

See [`docs/analyst-design-decisions.md`](analyst-design-decisions.md) for the fuller reasoning behind the workflow.
