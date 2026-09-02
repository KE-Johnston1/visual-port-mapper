# Analyst Design Decisions

## Why this lab does not turn exposure into an automatic verdict

A network scan can establish that a service responded or appeared to be listening. It does not, by itself, establish that the service is unauthorised, vulnerable, malicious or evidence of compromise.

The lab therefore separates **observation** from **security judgement**. This is the central design decision behind the project.

## Investigation model

The intended analyst workflow is:

```text
Observation / Alert
        ↓
Triage
        ↓
Severity + Asset Criticality + Business Impact
        ↓
Evidence enrichment and correlation
        ↓
Verification
        ↓
Assessment
        ↓
Escalation / Containment / Remediation / Monitoring / Closure
        ↓
Documentation against applicable response requirements
```

### Triage questions

Before spending significant investigation time, the analyst should establish:

- What was observed?
- Which asset, user or service is involved?
- When did it occur, including timezone where relevant?
- Is the asset known and authorised?
- What is the asset's business role and criticality?
- What evidence is already available?
- What important evidence is missing?
- Is there an indication of active compromise or material business impact?
- Does organisational policy require immediate escalation?

## Prioritisation

The lab does not use an invented numerical risk score. Instead, it demonstrates the factors an analyst would use to prioritise work:

- **Severity** — how concerning is the observed activity or condition based on available evidence?
- **Asset criticality** — what is the importance of the affected system to the organisation?
- **Business impact** — what could delay, disruption or compromise mean for operations, customers or services?
- **Evidence confidence** — how strong and independently supported is the current context?
- **Response requirements** — do organisational SLAs, OLAs, escalation procedures or incident-response playbooks create a target response or escalation path?

A high-severity observation affecting a critical business asset may require rapid escalation even while some investigation questions remain open. Conversely, an expected service on a known asset may require normal verification rather than urgent response.

Priority is therefore a **decision-support concept**, not a universal formula. Production organisations define their own severity categories and response targets.

## SIEM, EDR and SOAR

Security tooling can accelerate the investigation without replacing the analyst.

| Capability | Investigation value | Analyst responsibility |
|---|---|---|
| SIEM | Correlates authentication, network, endpoint and security events across sources and time windows | Validate relevance, timing and source reliability |
| EDR | Provides endpoint/process, user, file and network telemetry | Assess host-level evidence in context |
| SOAR | Automates repeatable enrichment, lookups and approved playbook actions | Confirm automation is appropriate and validate resulting evidence |

The model is:

**tools accelerate evidence gathering → analyst validates evidence → analyst makes the decision.**

The project does not claim to operate live SIEM, EDR or SOAR integrations. These are represented as production SOC concepts that inform the workflow.

## Time, SLA and business context

Investigation quality matters, but so does timely response. Security teams operate under organisational priorities and may have SLAs, OLAs, escalation procedures or incident-response requirements that determine how quickly an event must be acknowledged, investigated or escalated.

The lab therefore treats time as part of the operational context rather than claiming a universal SLA. A useful investigation question is:

> **What needs to happen next, how quickly, and what organisational requirement determines that priority?**

## MITRE ATT&CK use

MITRE ATT&CK should be used as an analytical aid rather than a label generator. Where relevant, the analyst can document:

```text
Observed behaviour
      ↓
Potential ATT&CK technique
      ↓
Supporting evidence
      ↓
Confidence / uncertainty
      ↓
Next investigation step
```

An observed service or port is not automatically mapped to an ATT&CK technique. Mapping requires supporting behavioural evidence.

## Analyst communication

A useful escalation record should allow another analyst or responder to understand the decision without repeating the entire investigation. The project therefore favours communication that states:

- priority and why it was assigned;
- affected asset/user/service;
- observed finding;
- evidence supporting the finding;
- evidence gaps and uncertainty;
- business impact or asset criticality;
- current assessment;
- required next action;
- escalation owner/path; and
- applicable response target or organisational requirement.

## Example reasoning

For an unknown internal asset exposing SSH and TCP/8080:

1. The scan establishes that the services were observed; it does not establish compromise.
2. Unknown ownership and criticality increase uncertainty.
3. The analyst checks authorisation, business purpose and expected services.
4. SIEM/EDR evidence, where available, can accelerate correlation with authentication, endpoint and network activity.
5. If the asset is high criticality or evidence suggests active compromise, escalation may need to happen before every question is answered.
6. If the evidence remains insufficient, the analyst records the gaps rather than inventing a conclusion.
7. The final disposition is supported by evidence and documented rationale.

This demonstrates the thought process the project is intended to showcase: **challenge assumptions, establish context, verify important claims, consider business impact and make the least-assumptive defensible decision.**

## AI-assisted development transparency

AI tools were used during development as a coding and research assistant, including support with implementation ideas, debugging, documentation and test development. Project requirements, investigation workflow, security assumptions and final design decisions were reviewed and validated by the author.

AI-generated suggestions were treated as proposals rather than authoritative answers. Changes were tested against the project's requirements and expected behaviour, and design decisions were reviewed for security reasoning, limitations and accuracy.

The use of AI does not represent a claim that AI independently designed or validated the investigation methodology. The purpose of this disclosure is to be transparent about development assistance while making clear that the project demonstrates the author's reasoning, validation and decision-making.
