# Network Exposure & Investigation Lab

A defensive Python portfolio lab for turning **authorised Nmap discovery data** into asset, service and exposure context for analyst review.

> **An exposed service is an observation, not a verdict.**

## What this project demonstrates

This project shows how I approach network-security findings as an analyst rather than treating technical observations as automatic verdicts.

- Parse Nmap XML into structured observations.
- Validate that only open services become exposure observations.
- Preserve useful service/version context when available.
- Map discovered services to a synthetic asset inventory.
- Validate investigation case data against that inventory.
- Compare observations with an expected service baseline.
- Identify unexpected exposure without equating exposure with compromise.
- Triage findings using severity, asset criticality, business impact and evidence confidence.
- Consider organisation-specific SLA/OLA and escalation requirements when prioritising response.
- Use SIEM, EDR and SOAR as investigation accelerators rather than automatic decision-makers.
- Correlate evidence and document evidence gaps.
- Record a least-assumptive, defensible assessment and recommended next action.
- Use MITRE ATT&CK as an analytical aid only where supporting behavioural evidence exists.
- Test parser failures, assessment decisions and the complete evidence pipeline.
- Visualise network exposure without making security decisions in the visualisation layer.
- Work through controlled investigation scenarios and document analyst reasoning.

## Analyst workflow

```text
1. Observation / alert
2. Triage
3. Severity + asset criticality + business impact
4. Evidence enrichment and correlation
5. Verification
6. Defensible assessment
7. Escalation / containment / remediation / monitoring / closure
8. Documentation against applicable response requirements
```

The software presents evidence; **the analyst makes the judgement**.

For the fuller verification sequence, including timestamp correlation, authorisation, change/testing checks, independent evidence, security tooling, prioritisation and escalation, see [`docs/analyst-workflow.md`](docs/analyst-workflow.md).

For the reasoning behind the workflow, see [`docs/analyst-design-decisions.md`](docs/analyst-design-decisions.md).

### Assessment states

- **Expected** — available evidence supports the service being authorised and consistent with the baseline.
- **Requires Investigation** — the observation is unexplained or outside the baseline and needs further verification.
- **Security Concern** — should only be selected when evidence demonstrates a material security issue or unauthorised exposure.
- **Insufficient Evidence** — the available information is not enough to make a defensible classification.

Uncertainty is documented rather than converted into a false positive or invented risk rating.

## Triage, prioritisation and business impact

A production SOC must balance investigation quality with timely response. The lab therefore treats prioritisation as a combination of:

- **Severity** — how concerning the activity or condition is based on available evidence.
- **Asset criticality** — how important the affected system is to the organisation.
- **Business impact** — potential operational, customer or service impact.
- **Evidence confidence** — how strongly the current context is supported.
- **Response requirements** — applicable organisational SLAs, OLAs, escalation procedures and incident-response playbooks.

The project deliberately avoids an invented universal risk formula. A high-severity event affecting a critical asset may require rapid escalation even while investigation questions remain open. An expected service on a known asset may follow normal verification instead.

## SIEM, EDR and SOAR in the investigation workflow

Security tooling can reduce manual investigation time by correlating evidence, enriching observations and automating repeatable tasks:

| Capability | Investigation value |
|---|---|
| **SIEM** | Correlates authentication, network and security events across sources and time windows. |
| **EDR** | Provides endpoint/process, user, file and network telemetry. |
| **SOAR** | Automates repeatable enrichment and approved playbook steps. |
| **Analyst** | Validates evidence, establishes context and makes the final defensible decision. |

The principle is:

**Tools accelerate evidence gathering → analyst validates evidence → analyst makes the decision.**

This project does **not** claim to operate live SIEM, EDR or SOAR integrations. They are represented as production SOC concepts that inform the workflow.

## MITRE ATT&CK as an analytical aid

Where appropriate, observed behaviour can be considered against MITRE ATT&CK using:

```text
Observed behaviour
      ↓
Potential technique
      ↓
Supporting evidence
      ↓
Confidence / uncertainty
      ↓
Next investigation step
```

A port or service is not automatically treated as an ATT&CK technique. Mapping requires supporting behavioural evidence.

## End-to-end evidence pipeline

```text
sample_scan.xml
      ↓
nmap_parser.py
      ↓
ServiceObservation
      ↓
asset_inventory.json
      ↓
network_exposure.py
      ↓
Assessment + confidence + evidence gaps + next action
```

`investigation_pipeline.py` connects those components. It performs **no network activity**; it only processes an existing Nmap XML file and synthetic/authorised inventory data. It also validates the browser investigation case data before running the sample pipeline.

Run it against the included synthetic evidence:

```bash
python investigation_pipeline.py
```

## Investigation console

The project includes a browser-based investigation exercise. It loads case data directly from [`data/cases.json`](data/cases.json), keeping scenario data separate from the interface.

Open [`docs/investigation-console.html`](docs/investigation-console.html) through a local HTTP server rather than `file://` because browsers restrict JavaScript requests for local files.

From the repository root:

```bash
python -m http.server 8000
```

Then open:

```text
http://localhost:8000/docs/investigation-console.html
```

The console lets an analyst:

- select an investigation case;
- review asset ownership, role and criticality;
- inspect discovered services;
- compare services with the expected context;
- review known evidence;
- identify evidence gaps;
- work through case-specific verification checks;
- select an assessment; and
- record a written rationale and disposition guidance.

The console deliberately blocks **Expected** and **Security Concern** decisions until every case verification check is marked complete. This is a training control rather than proof of external evidence: the underlying verification still has to be performed and retained outside the console.

## Visual investigation aids

The console includes:

- **Service-presence matrix** — shows observed services against a small set of common service ports without declaring compromise.
- **Asset relationship view** — provides simplified investigative context around an asset and its observed services. It is not a claim about actual routing or attack paths.
- **Investigation timeline** — presents the sequence of synthetic evidence available to the analyst.
- **Evidence completeness indicator** — shows known evidence versus outstanding gaps; it is not a probability of compromise.
- **Verification checklist** — makes case-specific evidence requirements explicit before a stronger disposition can be recorded.
- **Decision trail** — records the assessment, rationale, verification status and disposition guidance.

## Recruiter brief

For a concise explanation of the investigative approach, see [`docs/recruiter-brief.md`](docs/recruiter-brief.md).

The separate [`docs/recruiter-investigation.md`](docs/recruiter-investigation.md) provides a worked investigation scenario and example analyst communication.

## Design decisions and learning

This project is deliberately built around a few principles:

1. **Observation is not automatically compromise.** A scan can establish what was observed, not why it exists.
2. **Context comes before conclusion.** Ownership, business purpose, criticality, authorisation and baseline matter.
3. **Evidence should be verified.** Plausible explanations are not treated as verified explanations.
4. **Uncertainty is useful information.** Evidence gaps are documented instead of hidden behind an invented score.
5. **Automation supports analysts.** SIEM, EDR and SOAR can accelerate investigation but do not replace judgement.
6. **Time is part of operational security.** Severity, business impact and organisational response requirements influence priority.
7. **Communication is part of the investigation.** A defensible result should explain the finding, evidence, gaps, impact, decision and next action.

The full rationale is documented in [`docs/analyst-design-decisions.md`](docs/analyst-design-decisions.md).

## AI-assisted development transparency

AI tools were used during development as a coding and research assistant, including support with implementation ideas, debugging, documentation and test development. Project requirements, investigation workflow, security assumptions and final design decisions were reviewed and validated by the author.

AI-generated suggestions were treated as proposals rather than authoritative answers. Changes were tested against the project's requirements and expected behaviour, and design decisions were reviewed for security reasoning, limitations and accuracy.

The purpose of this disclosure is transparency: AI assisted parts of the development process, but the project is intended to demonstrate the author's reasoning, validation and decision-making rather than autonomous AI design.

## Safety & data

- Test data is synthetic and intended for educational use.
- Only scan systems you own or have explicit permission to test.
- Do not place real credentials, customer data, private logs or production network captures in this repository.
- Do not use network-scanning functionality against public or third-party systems without explicit authorisation.
- The project does not execute Nmap, capture packets, exploit hosts or perform automated incident response.
- Generated logs, Python caches, coverage data and local output files are excluded through `.gitignore`.

## Limitations

This is an educational investigation lab, not an enterprise asset-management, vulnerability-management or SIEM product.

It does **not** perform authenticated vulnerability assessment, exploitation, packet capture, continuous monitoring or automated incident response.

The assessment engine is intentionally conservative. Its confidence value describes the strength of available **context**, not the likelihood that a system is compromised.

## Running the tests

No external service is required for the core tests.

```bash
python -m unittest discover -s tests -v
```

The tests cover expected and unexpected exposure, unknown assets, unauthorised assets, baseline normalisation, malformed Nmap input, invalid inventory data, invalid case data and the complete parser → inventory → assessment flow.

## Repository structure

```text
.
├── .github/
│   ├── dependabot.yml             # Dependency update configuration
│   └── workflows/
│       ├── tests.yml              # Automated test and pipeline checks
│       └── codeql.yml             # GitHub CodeQL analysis
├── SECURITY.md                    # Security and responsible-disclosure guidance
├── data/
│   ├── asset_inventory.json
│   └── cases.json
├── docs/
│   ├── analyst-workflow.md        # Verification, prioritisation and escalation workflow
│   ├── analyst-design-decisions.md # Reasoning, design decisions and AI disclosure
│   ├── investigation-console.html # Hands-on analyst console
│   ├── recruiter-brief.md         # Concise project explanation
│   ├── recruiter-investigation.md # Worked investigation scenario
│   └── case-notes-template.md     # Analyst notes template
├── tests/
│   ├── test_network_exposure.py
│   ├── test_nmap_parser.py
│   └── test_investigation_pipeline.py
├── network_exposure.py
├── investigation_pipeline.py
├── nmap_parser.py
├── visualizer.py
├── sample_scan.xml
├── requirements.txt
└── README.md
```

## Future development

Future work should be driven by an investigation need rather than feature count. Possible extensions include:

- comparing two authorised scan snapshots to identify service changes;
- richer synthetic service/version context;
- additional investigation cases;
- stronger automated validation of case data; and
- optional export of analyst case notes.

## Portfolio context

This repository is designed to complement **ThreatTrace Lab** rather than duplicate it:

| Project | Demonstrates |
|---|---|
| ThreatTrace Lab | Security-alert triage, evidence correlation and investigation |
| Network Exposure & Investigation Lab | Network discovery, asset context and exposure assessment |

Together they demonstrate a consistent principle:

> **Collect evidence, establish context, verify important claims, document uncertainty and make a defensible human decision.**

## Author

Created by [KE-Johnston1](https://github.com/KE-Johnston1) as a practical cybersecurity portfolio project focused on network visibility, evidence-based analysis and human judgement.
