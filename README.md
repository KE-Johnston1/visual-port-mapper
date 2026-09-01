# Network Exposure & Investigation Lab

A defensive Python portfolio lab for turning **authorised Nmap discovery data** into asset, service and exposure context for analyst review.

> **An exposed service is an observation, not a verdict.**

## What this project demonstrates

This project is designed to show how I approach network-security findings as an analyst rather than treating technical observations as automatic verdicts.

- Parsing Nmap XML into structured observations
- Validating that only open services become exposure observations
- Mapping discovered services to a synthetic asset inventory
- Comparing discovered services with an expected service baseline
- Identifying expected and unexpected exposure without equating exposure with compromise
- Reporting evidence gaps and recommended next actions
- Assigning a **confidence level to the assessment context**, not a probability of compromise
- Testing the parser, analysis engine and end-to-end evidence pipeline
- Visualising network exposure without making security decisions in the visualisation layer
- Working through controlled investigation scenarios
- Documenting analyst reasoning, uncertainty and verification decisions

## Analyst workflow

```text
1. Establish asset identity and ownership
2. Review discovered services
3. Compare observations with the expected baseline
4. Identify what is known
5. Identify evidence gaps
6. Gather/verify additional context
7. Make a defensible assessment
8. Document rationale and next action
```

The tool presents evidence; **the analyst makes the judgement**.

### Assessment states

- **Expected** — available evidence supports the service being authorised and consistent with the baseline.
- **Requires Investigation** — the observation is unexplained or outside the baseline and needs further verification.
- **Security Concern** — should only be selected when evidence demonstrates a material security issue or unauthorised exposure.
- **Insufficient Evidence** — the available information is not enough to make a defensible classification.

The last outcome is deliberate. Uncertainty is documented rather than converted into a false positive or invented risk rating.

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

`investigation_pipeline.py` connects those components. It performs **no network activity**; it only processes an existing Nmap XML file and synthetic/authorised inventory data.

Run it against the included synthetic evidence:

```bash
python investigation_pipeline.py
```

## Investigation console

The project includes a browser-based investigation exercise. It loads its cases directly from [`data/cases.json`](data/cases.json), so the case definitions are not duplicated inside the HTML/JavaScript.

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

- select an investigation case
- review asset ownership, role and criticality
- inspect discovered services
- compare services with the expected context
- review known evidence
- identify evidence gaps
- select an assessment
- record a written rationale

## Visual investigation aids

The console includes:

- **Exposure heatmap** — shows observed services against a small set of common service ports without declaring compromise.
- **Asset relationship view** — provides simplified investigative context around an asset and its observed services.
- **Investigation timeline** — presents the sequence of synthetic evidence available to the analyst.
- **Evidence completeness indicator** — shows known evidence versus outstanding gaps; it is not a probability of compromise.
- **Decision trail** — records the assessment, rationale, verification reminder and disposition guidance.

## Recruiter brief

For a concise explanation of the investigative approach, see [`docs/recruiter-brief.md`](docs/recruiter-brief.md).

The brief explains the human-in-the-loop approach, evidence gaps, verification and the distinction between an observation and a security verdict.

## Safety & data

- Test data is synthetic and intended for educational use.
- Only scan systems you own or have explicit permission to test.
- Do not place real credentials, customer data, private logs or production network captures in this repository.
- Do not use network-scanning functionality against public or third-party systems without explicit authorisation.
- Generated logs, Python caches and local output files should remain excluded through `.gitignore`.

## Limitations

This is an educational investigation lab, not an enterprise asset-management, vulnerability-management or SIEM product.

It does **not** perform authenticated vulnerability assessment, exploitation, packet capture, continuous monitoring or automated incident response.

The assessment engine is intentionally conservative. Its confidence value describes the strength of the available **context**, not the likelihood that a system is compromised.

## Running the tests

No external service is required for the core tests.

```bash
python -m unittest discover -s tests -v
```

The tests cover both individual analysis decisions and the complete parser → inventory → assessment flow.

## Repository structure

```text
.
├── data/
│   ├── asset_inventory.json
│   └── cases.json
├── docs/
│   ├── investigation-console.html # Hands-on analyst console
│   ├── recruiter-brief.md         # Concise project explanation
│   ├── recruiter-investigation.md # Investigation walkthrough
│   └── case-notes-template.md
├── tests/
│   ├── test_network_exposure.py
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

- comparing two authorised scan snapshots to identify service changes
- richer synthetic service/version context
- additional investigation cases
- stronger automated validation of case data
- optional export of analyst case notes

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
