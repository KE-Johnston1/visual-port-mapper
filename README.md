# Network Exposure & Investigation Lab

A defensive Python portfolio lab for turning **authorised Nmap discovery data** into asset, service and exposure context for analyst review.

> **An exposed service is an observation, not a verdict.**

## What this project demonstrates

This project shows how I approach network-security findings as an analyst rather than treating technical observations as automatic verdicts.

- Parse Nmap XML into structured observations.
- Validate that only open services become exposure observations.
- Preserve useful service/version context when it is available.
- Map discovered services to a synthetic asset inventory.
- Compare observations with an expected service baseline.
- Identify unexpected exposure without equating exposure with compromise.
- Report evidence gaps and recommended next actions.
- Assign confidence to the strength of the available context, not to the probability of compromise.
- Test parser failures, assessment decisions and the complete evidence pipeline.
- Visualise network exposure without making security decisions in the visualisation layer.
- Work through controlled investigation scenarios and document analyst reasoning.

## Analyst workflow

```text
1. Establish asset identity and ownership
2. Review discovered services
3. Compare observations with the expected baseline
4. Identify what is known
5. Identify evidence gaps
6. Gather and verify additional context
7. Make a defensible assessment
8. Document rationale and next action
```

The software presents evidence; **the analyst makes the judgement**.

### Assessment states

- **Expected** — available evidence supports the service being authorised and consistent with the baseline.
- **Requires Investigation** — the observation is unexplained or outside the baseline and needs further verification.
- **Security Concern** — should only be selected when evidence demonstrates a material security issue or unauthorised exposure.
- **Insufficient Evidence** — the available information is not enough to make a defensible classification.

Uncertainty is documented rather than converted into a false positive or invented risk rating.

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

The project includes a browser-based investigation exercise. It loads case data directly from [`data/cases.json`](data/cases.json), keeping the scenario data separate from the interface.

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
- select an assessment; and
- record a written rationale and disposition guidance.

## Visual investigation aids

The console includes:

- **Exposure heatmap** — shows observed services against a small set of common service ports without declaring compromise.
- **Asset relationship view** — provides simplified investigative context around an asset and its observed services.
- **Investigation timeline** — presents the sequence of synthetic evidence available to the analyst.
- **Evidence completeness indicator** — shows known evidence versus outstanding gaps; it is not a probability of compromise.
- **Decision trail** — records the assessment, rationale, verification reminder and disposition guidance.

## Recruiter brief

For a concise explanation of the investigative approach, see [`docs/recruiter-brief.md`](docs/recruiter-brief.md).

The separate [`docs/recruiter-investigation.md`](docs/recruiter-investigation.md) provides a worked investigation scenario and example analyst communication.

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

The assessment engine is intentionally conservative. Its confidence value describes the strength of the available **context**, not the likelihood that a system is compromised.

## Running the tests

No external service is required for the core tests.

```bash
python -m unittest discover -s tests -v
```

The tests cover expected and unexpected exposure, unknown assets, unauthorised assets, baseline normalisation, malformed Nmap input, invalid inventory data and the complete parser → inventory → assessment flow.

## Repository structure

```text
.
├── data/
│   ├── asset_inventory.json
│   └── cases.json
├── docs/
│   ├── investigation-console.html # Hands-on analyst console
│   ├── recruiter-brief.md         # Concise project explanation
│   ├── recruiter-investigation.md # Worked investigation scenario
│   └── case-notes-template.md     # Analyst notes template
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
