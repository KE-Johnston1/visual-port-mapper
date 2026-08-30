# Network Exposure & Investigation Lab

A defensive Python portfolio lab for turning **authorised Nmap discovery data** into asset, service and exposure context for analyst review.

> **An exposed service is an observation, not a verdict.**

The project demonstrates a practical investigation workflow:

```text
Nmap evidence → Parser → Asset inventory → Service baseline
→ Evidence gaps → Assessment engine → Analyst decision
→ Recruiter console / case notes
```

## Why this project exists

A network scan can tell an analyst what is visible. It does not, by itself, establish whether that visibility is expected, authorised, business-required or risky.

This lab therefore combines discovery data with synthetic asset context and an expected service baseline. The analysis engine reports what the evidence supports and explicitly records what is still unknown.

That approach maps naturally to NIST Cybersecurity Framework (CSF) 2.0 outcomes around maintaining inventories of hardware, software, services and systems, representing authorised network communications, prioritising assets by criticality, and understanding cybersecurity risk. citeturn0search12turn0search0

## What it demonstrates

- Parsing Nmap XML into structured observations
- Validating that only open services become exposure observations
- Mapping discovered services to a synthetic asset inventory
- Comparing observed services with an expected service baseline
- Identifying expected and unexpected exposure without equating exposure with compromise
- Reporting evidence gaps and recommended next actions
- Assigning a **confidence level to the assessment context**, not a probability of compromise
- Testing the parser, analysis engine and end-to-end evidence pipeline
- Visualising network exposure without making security decisions in the visualisation layer
- Working through controlled recruiter investigation scenarios
- Documenting analyst reasoning and uncertainty

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

The repository now has one Python path for the technical evidence workflow:

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

Example output:

```text
10.10.10.20 tcp/22 ssh: expected (high)
10.10.10.20 tcp/80 http: expected (high)
10.10.10.20 tcp/443 https: expected (high)
```

## Recruiter investigation console

The console is a browser-based investigation exercise. It loads its cases directly from [`data/cases.json`](data/cases.json), so the case definitions are not duplicated inside the HTML/JavaScript.

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

The cases are intentionally designed so that the analyst must distinguish **what the evidence proves** from **what still needs verification**.

See [`docs/recruiter-brief.md`](docs/recruiter-brief.md) and [`docs/case-notes-template.md`](docs/case-notes-template.md) for the intended recruiter exercise and investigation documentation format.

## Example investigation

A synthetic scan identifies:

```text
10.10.10.20
22/tcp   SSH
80/tcp   HTTP
443/tcp  HTTPS
```

If the authorised asset baseline lists all three services, the correct technical assessment is **Expected**. An open port is not automatically evidence of compromise.

If an authorised asset exposes TCP/8080 but the service is not in the baseline, the engine reports **Requires Investigation** and identifies evidence gaps such as business justification, service ownership, exposure scope and configuration/version review.

If an asset is unknown, the engine returns **Insufficient Evidence** rather than inventing ownership, business purpose or risk.

## Repository structure

```text
.
├── data/
│   ├── asset_inventory.json        # Synthetic asset/service baseline
│   └── cases.json                  # Synthetic recruiter investigation cases
├── docs/
│   ├── investigation-console.html  # Interactive recruiter exercise
│   ├── recruiter-brief.md          # What the exercise demonstrates
│   └── case-notes-template.md      # Analyst documentation template
├── tests/
│   ├── test_network_exposure.py    # Analysis tests
│   └── test_investigation_pipeline.py # End-to-end pipeline tests
├── network_exposure.py              # Context-aware assessment engine
├── investigation_pipeline.py        # Parser → inventory → engine integration
├── nmap_parser.py                   # Nmap XML evidence parser
├── visualizer.py                    # Exposure visualisation
├── sample_scan.xml                  # Synthetic Nmap-style input
├── requirements.txt
└── README.md
```

The previous SSH brute-force material was removed because ThreatTrace Lab is now the dedicated alert-investigation project in this portfolio. Keeping one clear purpose per repository makes the work easier to understand and defend in an interview.

## Running the tests

No external service is required for the core tests.

```bash
python -m unittest discover -s tests -v
```

The tests cover both individual analysis decisions and the complete parser → inventory → assessment flow.

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

Together they demonstrate a consistent principle: **collect evidence, establish context, document uncertainty and make a defensible human decision.**

## Author

Created by [KE-Johnston1](https://github.com/KE-Johnston1) as a practical cybersecurity portfolio project focused on network visibility, evidence-based analysis and human judgement.
