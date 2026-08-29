# Network Exposure & Investigation Lab

A defensive Python lab for turning authorised Nmap discovery data into **asset, service and exposure context** for analyst review.

The project is deliberately not a vulnerability scanner and does not treat an open port as proof of compromise. It demonstrates a practical workflow:

```text
Discovery → Asset context → Service baseline → Evidence gaps → Risk assessment → Analyst recommendation
```

## Why this project exists

A network scan answers **what is visible**. A security analyst still needs to establish **whether that visibility is expected, who owns the asset, what business purpose the service has, and what evidence is missing** before making a judgement.

This approach is consistent with current NIST guidance that emphasises maintaining inventories of hardware, software and services and documenting expected network ports, protocols and services. citeturn0search12turn0search0

## What it demonstrates

- Parsing Nmap XML into structured observations
- Mapping discovered services to an asset inventory
- Comparing observed services with an expected baseline
- Distinguishing **expected**, **investigate**, and **insufficient evidence** outcomes
- Explicitly recording evidence gaps rather than inventing certainty
- Unit testing security-analysis logic
- Visualising discovered network exposure
- Safe, synthetic investigation scenarios

## Investigation principle

> **An exposed service is an observation, not a verdict.**

For example, TCP/22 may be completely appropriate on an administration server and inappropriate on another asset. The analyst should establish context before recommending remediation.

## Example investigation

A synthetic scan identifies:

```text
10.10.10.20
22/tcp   SSH
80/tcp   HTTP
443/tcp  HTTPS
```

The inventory identifies the host as an authorised web server and lists those services as expected. The result is therefore **Expected**, not automatically suspicious.

A different host may contain an exposed service that is not in its baseline. The tool reports **Investigate** and identifies evidence gaps such as service ownership, business justification and configuration/version review.

An unknown asset produces **Insufficient Evidence** rather than a fabricated risk rating.

## Repository structure

```text
.
├── data/
│   └── asset_inventory.json       # Synthetic asset/service baseline
├── tests/
│   └── test_network_exposure.py   # Analysis tests
├── network_exposure.py            # Context-aware assessment logic
├── nmap_parser.py                 # Nmap XML parser
├── visualizer.py                  # Exposure visualisation
├── port_scanner.py                # Optional authorised lab scanner
├── sample_scan.xml                # Synthetic Nmap-style input
└── README.md
```

Older SSH brute-force material remains available as historical learning work, but it is **not the canonical detection engine for this project**. ThreatTrace Lab is the dedicated alert-investigation project in this portfolio.

## Running the analysis

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

The analysis module can also be imported into your own investigation workflow:

```python
from network_exposure import AssetContext, ServiceObservation, assess_service

context = AssetContext(
    owner="Web Team",
    role="Web server",
    criticality="high",
    authorised=True,
    expected_services=frozenset({"tcp/80", "tcp/443", "tcp/22"}),
)

result = assess_service(
    ServiceObservation("10.10.10.20", 443, "tcp", "https"),
    context,
)

print(result)
```

## Safety and data

- Test data is synthetic and intended for educational use.
- Only scan systems you own or have explicit permission to test.
- The repository should not contain real credentials, customer data, private logs or production network captures.
- Do not use the scanner against public or third-party systems without explicit authorisation.
- Generated logs, Python caches and local output files are excluded through `.gitignore`.

## Limitations

This project is an educational investigation lab, not an enterprise asset-management platform or vulnerability-management product. It does not perform authenticated vulnerability assessment, exploitation, packet capture, continuous monitoring or automated incident response.

The assessment logic is intentionally conservative: **unknown context produces an evidence gap, not an invented conclusion**.

## Future development

Potential future work includes change detection between authorised scan snapshots, richer service/version context, an interactive recruiter investigation mode, additional synthetic cases and broader test coverage.

## Author

Created by [Karen Johnston](https://github.com/KE-Johnston1) as a practical cybersecurity portfolio project focused on network visibility, evidence-based analysis and human judgement.
