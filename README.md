# Visual Port Mapper

A modular Python toolkit for visualising open ports and services from Nmap scan data.  
Designed to make network insights accessible for both technical and non-technical audiences.

## Overview

This repository includes tools for detecting and investigating SSH brute force activity:

- **SSH Brute Force Detector**  
  Parses logs, flags suspicious IP addresses, and visualises failed login attempts.

- **Port Scanner**  
  Investigates flagged IPs for open services across common ports.

- **Walkthrough**  
  Documents the full detection → investigation → response workflow.

## Features

- Parses Nmap XML output using Python’s `xml.etree.ElementTree`  
- Visualises open ports per IP address using `matplotlib`  
- Labels each port with its corresponding service (e.g. 443 → HTTPS)  
- Saves charts as `.png` files for documentation and sharing  
- Runs entirely in GitHub Codespaces—no local setup required

## Example Output

Sample charts are stored in the repository (`ssh_attempts_chart.png`, `open_ports_192_168_1_1.png`)  
Each visual includes service labels and detection context.

## How to Run (in GitHub Codespaces)

1. Open this repository in GitHub Codespaces  
2. Install required libraries:
pip install matplotlib
3. Run the visualiser:
python visualizer.py sample_scan.xml
4. View the saved chart in the file explorer

## Project Structure

| File                  | Purpose                                         |
|-----------------------|-------------------------------------------------|
| `nmap_parser.py`      | Parses Nmap XML and extracts port/service data |
| `visualizer.py`       | Generates bar charts from parsed data          |
| `sample_scan.xml`     | Sample Nmap scan for testing                   |
| `ssh_brute_force_detector.py` | Flags suspicious SSH login attempts    |
| `port_scanner.py`     | Scans flagged IPs for open ports               |
| `ssh_brute_force_walkthrough.md` | Step-by-step detection guide        |

## Ethical Use Notice

This toolkit does not perform exploitation, vulnerability testing, or penetration activities.  
It is intended solely for visualising scan results from Nmap in a safe, educational context.

## Setup Instructions

To install all dependencies:
pip install -r requirements.txt


## Author

Created by [Karen Johnston](https://github.com/KE-Johnston1) — entry-level cybersecurity analyst focused on ethical detection tooling and modular documentation.

