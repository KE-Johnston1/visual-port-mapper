Visual Port Mapper
This repository showcases a modular approach to detecting and investigating SSH brute force activity using Python. Each tool is designed to be accessible, practical, and easy to extend.

## Projects in This Repo

This repository contains modular tools for detecting and investigating SSH brute force activity:

- **SSH Brute Force Detector**: Parses logs, flags suspicious IPs, and visualizes failed login attempts.
- **Port Scanner**: Investigates flagged IPs for open services across common ports.
- **Walkthrough**: Documents the full detection → investigation → response flow.

A Python-based tool that transforms raw Nmap scan data into clear, visual charts making network insights accessible for both technical and non-technical audiences.

 Features
 Parses Nmap XML output using Python’s xml.etree.ElementTree

Visualizes open ports per IP address using matplotlib

Labels each port with its corresponding service (e.g., 443 (https))

Saves charts as .png files for easy sharing and documentation

Runs entirely in GitHub Codespaces—no local setup required

Example Output

How to Run (in GitHub Codespaces)
Open this repo in GitHub Codespaces

Install required library:

bash
pip install matplotlib
Run the visualizer:

bash
python visualizer.py sample_scan.xml
View the saved chart in the file explorer

Project Structure
File	Purpose
nmap_parser.py	Parses Nmap XML and extracts port/service info
visualizer.py	Generates bar charts from parsed data
sample_scan.xml	Sample Nmap scan for testing
Ethical Use Notice
This tool does not perform exploitation, vulnerability testing, or penetration activities. It is designed solely for visualizing scan results from Nmap in a safe, educational context.
##  Setup Instructions

To install dependencies:

```bash
pip install -r requirements.txt
