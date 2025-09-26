Visual Port Mapper
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
