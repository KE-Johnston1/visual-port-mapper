# SSH Brute Force Detection & Investigation Walkthrough

## Scenario

A suspected brute force attack is targeting SSH services. Multiple failed login attempts are observed in the system logs.

## Step 1: Detection

- Used `ssh_brute_force_detector.py` to parse `sample_auth.log`  
- Flagged IP addresses with more than three failed login attempts  
- Saved results to `suspicious_ips.txt`  
- Visualised login failures using a bar chart (`ssh_attempts_chart.png`)

## Step 2: Investigation

- Executed `port_scanner.py` to check open ports on flagged IPs  
- Scanned ports 22 (SSH), 80 (HTTP), and 443 (HTTPS)  
- All ports were closed, suggesting the IPs may be spoofed, inactive, or previously blocked

## Step 3: Response

- Recommended blocking IPs with repeated failed attempts  
- Suggested enabling rate limiting and key-based authentication  
- Logged findings for future incident review

## Summary

This modular workflow demonstrates how Python can support real-world threat detection, investigation, and response. It includes:

- A log parser that flags suspicious SSH login attempts  
- A port scanner that checks for exposed services across common ports  
- Clear documentation and visual output for both technical and non-technical audiences

Together, these tools form a practical, accessible approach to analysing potential threats and communicating findings effectively.


