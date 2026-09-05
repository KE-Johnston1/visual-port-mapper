# Network Security Telemetry

This lab models three independent network-security evidence sources alongside authorised Nmap discovery data:

- **Firewall:** helps establish whether traffic was allowed or denied, where it came from, and which rule/policy handled it.
- **IDS:** records detection context such as a signature, timestamp, source, destination and service. An alert is a hypothesis requiring investigation, not proof of compromise.
- **IPS:** records prevention/blocking context. A block demonstrates a control action; it does not establish that exploitation succeeded or that the host was compromised.

## Analyst correlation

For each relevant event, correlate:

1. exact timestamp and timezone;
2. source and destination IP addresses;
3. protocol and destination port;
4. firewall action and rule/policy;
5. IDS/IPS signature and severity;
6. whether the event matches the Nmap observation;
7. authorised change, maintenance, testing or penetration-test activity;
8. authentication, endpoint and service evidence where available;
9. business impact and required response.

The synthetic dataset intentionally demonstrates that multiple network signals can strengthen an investigation without becoming a verdict. NET-001 contains an allowed firewall connection, an IDS reconnaissance alert and an IPS block against TCP/8080. The analyst still has to establish ownership, authorisation, service context and impact before deciding whether the exposure is expected, requires investigation, represents a security concern, or remains insufficiently evidenced.

## Data boundary

`data/network_telemetry.json` contains synthetic training evidence only. The project does not connect to or collect from live firewalls, IDS/IPS platforms, packet captures or production systems.
