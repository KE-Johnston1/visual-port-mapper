# Recruiter Investigation: NET-001

## Scenario

An authorised network discovery scan identifies an internal asset with exposed services that are not present in the current service baseline.

The analyst is **not** expected to declare the asset compromised from the scan alone.

## Initial evidence

```text
Asset:        10.10.10.50
Owner:        Unknown
Role:         Unknown
Criticality:  Unknown
Authorisation: Not established

Observed:
22/tcp  SSH
8080/tcp HTTP-alt
```

The distinction matters: **“not established” is not the same as “confirmed unauthorised.”**

## Analyst questions

1. Is `10.10.10.50` a known asset?
2. Who owns it and what is its business purpose?
3. Is SSH expected on this asset?
4. Is TCP/8080 expected or documented?
5. Is the host inside an authorised scanning scope?
6. What was the exact discovery timestamp and timezone?
7. Is the host reachable from networks where it should not be?
8. What software/version is providing each service?
9. Has this exposure appeared in previous authorised scans?
10. Was a deployment, maintenance window, vulnerability assessment or penetration test underway at the time?
11. Do network, firewall, authentication or host logs corroborate the observation and its context?

## Evidence gaps

At the initial stage, the analyst does not know:

- asset ownership
- business purpose
- service owner
- expected service baseline
- exact event timing/context
- exposure scope
- configuration/version
- historical state
- whether authorised testing or maintenance explains the observation

## Verification sequence

The analyst should establish the facts in roughly this order:

1. Preserve the original scan evidence and exact timestamp.
2. Identify the asset owner, business role and criticality.
3. Confirm authorised status and expected services.
4. Check approved change, deployment, maintenance and security-testing activity.
5. Correlate independent network, authentication and host evidence where available.
6. Assess the business impact and exposure scope.
7. Record the least-conclusive assessment supported by the evidence.

A plausible explanation is not treated as a verified explanation until the relevant evidence has been checked.

## Possible outcomes

### Expected

Use when ownership, business purpose, service authorisation and the relevant explanation are verified and the observed service matches the approved baseline.

### Investigate

Use when an exposed service or asset is not explained by the current baseline and there is enough evidence to justify further investigation.

### Insufficient Evidence

Use when important context is unavailable and a stronger conclusion would require assumptions.

### Security Concern

Use only after sufficient evidence establishes that the exposure is unauthorised or creates a material security risk under the organisation's policies and risk criteria. Follow the applicable escalation and response playbook.

## Analyst communication example

> The scan identified SSH and TCP/8080 on 10.10.10.50. The asset is not currently associated with an owner or approved service baseline, so the authorisation status has not been established. This is insufficient to conclude compromise. I recommend verifying ownership and business purpose, confirming authorised services, checking the exact discovery timestamp against change, maintenance or security-testing activity, validating exposure scope, reviewing service/version context, and correlating relevant network or authentication evidence before deciding whether remediation or escalation is required.

## Learning objective

This scenario demonstrates the difference between **network discovery** and **security judgement**. The tool provides evidence. The analyst provides context, challenges assumptions, identifies gaps and documents the reasoning behind the decision.
