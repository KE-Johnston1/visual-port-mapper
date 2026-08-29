# Recruiter Investigation: NET-001

## Scenario

An authorised network discovery scan identifies an internal asset with an exposed service that is not present in the current service baseline.

The analyst is **not** expected to declare the asset compromised from the scan alone.

## Initial evidence

```text
Asset:        10.10.10.50
Owner:        Unknown
Role:         Unknown
Criticality:  Unknown
Status:       Unauthorised / unverified

Observed:
22/tcp  SSH
8080/tcp HTTP-alt
```

## Analyst questions

1. Is `10.10.10.50` a known asset?
2. Who owns it and what is its business purpose?
3. Is SSH expected on this asset?
4. Is TCP/8080 expected or documented?
5. Is the host inside an authorised scanning scope?
6. Is the host reachable from networks where it should not be?
7. What software/version is providing the service?
8. Has this exposure appeared in previous authorised scans?

## Evidence gaps

At the initial stage, the analyst does not know:

- asset ownership
- business purpose
- service owner
- expected service baseline
- exposure scope
- configuration/version
- historical state

## Possible outcomes

### Expected
Use when ownership, business purpose and service authorisation are verified and the observed service matches the approved baseline.

### Investigate
Use when an exposed service or asset is not explained by the current baseline and there is enough evidence to justify further investigation.

### Insufficient Evidence
Use when the available information is too limited to make a defensible assessment.

### Security Concern
Use only after sufficient evidence establishes that the exposure is unauthorised or creates a material security risk under the organisation's policies and risk criteria.

## Analyst communication example

> The scan identified SSH and TCP/8080 on 10.10.10.50. The asset is not currently associated with an owner or approved service baseline. This is insufficient to conclude compromise, but the exposure cannot be validated as expected. I recommend verifying ownership and business purpose, confirming authorised services, checking configuration/version information, and comparing the host against previous authorised scan results before deciding whether remediation or escalation is required.

## Learning objective

This scenario demonstrates the difference between **network discovery** and **security judgement**. The tool provides evidence. The analyst provides context, challenges assumptions, identifies gaps and documents the reasoning behind the decision.
