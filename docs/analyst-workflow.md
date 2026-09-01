# Analyst Verification Workflow

## Purpose

This project treats a network observation as evidence that requires context, not as proof of compromise.

The workflow below is deliberately conservative: establish what was observed, determine what should have been observed, identify what is still unknown, verify the explanation, then document or escalate the decision.

## Verification sequence

1. **Confirm the exact observation**
   - Preserve the source evidence and exact timestamp.
   - Confirm the host/IP, protocol, port and service information.
   - Distinguish an observed listening service from an inferred application or compromise.

2. **Establish asset context**
   - Identify the asset owner and business purpose.
   - Confirm the asset role and criticality.
   - Confirm whether the asset is authorised and still in service.

3. **Check expected state**
   - Compare the observation with the approved service/configuration baseline.
   - Check relevant change, maintenance and deployment records.
   - Confirm whether an authorised penetration test, vulnerability assessment or other security testing activity is underway.

4. **Correlate independent evidence**
   - Check network, firewall, routing or load-balancer evidence where relevant.
   - Correlate authentication and account activity with the exact time window.
   - Review endpoint/service logs where available and authorised.
   - Use packet capture or deeper telemetry only where appropriate and authorised.

5. **Assess user and business context**
   - Determine whether the observed activity matches expected user or service behaviour.
   - Consider the asset's business impact and potential cost of disruption.
   - Record material uncertainty rather than filling gaps with assumptions.

6. **Choose the least-assumptive defensible state**
   - **Expected:** evidence supports an authorised explanation and the relevant verification has been completed.
   - **Requires Investigation:** the observation is meaningful but important questions remain open.
   - **Insufficient Evidence:** there is not enough context to support a stronger conclusion.
   - **Security Concern:** evidence supports an unauthorised or materially risky condition; follow the organisation's escalation and response playbook.

7. **Close only when verified**
   - Do not treat a plausible explanation as a verified explanation.
   - Retain the evidence used to support closure or escalation.
   - If the evidence does not support closure, keep the investigation open and state exactly what is needed next.

## Example: suspicious SSH activity

An SSH observation should not automatically become an incident finding. Before closing it as expected, verify the exact timestamp, source IP context, affected account, asset ownership, authorised access, maintenance or testing activity, and relevant network/authentication evidence. If those checks cannot establish a legitimate explanation, document the remaining gaps and escalate according to the applicable playbook rather than guessing.

## Portfolio boundary

The repository uses synthetic or authorised training data. The pipeline does not perform live scanning, exploitation, packet capture or automated response. The workflow demonstrates analyst reasoning and evidence handling rather than pretending that a small sample can reproduce a production SOC.
