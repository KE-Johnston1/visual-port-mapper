# Analyst Verification Workflow

## Purpose

This project treats a network observation as evidence that requires context, not as proof of compromise.

The workflow below is deliberately conservative: establish what was observed, determine what should have been observed, identify what is still unknown, verify the explanation, then document or escalate the decision. In a production SOC, this investigation also has to be **timely**: analysts balance evidence quality with alert severity, business impact and applicable response targets.

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

4. **Use security tooling to accelerate investigation**
   - Where available, use **SIEM** telemetry to centralise and correlate relevant events across systems and time windows.
   - Use **EDR** telemetry to investigate endpoint processes, users, files, network connections and other host-level evidence where appropriate.
   - Use **SOAR** capabilities to automate repetitive enrichment or investigation steps and support consistent playbook execution.
   - Treat tool output as investigative evidence and context, not as an automatic verdict.
   - The analyst remains responsible for validating the evidence, assessing confidence and making the defensible decision.

   These tools can reduce investigation time by bringing related evidence together and automating repeatable tasks. This matters because delayed investigation or response can increase business impact, particularly for higher-severity events. In a real environment, the investigation is therefore prioritised according to severity, asset criticality, business impact and the organisation's applicable **SLA/OLA, escalation and incident-response requirements**.

5. **Correlate independent evidence**
   - Check network, firewall, routing or load-balancer evidence where relevant.
   - Correlate authentication and account activity with the exact time window.
   - Review endpoint/service logs where available and authorised.
   - Use packet capture or deeper telemetry only where appropriate and authorised.
   - Where SIEM/EDR/SOAR data is available, record which source contributed to the assessment rather than treating a single tool as authoritative.

6. **Assess user and business context**
   - Determine whether the observed activity matches expected user or service behaviour.
   - Consider the asset's business impact and potential cost of disruption.
   - Consider whether the event requires immediate escalation or containment before the investigation is fully complete.
   - Record material uncertainty rather than filling gaps with assumptions.

7. **Choose the least-assumptive defensible state**
   - **Expected:** evidence supports an authorised explanation and the relevant verification has been completed.
   - **Requires Investigation:** the observation is meaningful but important questions remain open.
   - **Insufficient Evidence:** there is not enough context to support a stronger conclusion.
   - **Security Concern:** evidence supports an unauthorised or materially risky condition; follow the organisation's escalation and response playbook.

8. **Close only when verified**
   - Do not treat a plausible explanation as a verified explanation.
   - Retain the evidence used to support closure or escalation.
   - If the evidence does not support closure, keep the investigation open and state exactly what is needed next.
   - Record the decision, rationale, relevant evidence sources and any required follow-up or escalation.

## Investigation efficiency and business impact

A production SOC is not only concerned with whether an analyst reaches the correct conclusion; it also has to reach that conclusion **within an appropriate operational timeframe**. SIEM, EDR and SOAR can support this by reducing manual searching, correlating related evidence, enriching alerts and automating repeatable actions.

The objective is not to replace analyst judgement. The objective is to allow the analyst to spend more time evaluating the evidence and less time performing repetitive collection and correlation.

A useful mental model is:

```text
Alert / Observation
        ↓
Severity + Asset Criticality + Business Impact
        ↓
SIEM / EDR / SOAR enrichment and correlation
        ↓
Analyst validation and evidence review
        ↓
Defensible assessment
        ↓
Escalate / Contain / Remediate / Monitor / Close
        ↓
Document against applicable response requirements
```

**Important:** an SLA is organisation-specific. The lab does not claim to implement a particular production SLA. Instead, it demonstrates the principle that investigation priority and response timing are operational concerns alongside technical accuracy.

## Example: suspicious SSH activity

An SSH observation should not automatically become an incident finding. Before closing it as expected, verify the exact timestamp, source IP context, affected account, asset ownership, authorised access, maintenance or testing activity, and relevant network/authentication evidence.

Where available, SIEM correlation could quickly identify related authentication failures or successful logins, while EDR could provide endpoint/process context. SOAR could automate repeatable enrichment or lookups. These capabilities can shorten the time needed to assemble evidence, but the analyst should still validate the evidence and determine whether the activity is authorised, suspicious or requires escalation.

If the evidence cannot establish a legitimate explanation, document the remaining gaps and escalate according to the applicable severity, business-impact and response requirements rather than guessing.

## Portfolio boundary

The repository uses synthetic or authorised training data. The pipeline does not perform live scanning, exploitation, packet capture or automated response. SIEM, EDR and SOAR are discussed as **production investigation concepts and workflow integrations**, not as claims that this small lab operates a live enterprise SOC or connects to those platforms.
