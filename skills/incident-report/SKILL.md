---
name: incident-report
description: Procedure to draft the comprehensive incident response report based on verified evidence and findings.
---
# Procedure for Incident Report Generation

1. Consolidate all verified facts, timeline events, IOCs, MITRE ATT&CK mappings, rule test results, and containment decisions.
2. Structure the final report into the following sections[cite: 76]:
   - **1. Executive Summary**: Concise overview of the incident, scope, and impact[cite: 76].
   - **2. Investigation Timeline**: Chronological events with exact `file:line` evidence references[cite: 69, 76].
   - **3. Verified Indicators of Compromise (IOCs)**: List of confirmed IOCs with status (observed, confirmed, refuted)[cite: 76].
   - **4. MITRE ATT&CK Mapping**: Observed techniques backed by evidence[cite: 39, 70, 76].
   - **5. Detection Rules & Test Results**: Details and validation results for Sigma and YARA rules[cite: 74, 76].
   - **6. Containment & Response Plan**: Proposed and approved containment actions.
   - **7. Open Questions & Recommendations**: Remaining uncertainties and next steps[cite: 76].
3. Ensure every asserted fact strictly cites its source reference (`file:line`) from the evidence[cite: 51].
4. Save the finalized report to `/output/rapport_incident.md`[cite: 76].
