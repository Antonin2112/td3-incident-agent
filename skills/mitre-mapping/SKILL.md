---
name: mitre-mapping
description: Procedure to map observed malicious behaviors to MITRE ATT&CK techniques.
---
# Procedure for MITRE ATT&CK Mapping

1. Analyze the verified events and process chains in `/incident/`.
2. Identify tactics and techniques used by the attacker (e.g., Execution, Persistence, Defense Evasion, Exfiltration).
3. Validate each technique ID (e.g., T1059.001) using the `check_mitre_attack` tool.
4. For each technique, cite the supporting evidence (`file:line`).
