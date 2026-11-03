---
name: rule-creation
description: Procedure to write and validate Sigma and YARA detection rules.
---
# Procedure for Detection Rule Creation

1. Review verified IOCs and process command lines.
2. Draft a Sigma rule covering process creation / suspicious execution and validate it using `validate_sigma_rule`.
3. Draft a YARA rule for suspect scripts or payloads.
4. Test the YARA rule against evidence using `test_yara_rule` to ensure it triggers without false positive.
