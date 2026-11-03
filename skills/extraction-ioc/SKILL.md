---
name: extraction-ioc
description: Procedure to extract, verify, and document indicators of compromise (IOCs) from incident evidence.
---
# Procedure for IOC Extraction

1. Read through all log files and evidence in `/incident/`.
2. Extract potential IOCs (IP addresses, domain names, file hashes, user accounts, obfuscated commands).
3. For each extracted IOC, execute the `verify_ioc` tool to obtain exact `file:line` references.
4. If an IOC is Base64-encoded, decode it using `decode_base64` and extract sub-IOCs.
5. Discard any IOC that cannot be verified in the evidence.
6. Summarize the verified IOCs with their `file:line` source references.
7. Save the verified IOC list to `/output/iocs.json`.
