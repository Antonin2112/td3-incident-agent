INC-2026-0417 - Incident Rules Complete

Directory: /output/incident_rules/

Files Created:
- suspicious_powershell_outlook.yml (Sigma rule - VALIDATED)
- yara_suspicious_download.yar (YARA rule for encoded PS)
- yara_test_file.yar (YARA test rule)
- SUMMARY.md (Complete incident summary)

Key IOCs:
- 203.0.113.42 - SQL injection source IP
- malicious-domain.ru - Malicious domain referenced
- 192.168.1.100 - Suspicious download URL
- PC-COMPTA-07 - Compromised host
- facture_2024-11.ps1 - Malicious PowerShell script

Techniques: T1059.001, T1059, T1068, T1566.002