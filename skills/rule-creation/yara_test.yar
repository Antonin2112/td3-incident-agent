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