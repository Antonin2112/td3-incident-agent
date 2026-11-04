rule suspicious_powershell_download : "suspicious_powershell_download" {
    meta:
        description = "Detects PowerShell scripts with encoded/command patterns associated with malicious download"
        author = "Incident Analyst"
        date = "2024-11-16"
        reference = "INC-2026-0417"
    strings:
        $encoded_cmd = "IEX.*New-Object.*WebClient.*DownloadString"
        $suspicious_url = "192.168.1.100"
        $powershell_api = "System.Management.Automation.AmsiUtils"
    condition:
        all of ($encoded_cmd, $suspicious_url) or (any of ($encoded_cmd, $powershell_api))
}