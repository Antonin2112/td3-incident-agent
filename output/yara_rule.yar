rule Suspicious_PowerShell_Download:
{
    meta:
        description = "Detects obfuscated PowerShell scripts with encoded commands"
        author = "SOC Level-2 Analyst"
        date = "2026-01-15"
    strings:
        $obfuscated = "SQBFAFgA"
        $powershell = "powershell.exe"
    condition:
        uint16(0) == 0x5A4D and
        any of ($obfuscated) and
        any of ($powershell)
}