rule PowerShell_Encoded_Command_Malicious
{
    strings:
        $encoded = /SQBFAFgAIAAo/
        $decoded_cmd = /IEX\(New-Object Net.WebClient\)\.DownloadString/
    condition:
        $encoded and $decoded_cmd
}