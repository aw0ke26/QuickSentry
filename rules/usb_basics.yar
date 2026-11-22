// Starter rules. Drop any extra .yar files in this folder (needs yara-python).

rule LNK_Launches_Encoded_PowerShell
{
    meta:
        description = "Shortcut file that starts PowerShell with an encoded command"
    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }
        $ps  = "powershell" nocase wide ascii
        $enc = /-e(nc|ncodedcommand)?\s/ nocase wide ascii
    condition:
        $lnk at 0 and $ps and $enc
}

rule Script_Downloads_And_Runs
{
    meta:
        description = "Script that pulls something off the internet and executes it"
    strings:
        $d1 = "DownloadString" nocase
        $d2 = "DownloadFile" nocase
        $d3 = "Invoke-WebRequest" nocase
        $d4 = "bitsadmin /transfer" nocase
        $d5 = "certutil -urlcache" nocase
        $x1 = "IEX" nocase
        $x2 = "Invoke-Expression" nocase
        $x3 = "Start-Process" nocase
    condition:
        filesize < 2MB and any of ($d*) and any of ($x*)
}
