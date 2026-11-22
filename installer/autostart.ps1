# Registers / removes the QuickSentry sign-in task (called by the installer).
# Uses Register-ScheduledTask so the task has NO run-time limit (schtasks.exe defaults to 72 hours,
# which would quietly kill QuickSentry on a PC that stays up for days).
param(
    [switch]$Install,
    [switch]$Remove,
    [string]$Exe,
    [string]$User = $env:USERNAME
)
$ErrorActionPreference = 'Stop'
$name = 'QuickSentry'

if ($Remove) {
    Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
    exit 0
}
if ($Install) {
    if (-not (Test-Path -LiteralPath $Exe)) { throw "Not found: $Exe" }
    $action    = New-ScheduledTaskAction -Execute $Exe -Argument '--tray'
    $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $User
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
                   -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Settings $settings `
        -Principal $principal -Description 'QuickSentry network/hardware/port sentry (tray)' -Force | Out-Null
    exit 0
}
Write-Host 'Use -Install -Exe <path> [-User <name>]  or  -Remove'
exit 1
