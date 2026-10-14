#Requires -Version 7.4
#Requires -RunAsAdministrator

# .SYNOPSIS
#   Baseline settings for the finance hosts that are not covered by the domain's group policy.
# .DESCRIPTION
#   Re-run after every Windows feature update; the script is idempotent and reports what it changed.
[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = 'Stop'

$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lsaSettings = [ordered]@{
    RestrictAnonymous         = 1
    RestrictAnonymousSAM      = 1
    EveryoneIncludesAnonymous = 0
    LimitBlankPasswordUse     = 1
    LmCompatibilityLevel      = 5
}

foreach ($setting in $lsaSettings.GetEnumerator()) {
    $current = (Get-ItemProperty -Path $lsaPath -Name $setting.Key -ErrorAction SilentlyContinue).($setting.Key)
    if ($current -ne $setting.Value -and $PSCmdlet.ShouldProcess("$lsaPath\$($setting.Key)", "Set to $($setting.Value)")) {
        Set-ItemProperty -Path $lsaPath -Name $setting.Key -Value $setting.Value -Type DWord
        Write-Verbose "$($setting.Key): $current -> $($setting.Value)"
    }
}

# Only the ops jump hosts may reach the host's management ports.
$rules = @(
    @{ Name = 'Tallowbrook-RDP'; Port = 3389 }
    @{ Name = 'Tallowbrook-Backup-Share'; Port = 445 }
)
foreach ($rule in $rules) {
    if (-not (Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue) -and $PSCmdlet.ShouldProcess($rule.Name, 'Add firewall rule')) {
        New-NetFirewallRule -Name $rule.Name -DisplayName $rule.Name -Direction Inbound -Protocol TCP `
            -LocalPort $rule.Port -RemoteAddress 10.20.8.0/24 -Action Allow | Out-Null
    }
}

# The agent's gMSA may log on as a service and nothing else.
$exportPath = Join-Path $env:TEMP 'user-rights.inf'
secedit /export /cfg $exportPath /areas USER_RIGHTS | Out-Null
$policy = Get-Content -Path $exportPath
if (-not ($policy -match '^SeServiceLogonRight .*svc-billagent')) {
    Write-Warning 'svc-billagent$ is missing from "Log on as a service"; Install-BillingAgent.ps1 adds it.'
}
Remove-Item -Path $exportPath -Force
