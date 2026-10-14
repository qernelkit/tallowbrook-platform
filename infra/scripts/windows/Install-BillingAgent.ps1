#Requires -Version 7.4
#Requires -RunAsAdministrator

# .SYNOPSIS
#   Installs or updates the Billing.Agent Windows service on a finance host from the release MSI.
# .EXAMPLE
#   ./Install-BillingAgent.ps1 -MsiPath \\ops-share\releases\billing-agent\2.14.0\Tallowbrook.BillingAgent.msi
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string] $MsiPath,

    [string] $ServiceAccount = 'CORP\svc-billagent$',

    [string] $ServiceName = 'Tallowbrook Billing Agent'
)

$ErrorActionPreference = 'Stop'

if (-not (Test-ADServiceAccount -Identity ($ServiceAccount -replace '^CORP\\', ''))) {
    throw "$ServiceAccount is not installed on this host; run Install-ADServiceAccount first."
}

$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq 'Running' -and $PSCmdlet.ShouldProcess($ServiceName, 'Stop')) {
    Stop-Service -Name $ServiceName
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
}

if ($PSCmdlet.ShouldProcess($MsiPath, 'Install')) {
    $logPath = Join-Path $env:TEMP "billing-agent-install-$(Get-Date -Format yyyyMMddHHmmss).log"
    $process = Start-Process -FilePath msiexec.exe -ArgumentList '/i', "`"$MsiPath`"", '/qn', '/norestart', '/l*v', "`"$logPath`"" -Wait -PassThru
    if ($process.ExitCode -notin 0, 3010) {
        throw "msiexec failed with $($process.ExitCode); see $logPath"
    }
}

# The MSI registers the service as LocalSystem; switch it to the gMSA and set the recovery actions.
& sc.exe config $ServiceName obj= $ServiceAccount password= '' start= delayed-auto | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null

foreach ($folder in 'outbox', 'statements', 'keys') {
    $path = Join-Path 'C:/ProgramData/Tallowbrook/BillingAgent' $folder
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    $acl = Get-Acl -Path $path
    $acl.SetAccessRuleProtection($true, $false)
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($ServiceAccount, 'Modify', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new('BUILTIN\Administrators', 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'))
    Set-Acl -Path $path -AclObject $acl
}

Start-Service -Name $ServiceName
Write-Host "$ServiceName is $((Get-Service -Name $ServiceName).Status)"
