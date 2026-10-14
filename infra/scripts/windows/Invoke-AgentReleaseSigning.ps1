#Requires -Version 7.4

# .SYNOPSIS
#   Release build step: signs Billing.Agent.exe and its MSI before they are published to the ops share.
# .PARAMETER ReleaseDirectory
#   Output folder of the release build (contains Billing.Agent.exe and Tallowbrook.BillingAgent.msi).
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $ReleaseDirectory,

    [string] $TimestampServer = 'http://timestamp.tallowbrook.example/tsa'
)

$ErrorActionPreference = 'Stop'

$signtool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter signtool.exe |
    Where-Object FullName -Match '\\x64\\' |
    Sort-Object FullName -Descending |
    Select-Object -First 1 -ExpandProperty FullName
if (-not $signtool) {
    throw 'signtool.exe not found; install the Windows SDK signing tools on the build agent.'
}

$artifacts = @(
    Join-Path $ReleaseDirectory 'Billing.Agent.exe'
    Join-Path $ReleaseDirectory 'Tallowbrook.BillingAgent.msi'
)
foreach ($artifact in $artifacts) {
    if (-not (Test-Path -LiteralPath $artifact)) {
        throw "Missing release artifact: $artifact"
    }
}

$signArguments = @(
    'sign'
    '/n', 'Tallowbrook Logistics Code Signing'
    '/fd', 'SHA256'
    '/tr', $TimestampServer
    '/td', 'SHA256'
    '/d', 'Tallowbrook Billing Agent'
)

Write-Verbose "Running $signtool for $($artifacts.Count) file(s)"
& $signtool @signArguments $artifacts
if ($LASTEXITCODE -ne 0) {
    throw "signtool exited with $LASTEXITCODE"
}
