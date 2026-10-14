#Requires -Version 7.4

# .SYNOPSIS
#   Authenticode-signs every script and module in this folder before it is copied to the finance hosts.
# .DESCRIPTION
#   The finance hosts run with the AllSigned execution policy. The signing identity must be the
#   company code-signing certificate, installed in CurrentUser\My of the release engineer.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $TimestampServer = 'http://timestamp.tallowbrook.example/tsa',

    [string] $Path = $PSScriptRoot
)

$ErrorActionPreference = 'Stop'

$expected = Get-PfxCertificate -FilePath (Join-Path $env:ProgramData 'Tallowbrook/pki/signing/windows-codesign.crt')
$signingCert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert |
    Where-Object Thumbprint -EQ $expected.Thumbprint |
    Select-Object -First 1
if (-not $signingCert) {
    throw "Import the company code-signing identity (thumbprint $($expected.Thumbprint)) into CurrentUser\My first."
}

$scripts = Get-ChildItem -Path $Path -Recurse -File -Include '*.ps1', '*.psm1', '*.psd1'
Write-Host "Signing $($scripts.Count) scripts as $($signingCert.Subject)"
foreach ($file in $scripts) {
    if ($PSCmdlet.ShouldProcess($file.Name, 'Sign')) {
        $result = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $signingCert -HashAlgorithm SHA256 -TimestampServer $TimestampServer
        if ($result.Status -ne 'Valid') {
            Write-Warning "$($file.Name): $($result.StatusMessage)"
        }
    }
}
