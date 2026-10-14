#Requires -Version 7.4

# .SYNOPSIS
#   Nightly backup of Billing.Agent's configuration folder to the finance backup share.
# .DESCRIPTION
#   The zip is encrypted with a random key for each run; that key is in turn encrypted to the Finance
#   Operations recipient, whose certificate is in the machine store of every finance host. Restores are
#   done with Unprotect-CmsMessage on an ops workstation holding the recipient's key.
[CmdletBinding()]
param(
    [string] $ConfigurationPath = 'C:/ProgramData/Tallowbrook/BillingAgent',

    [string] $Destination = '\\fin-backup01\agent-config',

    [string] $Recipient = 'CN=Tallowbrook Finance Operations',

    [int] $KeepDays = 90
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'TallowbrookOps.Crypto.psm1')

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$zipPath = Join-Path ([IO.Path]::GetTempPath()) "agent-config-$stamp.zip"
Compress-Archive -Path (Join-Path $ConfigurationPath '*') -DestinationPath $zipPath -CompressionLevel Optimal -Force

$aes = [System.Security.Cryptography.Aes]::Create()
try {
    $keyEnvelope = Protect-CmsMessage -To $Recipient -Content ([Convert]::ToBase64String([byte[]]($aes.Key + $aes.IV)))

    $backupPath = Join-Path $Destination "agent-config-$stamp.zip.bin"
    $output = [IO.File]::Create($backupPath)
    try {
        $stream = [System.Security.Cryptography.CryptoStream]::new($output, $aes.CreateEncryptor(), 'Write')
        $source = [IO.File]::OpenRead($zipPath)
        try {
            $source.CopyTo($stream)
            $stream.FlushFinalBlock()
        }
        finally {
            $source.Dispose()
            $stream.Dispose()
        }
    }
    finally {
        $output.Dispose()
    }

    Set-Content -Path (Join-Path $Destination "agent-config-$stamp.key.cms") -Value $keyEnvelope
    $checksum = (Get-FileHash -Algorithm SHA256 -Path $backupPath).Hash
    Set-Content -Path "$backupPath.sha256" -Value $checksum.ToLowerInvariant()
    Write-Verbose "Backup $(Split-Path -Leaf $backupPath) written, id $(ConvertTo-Base64Url -Bytes ([Text.Encoding]::ASCII.GetBytes($stamp)))"
}
finally {
    $aes.Dispose()
    Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
}

Get-ChildItem -Path $Destination -File |
    Where-Object LastWriteTime -LT (Get-Date).AddDays(-$KeepDays) |
    Remove-Item -Force
