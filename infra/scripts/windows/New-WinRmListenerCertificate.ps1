#Requires -Version 7.4
#Requires -Modules PKI
#Requires -RunAsAdministrator

# .SYNOPSIS
#   Creates the WinRM listener certificate on a finance host and binds the HTTPS listener to it.
# .DESCRIPTION
#   Ops connect to the finance hosts with Enter-PSSession -UseSSL only. The listener certificate is
#   created on the host itself and never leaves it; its thumbprint is recorded in the CMDB.
# .EXAMPLE
#   ./New-WinRmListenerCertificate.ps1 -HostName fin-host-01.corp.tallowbrook.example -Verbose
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('\.corp\.tallowbrook\.example$')]
    [string] $HostName,

    [ValidateRange(1, 3)]
    [int] $ValidYears = 2
)

$ErrorActionPreference = 'Stop'

$certificateParameters = @{
    Subject           = "CN=$HostName"
    DnsName           = $HostName, ($HostName -split '\.')[0]
    KeyAlgorithm      = 'RSA'
    KeyLength         = 2048
    HashAlgorithm     = 'SHA256'
    Provider          = 'Microsoft Software Key Storage Provider'
    KeyExportPolicy   = 'NonExportable'
    KeyUsage          = 'DigitalSignature', 'KeyEncipherment'
    TextExtension     = @('2.5.29.37={text}1.3.6.1.5.5.7.3.1')
    CertStoreLocation = 'Cert:\LocalMachine\My'
    NotAfter          = (Get-Date).AddYears($ValidYears)
}

$existing = Get-ChildItem -Path WSMan:\localhost\Listener |
    Where-Object { $_.Keys -contains 'Transport=HTTPS' }

if ($PSCmdlet.ShouldProcess($HostName, 'Create listener key pair and bind WinRM')) {
    $listenerCert = New-SelfSignedCertificate @certificateParameters
    Write-Verbose "Created $($listenerCert.Thumbprint), valid until $($listenerCert.NotAfter.ToString('yyyy-MM-dd'))"

    if ($existing) {
        Write-Verbose 'Removing the previous HTTPS listener'
        $existing | Remove-Item -Recurse -Force
    }

    New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $listenerCert.Thumbprint -HostName $HostName -Force | Out-Null

    $rule = Get-NetFirewallRule -Name 'Tallowbrook-WinRM-HTTPS' -ErrorAction SilentlyContinue
    if (-not $rule) {
        New-NetFirewallRule -Name 'Tallowbrook-WinRM-HTTPS' -DisplayName 'WinRM over HTTPS (ops jump hosts)' `
            -Direction Inbound -Protocol TCP -LocalPort 5986 -RemoteAddress 10.20.8.0/24 -Action Allow | Out-Null
    }

    [pscustomobject]@{
        HostName   = $HostName
        Thumbprint = $listenerCert.Thumbprint
        NotAfter   = $listenerCert.NotAfter
    }
}
