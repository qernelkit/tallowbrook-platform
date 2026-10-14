#Requires -Version 7.4
#Requires -Modules ActiveDirectory

# .SYNOPSIS
#   Creates the group managed service account that Billing.Agent runs as.
# .DESCRIPTION
#   Run once from an admin workstation with domain admin rights. Finance hosts must be members of
#   FIN-AGENT-HOSTS before Install-ADServiceAccount succeeds on them.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $Name = 'svc-billagent',

    [string] $HostGroup = 'FIN-AGENT-HOSTS'
)

$ErrorActionPreference = 'Stop'

if (Get-ADServiceAccount -Filter "Name -eq '$Name'") {
    Write-Verbose "$Name already exists"
    return
}

if ($PSCmdlet.ShouldProcess($Name, 'Create gMSA')) {
    New-ADServiceAccount -Name $Name `
        -DNSHostName "$Name.corp.tallowbrook.example" `
        -KerberosEncryptionType AES256 `
        -PrincipalsAllowedToRetrieveManagedPassword $HostGroup `
        -Description 'Billing.Agent Windows service on the finance hosts'
    Write-Verbose "Created $Name; run Install-ADServiceAccount $Name on each finance host"
}
