#Requires -Version 7.4

# .SYNOPSIS
#   Stores the bank upload-portal password for Billing.Agent on a finance host.
# .DESCRIPTION
#   The password is passed to a session that runs as svc-billagent (JEA configuration
#   TallowbrookBillingAgent), which writes it with Save-AgentCredential. Only that account can read
#   the stored file afterwards.
[CmdletBinding()]
param(
    [string] $ComputerName = 'localhost',

    [string] $UserName = 'TALLOWBROOK01'
)

$ErrorActionPreference = 'Stop'

$password = Read-Host -Prompt "Bank portal password for $UserName" -AsSecureString
$credential = [pscredential]::new($UserName, $password)

Invoke-Command -ComputerName $ComputerName -UseSSL -ConfigurationName TallowbrookBillingAgent -ScriptBlock {
    param($Credential)
    Import-Module 'C:/Program Files/Tallowbrook/OpsModules/TallowbrookOps.Credentials.psm1'
    Save-AgentCredential -Credential $Credential -Confirm:$false
} -ArgumentList $credential

Write-Host "Stored. Restart the 'Tallowbrook Billing Agent' service on $ComputerName to use it."
