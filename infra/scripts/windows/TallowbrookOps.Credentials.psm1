#Requires -Version 7.4

# Credentials of service accounts on the finance hosts.
#
# Export-OpsCredential / Import-OpsCredential move a credential from the primary finance host to the DR
# host (the file is copied through the ops share). Save-AgentCredential stores the bank portal password
# for Billing.Agent and must run as the agent's own account.

# Shared with the DR finance host.
$script:TransferKey = [byte[]](0x5d, 0xe0, 0x82, 0x69, 0x8c, 0x08, 0xa0, 0xb1, 0x75, 0x68, 0xe2, 0x0a, 0x55, 0x0b, 0x02, 0xb5, 0x4a, 0xbc, 0xf0, 0xd7, 0x48, 0x4b, 0xa5, 0x1f, 0xdf, 0x5d, 0x86, 0xf2, 0x58, 0x9a, 0x87, 0xc4)

function Export-OpsCredential {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [Parameter(Mandatory)]
        [string] $Path
    )

    $blob = ConvertFrom-SecureString -SecureString $Credential.Password -Key $script:TransferKey
    [pscustomobject]@{
        UserName   = $Credential.UserName
        Password   = $blob
        ExportedBy = [Environment]::UserName
        ExportedOn = (Get-Date).ToString('o')
    } | ConvertTo-Json | Set-Content -Path $Path -Encoding utf8NoBOM
    Write-Verbose "Exported $($Credential.UserName) to $Path"
}

function Import-OpsCredential {
    [CmdletBinding()]
    [OutputType([pscredential])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $record = Get-Content -Path $Path -Raw | ConvertFrom-Json
    $password = ConvertTo-SecureString -String $record.Password -Key $script:TransferKey
    [pscredential]::new($record.UserName, $password)
}

function Save-AgentCredential {
    # Runs as svc-billagent (through the TallowbrookBillingAgent session configuration), so only that
    # account can read the file back.
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [pscredential] $Credential,

        [string] $Path = 'C:/ProgramData/Tallowbrook/BillingAgent/bank-portal.cred'
    )

    if ($PSCmdlet.ShouldProcess($Path, 'Store bank portal password')) {
        ConvertFrom-SecureString -SecureString $Credential.Password | Set-Content -Path $Path -NoNewline
    }
}

Export-ModuleMember -Function Export-OpsCredential, Import-OpsCredential, Save-AgentCredential
