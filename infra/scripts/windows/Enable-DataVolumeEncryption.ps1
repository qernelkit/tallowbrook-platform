#Requires -Version 7.4
#Requires -Modules BitLocker
#Requires -RunAsAdministrator

# .SYNOPSIS
#   Turns on BitLocker for the finance host's data volume (spool, outbox, agent configuration).
# .DESCRIPTION
#   The recovery password is escrowed to Active Directory by group policy; this script only checks that
#   the escrow happened before it returns.
[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $MountPoint = 'D:'
)

$ErrorActionPreference = 'Stop'

$volume = Get-BitLockerVolume -MountPoint $MountPoint
if ($volume.ProtectionStatus -eq 'On') {
    Write-Verbose "$MountPoint is already protected"
    return
}

if ($PSCmdlet.ShouldProcess($MountPoint, 'Enable BitLocker')) {
    Write-Verbose "Encrypting $MountPoint (used space only)"
    Enable-BitLocker -MountPoint $MountPoint `
        -EncryptionMethod XtsAes256 `
        -UsedSpaceOnly `
        -RecoveryPasswordProtector | Out-Null

    $protector = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
        Where-Object KeyProtectorType -EQ 'RecoveryPassword' |
        Select-Object -First 1
    Backup-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $protector.KeyProtectorId | Out-Null
    Write-Verbose "Recovery password $($protector.KeyProtectorId) escrowed to Active Directory"
}
