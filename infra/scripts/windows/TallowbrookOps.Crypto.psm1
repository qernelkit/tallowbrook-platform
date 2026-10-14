#Requires -Version 7.4

# Text encodings shared by the ops scripts: URL-safe base64 for ids in the CMDB, lower-case hex for
# thumbprint and checksum comparisons.

function ConvertTo-Base64Url {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertTo-HexString {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    [Convert]::ToHexString($Bytes).ToLowerInvariant()
}

Export-ModuleMember -Function ConvertTo-Base64Url, ConvertTo-HexString
