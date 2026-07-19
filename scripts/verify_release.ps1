[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,
    [Parameter(Mandatory = $true)]
    [string]$ChecksumPath
)

$ErrorActionPreference = "Stop"
$Expected = (Get-Content $ChecksumPath -Raw).Trim().Split()[0].ToLowerInvariant()
$Actual = (Get-FileHash -Algorithm SHA256 $ExePath).Hash.ToLowerInvariant()

if ($Expected -ne $Actual) {
    throw "Checksum mismatch. Expected $Expected but received $Actual."
}

Write-Host "Checksum verified: $Actual"
