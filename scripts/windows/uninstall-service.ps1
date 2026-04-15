param(
    [Parameter(Mandatory = $true)]
    [string]$DaemonPath,

    [Parameter(Mandatory = $false)]
    [string]$ServiceName = "AegisVpn"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $DaemonPath)) {
    throw "Daemon binary not found: $DaemonPath"
}

& $DaemonPath service-uninstall --service-name $ServiceName
