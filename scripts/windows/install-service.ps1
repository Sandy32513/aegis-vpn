param(
    [Parameter(Mandatory = $true)]
    [string]$DaemonPath,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "config\\control-plane.toml",

    [Parameter(Mandatory = $false)]
    [string]$ServiceName = "AegisVpn",

    [Parameter(Mandatory = $false)]
    [string]$DisplayName = "Aegis VPN"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $DaemonPath)) {
    throw "Daemon binary not found: $DaemonPath"
}

& $DaemonPath service-install --daemon-path $DaemonPath --config-path $ConfigPath --service-name $ServiceName --display-name $DisplayName
