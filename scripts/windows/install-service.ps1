#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$DaemonPath,

    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "config\control-plane.toml",

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string]$ServiceName = "AegisVpn",

    [Parameter(Mandatory = $false)]
    [string]$DisplayName = "Aegis VPN",

    [Parameter(Mandatory = $false)]
    [string]$InstallRoot = "$env:ProgramFiles\AegisVPN"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-ExistingFile {
    param(
        [Parameter(Mandatory = $true)][string]$PathValue,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $item = Get-Item -LiteralPath $PathValue -ErrorAction Stop
    if (-not ($item -is [System.IO.FileInfo])) {
        throw "$Label is not a file: $PathValue"
    }
    return $item.FullName
}

if ([string]::IsNullOrWhiteSpace($DisplayName) -or $DisplayName.Length -gt 256) {
    throw "DisplayName must be 1-256 characters"
}
if ($DisplayName.ToCharArray() | Where-Object { [char]::IsControl($_) }) {
    throw "DisplayName cannot contain control characters"
}

$daemonSource = Resolve-ExistingFile -PathValue $DaemonPath -Label "DaemonPath"
$configSource = $null
if (-not [string]::IsNullOrWhiteSpace($ConfigPath)) {
    $configSource = Resolve-ExistingFile -PathValue $ConfigPath -Label "ConfigPath"
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "Service already exists: $ServiceName. Run uninstall-service.ps1 first."
}

$installRootFull = [System.IO.Path]::GetFullPath($InstallRoot)
$daemonTarget = Join-Path $installRootFull "vpn-daemon.exe"
$configTarget = $null
if ($configSource) {
    $configDir = Join-Path $installRootFull "config"
    $configTarget = Join-Path $configDir "control-plane.toml"
}

if ($PSCmdlet.ShouldProcess($ServiceName, "Install Aegis VPN Windows service")) {
    New-Item -ItemType Directory -Path $installRootFull -Force | Out-Null
    if ($configTarget) {
        New-Item -ItemType Directory -Path (Split-Path -Parent $configTarget) -Force | Out-Null
    }

    Copy-Item -LiteralPath $daemonSource -Destination $daemonTarget -Force
    if ($configTarget) {
        Copy-Item -LiteralPath $configSource -Destination $configTarget -Force
    }

    icacls $installRootFull /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    icacls $daemonTarget /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($configTarget) {
        icacls $configTarget /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    }

    $daemonArgs = @("service-install", "--daemon-path", $daemonTarget, "--service-name", $ServiceName, "--display-name", $DisplayName)
    if ($configTarget) {
        $daemonArgs += @("--config-path", $configTarget)
    }

    & $daemonTarget @daemonArgs
    & (Join-Path $env:SystemRoot "System32\sc.exe") query $ServiceName | Out-String | Write-Verbose
}
