#requires -Version 5.1
#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false)]
    [string]$DaemonPath,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^[A-Za-z0-9_.-]{1,80}$')]
    [string]$ServiceName = "AegisVpn",

    [Parameter(Mandatory = $false)]
    [string]$InstallRoot = "$env:ProgramFiles\AegisVPN",

    [Parameter(Mandatory = $false)]
    [switch]$RemoveInstallRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Sc {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    $sc = Join-Path $env:SystemRoot "System32\sc.exe"
    & $sc @Arguments | Out-Null
}

if ($PSCmdlet.ShouldProcess($ServiceName, "Uninstall Aegis VPN Windows service")) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -ne "Stopped") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
        }

        if (-not [string]::IsNullOrWhiteSpace($DaemonPath) -and (Test-Path -LiteralPath $DaemonPath -PathType Leaf)) {
            $daemon = (Get-Item -LiteralPath $DaemonPath).FullName
            & $daemon service-uninstall --service-name $ServiceName
        } else {
            Invoke-Sc delete $ServiceName
        }
    }

    Get-Process -Name "vpn-daemon" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-NetFirewallRule -Group "AegisVPN" -ErrorAction SilentlyContinue | Remove-NetFirewallRule

    $backupKey = "HKLM:\Software\AegisVPN\Firewall"
    $backup = Get-ItemProperty -Path $backupKey -Name ProfileDefaultsJson -ErrorAction SilentlyContinue
    if ($backup -and $backup.ProfileDefaultsJson) {
        $profiles = $backup.ProfileDefaultsJson | ConvertFrom-Json
        foreach ($profile in @($profiles)) {
            Set-NetFirewallProfile -Profile $profile.Name -DefaultOutboundAction $profile.DefaultOutboundAction
        }
        Remove-ItemProperty -Path $backupKey -Name ProfileDefaultsJson -ErrorAction SilentlyContinue
    }

    if ($RemoveInstallRoot) {
        $installRootFull = [System.IO.Path]::GetFullPath($InstallRoot)
        if ((Split-Path -Leaf $installRootFull) -ne "AegisVPN") {
            throw "Refusing recursive removal outside an AegisVPN install root: $installRootFull"
        }
        if (Test-Path -LiteralPath $installRootFull) {
            Remove-Item -LiteralPath $installRootFull -Recurse -Force
        }
    }
}
