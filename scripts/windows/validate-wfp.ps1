# Aegis VPN — Windows Validation Script
# Run as Administrator on a real Windows host
# Usage: powershell -ExecutionPolicy Bypass -File scripts\windows\validate-wfp.ps1

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Write-Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "  [INFO] $msg" -ForegroundColor Yellow }

# ──────────────────────────────────────────────────────────────
Write-Step "1. Pre-test: Verify clean state"
# ──────────────────────────────────────────────────────────────

$firewallRules = Get-NetFirewallRule -Group "AegisVPN" -ErrorAction SilentlyContinue
if ($firewallRules) {
    Write-Fail "Found $($firewallRules.Count) existing AegisVPN firewall rules"
    $firewallRules | ForEach-Object { Write-Info "  - $($_.DisplayName)" }
} else {
    Write-Pass "No AegisVPN firewall rules found"
}

$adapters = Get-NetAdapter -Name "aegis*" -ErrorAction SilentlyContinue
if ($adapters) {
    Write-Fail "Found existing AegisVPN adapters"
} else {
    Write-Pass "No AegisVPN adapters found"
}

# ──────────────────────────────────────────────────────────────
Write-Step "2. Test: DNS leak check (pre-connect)"
# ──────────────────────────────────────────────────────────────

$dnsBefore = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 }
Write-Info "DNS servers before: $($dnsBefore.ServerAddresses -join ', ')"

# ──────────────────────────────────────────────────────────────
Write-Step "3. Test: IPv6 connectivity (pre-connect)"
# ──────────────────────────────────────────────────────────────

$ipv6Test = Test-Connection -ComputerName "::1" -Count 1 -Quiet -ErrorAction SilentlyContinue
if ($ipv6Test) {
    Write-Info "IPv6 loopback reachable (expected)"
} else {
    Write-Info "IPv6 loopback not reachable"
}

# ──────────────────────────────────────────────────────────────
Write-Step "4. Manual: Start daemon with kill switch"
# ──────────────────────────────────────────────────────────────

Write-Info "Run manually:"
Write-Info "  cargo run -p vpn-daemon -- run --config-path config\control-plane.toml"
Write-Info "Then verify WFP state with:"
Write-Info "  netsh wfp show state"
Write-Info "  Get-NetFirewallRule -Group AegisVPN"
Read-Host "Press Enter after starting daemon..."

# ──────────────────────────────────────────────────────────────
Write-Step "5. Test: Verify kill switch is active"
# ──────────────────────────────────────────────────────────────

$firewallRules = Get-NetFirewallRule -Group "AegisVPN" -ErrorAction SilentlyContinue
if ($firewallRules) {
    Write-Pass "Found $($firewallRules.Count) AegisVPN firewall rules"
    foreach ($rule in $firewallRules) {
        Write-Info "  - $($rule.DisplayName) [$($rule.Action)] [$($rule.Direction)]"
    }
} else {
    Write-Info "No firewall rules (may be using WFP native)"
}

# Check default outbound action
$profiles = Get-NetFirewallProfile
foreach ($profile in $profiles) {
    if ($profile.DefaultOutboundAction -eq "Block") {
        Write-Pass "Profile $($profile.Name): DefaultOutboundAction = Block"
    } else {
        Write-Info "Profile $($profile.Name): DefaultOutboundAction = $($profile.DefaultOutboundAction)"
    }
}

# ──────────────────────────────────────────────────────────────
Write-Step "6. Test: DNS leak check (post-connect)"
# ──────────────────────────────────────────────────────────────

$dnsAfter = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 }
Write-Info "DNS servers after: $($dnsAfter.ServerAddresses -join ', ')"

# ──────────────────────────────────────────────────────────────
Write-Step "7. Manual: Stop daemon"
# ──────────────────────────────────────────────────────────────

Write-Info "Stop the daemon (Ctrl+C or service stop)"
Read-Host "Press Enter after stopping daemon..."

# ──────────────────────────────────────────────────────────────
Write-Step "8. Test: Verify cleanup after disconnect"
# ──────────────────────────────────────────────────────────────

$firewallRules = Get-NetFirewallRule -Group "AegisVPN" -ErrorAction SilentlyContinue
if ($firewallRules) {
    Write-Fail "Found $($firewallRules.Count) leaked AegisVPN firewall rules after disconnect"
} else {
    Write-Pass "No AegisVPN firewall rules after disconnect"
}

$profiles = Get-NetFirewallProfile
foreach ($profile in $profiles) {
    if ($profile.DefaultOutboundAction -eq "Allow") {
        Write-Pass "Profile $($profile.Name): DefaultOutboundAction = Allow (restored)"
    } else {
        Write-Fail "Profile $($profile.Name): DefaultOutboundAction = $($profile.DefaultOutboundAction) (NOT restored)"
    }
}

# ──────────────────────────────────────────────────────────────
Write-Step "9. Test: Leak verification"
# ──────────────────────────────────────────────────────────────

$leakedRoutes = Get-NetRoute | Where-Object { $_.InterfaceAlias -like "aegis*" }
if ($leakedRoutes) {
    Write-Fail "Found $($leakedRoutes.Count) leaked routes on AegisVPN interfaces"
} else {
    Write-Pass "No leaked routes"
}

$leakedAdapters = Get-NetAdapter -Name "aegis*" -ErrorAction SilentlyContinue
if ($leakedAdapters) {
    Write-Info "Found $($leakedAdapters.Count) remaining adapters (may be normal if Wintun keeps them)"
} else {
    Write-Pass "No remaining AegisVPN adapters"
}

# ──────────────────────────────────────────────────────────────
Write-Step "Validation complete"
# ──────────────────────────────────────────────────────────────

Write-Host "`nReview results above. All PASS = Windows platform validated." -ForegroundColor Green
