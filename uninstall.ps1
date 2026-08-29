#Requires -RunAsAdministrator
<#
    Removing Steganon from Windows.

    It stops the protection first, then removes the files. The settings and the
    certificates stay unless the opposite is asked for explicitly — an
    uninstall must not destroy data the user put there.

    Usage:  powershell -ExecutionPolicy Bypass -File uninstall.ps1 [-Purge]
#>

param([switch]$Purge)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Root    = "$env:ProgramFiles\Steganon"
$DataDir = "$env:ProgramData\Steganon"

function Step($text) { Write-Host "▸ $text" -ForegroundColor Cyan }
function Ok($text)   { Write-Host "  ✓ $text" -ForegroundColor Green }

# ── 1. Stopping the protection ────────────────────────────────────────────
#
# In the order that matters: the task first, so the supervisor does not bring
# the connection back; then the disconnect; the firewall last, so there is
# never a moment with an open network and no protection.
Step "Stopping protection"
Stop-ScheduledTask -TaskName 'Steganon' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Steganon' -Confirm:$false -ErrorAction SilentlyContinue
if (Test-Path "$Root\steganon.cmd") {
    & "$Root\steganon.cmd" down 2>&1 | Out-Null
}

# Safety catch: if the tool can no longer run, the firewall is cleared
# directly. Otherwise the machine would be left without a network after the
# removal.
Get-NetFirewallRule -DisplayName 'Steganon*' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow `
    -ErrorAction SilentlyContinue
Get-Process openvpn -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Ok "firewall and connection are off"

# ── 2. Files ──────────────────────────────────────────────────────────────
Step "Removing files"
Remove-Item "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Steganon.lnk" `
    -Force -ErrorAction SilentlyContinue
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\Steganon.cmd" `
    -Force -ErrorAction SilentlyContinue
Remove-Item $Root -Recurse -Force -ErrorAction SilentlyContinue
Ok "application and shortcuts"

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($machinePath -like "*$Root*") {
    $cleaned = ($machinePath -split ';' | Where-Object { $_ -and $_ -ne $Root }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $cleaned, 'Machine')
    Ok "search path cleaned up"
}

if ($Purge) {
    Step "Deleting settings and certificates"
    Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    Ok "$DataDir"
} else {
    Write-Host "  The settings stay in $DataDir (-Purge to remove them)"
}

Write-Host ""
Write-Host "Removed. Traffic now leaves unprotected." -ForegroundColor Yellow
Write-Host ""
