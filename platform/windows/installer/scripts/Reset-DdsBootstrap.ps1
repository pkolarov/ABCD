<#
.SYNOPSIS
    Wipe DDS provisioning state on the local machine so the wizard can
    restart bootstrap from a clean slate.

.DESCRIPTION
    Stops the three DDS services, deletes node-data\, node_key.bin,
    node.toml, and the bootstrap resume marker. Leaves the MSI's installed
    binaries, services, and DACL alone — only the per-domain identity is
    removed.

    Intended to be invoked from the Onboarding Wizard's "Discard and
    restart" button when the user has a half-completed bootstrap state.

    Self-elevates via UAC if not already running as Administrator.

.PARAMETER Force
    Skip the WIPE confirmation prompt.

.PARAMETER InstallRoot
    DDS install dir. Defaults to "C:\Program Files\DDS".

.PARAMETER DataRoot
    DDS data dir. Defaults to "C:\ProgramData\DDS".
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [string]$InstallRoot = "C:\Program Files\DDS",
    [string]$DataRoot    = "C:\ProgramData\DDS"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Self-elevate ─────────────────────────────────────────────────
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($Force) { $argList += "-Force" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList -Wait
    exit
}

$NodeData     = Join-Path $DataRoot    "node-data"
$NodeKey      = Join-Path $DataRoot    "node_key.bin"
$Passphrase   = Join-Path $DataRoot    "node-passphrase.dpapi"
$ProvBundle   = Join-Path $DataRoot    "provision.dds"
$ConfigDir    = Join-Path $InstallRoot "config"
$NodeToml     = Join-Path $ConfigDir   "node.toml"
$ResumeMarker = Join-Path $DataRoot    "bootstrap\.in-progress.json"
$JoinEnv      = Join-Path $DataRoot    "join.env"
$BootstrapEnv = Join-Path $DataRoot    "bootstrap.env"

Write-Host ""
Write-Host "=== DDS Reset ===" -ForegroundColor Yellow
Write-Host "This will wipe:"
foreach ($p in @($NodeData, $NodeKey, $Passphrase, $ProvBundle, $NodeToml, $ResumeMarker, $JoinEnv, $BootstrapEnv)) {
    if (Test-Path $p) { Write-Host "  - $p" }
}
Write-Host ""

if (-not $Force) {
    $resp = Read-Host "Type 'WIPE' to confirm"
    if ($resp -ne 'WIPE') {
        Write-Host "Aborted." -ForegroundColor Cyan
        exit 0
    }
}

Write-Host "Stopping services..." -ForegroundColor Yellow
foreach ($svc in @('DdsPolicyAgent','DdsAuthBridge','DdsNode')) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Stopped') {
        Write-Host "  Stopping $svc..."
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Removing state..." -ForegroundColor Yellow
foreach ($p in @($NodeData)) {
    if (Test-Path $p) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $p }
}
foreach ($p in @($NodeKey, $Passphrase, $ProvBundle, $NodeToml, $ResumeMarker, $JoinEnv, $BootstrapEnv)) {
    if (Test-Path $p) { Remove-Item -Force -ErrorAction SilentlyContinue $p }
}

# Clear the AuthBridge DeviceUrn registry stamp so it doesn't point at a
# now-vanished device URN.
$bridgeKey = 'HKLM:\SOFTWARE\DDS\AuthBridge'
if (Test-Path $bridgeKey) {
    try { Remove-ItemProperty -Path $bridgeKey -Name DeviceUrn -ErrorAction SilentlyContinue } catch { }
}

Write-Host "Reset complete. Run the onboarding wizard to bootstrap or join again." -ForegroundColor Green
