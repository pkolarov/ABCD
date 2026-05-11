<#
.SYNOPSIS
    E2E assertions for Onboarding Wizard — Branch A (start a new domain).

.DESCRIPTION
    Run on a Windows VM after a fresh MSI install + driving the wizard
    through "Start a new DDS domain". Asserts the on-disk state, services,
    and named-pipe API match what bootstrap should produce.

    This script does NOT drive the wizard — it verifies the result. The
    wizard auto-launches via Active Setup on first interactive logon, or
    can be launched manually via the "DDS Console" Start-menu shortcut.

.PARAMETER InstallRoot
    DDS install dir. Defaults to "C:\Program Files\DDS".

.PARAMETER DataRoot
    DDS data dir. Defaults to "C:\ProgramData\DDS".

.PARAMETER ExpectedDomainName
    Expected domain name (matches what was typed in the wizard). When
    supplied, asserts domain.toml's name field equals this.

.OUTPUTS
    Exits 0 if all assertions pass, 1 otherwise. Prints PASS/FAIL lines
    so the caller can scrape them.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\Program Files\DDS",
    [string]$DataRoot    = "C:\ProgramData\DDS",
    [string]$ExpectedDomainName = ""
)

$ErrorActionPreference = "Continue"
$pass = 0
$fail = 0

function Assert {
    param([string]$Name, [bool]$Cond, [string]$Detail = "")
    if ($Cond) {
        Write-Host "PASS  $Name" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "FAIL  $Name $Detail" -ForegroundColor Red
        $script:fail++
    }
}

# ── Files ─────────────────────────────────────────────────────────
$NodeData       = Join-Path $DataRoot    'node-data'
$DomainTomlPath = Join-Path $NodeData    'domain.toml'
$AdmissionPath  = Join-Path $NodeData    'admission.cbor'
$DomainKeyPath  = Join-Path $NodeData    'domain_key.bin'
$NodeTomlPath   = Join-Path $InstallRoot 'config\node.toml'
$ProvBundle     = Join-Path $DataRoot    'provision.dds'
$BootstrapEnv   = Join-Path $DataRoot    'bootstrap.env'
$ResumeMarker   = Join-Path $DataRoot    'bootstrap\.in-progress.json'

Assert "domain.toml exists"      (Test-Path $DomainTomlPath) "(at $DomainTomlPath)"
Assert "admission.cbor exists"   (Test-Path $AdmissionPath)  "(at $AdmissionPath)"
Assert "domain_key.bin exists"   (Test-Path $DomainKeyPath)
Assert "node.toml exists"        (Test-Path $NodeTomlPath)
Assert "provision.dds exists"    (Test-Path $ProvBundle)
Assert "bootstrap.env exists"    (Test-Path $BootstrapEnv)
Assert "no leftover resume marker" (-not (Test-Path $ResumeMarker)) "(should be cleared on success)"

# ── Domain name (if expected) ─────────────────────────────────────
if ($ExpectedDomainName) {
    if (Test-Path $DomainTomlPath) {
        $dt = Get-Content $DomainTomlPath -Raw
        $ok = $dt -match ('(?m)^name\s*=\s*"' + [regex]::Escape($ExpectedDomainName) + '"')
        Assert "domain.toml name matches '$ExpectedDomainName'" $ok
    } else {
        Assert "domain.toml name matches '$ExpectedDomainName'" $false "(domain.toml not present)"
    }
}

# ── Services ──────────────────────────────────────────────────────
foreach ($svc in @('DdsNode','DdsAuthBridge','DdsPolicyAgent')) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    Assert "$svc registered"  ([bool]$s)
    Assert "$svc running"     ($s -and $s.Status -eq 'Running') "(status: $($s.Status))"
}

# ── Pipe + node API ───────────────────────────────────────────────
Assert "named-pipe \\.\pipe\dds-api open" (Test-Path '\\.\pipe\dds-api')

try {
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'dds-api', [System.IO.Pipes.PipeDirection]::InOut)
    $client.Connect(2000)
    $req = "GET /v1/health HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n"
    $b = [Text.Encoding]::UTF8.GetBytes($req)
    $client.Write($b, 0, $b.Length); $client.Flush()
    $ms = New-Object System.IO.MemoryStream
    $buf = New-Object byte[] 4096
    while (($n = $client.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n) }
    $client.Dispose()
    $resp = [Text.Encoding]::UTF8.GetString($ms.ToArray())
    Assert "GET /v1/health returns 2xx" ($resp -match '^HTTP/1.1 2\d\d')
} catch {
    Assert "GET /v1/health returns 2xx" $false "($($_.Exception.Message))"
}

# ── AuthBridge stamp ──────────────────────────────────────────────
$bridge = 'HKLM:\SOFTWARE\DDS\AuthBridge'
if (Test-Path $bridge) {
    $du = (Get-ItemProperty -Path $bridge -Name 'DeviceUrn' -ErrorAction SilentlyContinue).DeviceUrn
    Assert "AuthBridge\DeviceUrn populated" (-not [string]::IsNullOrWhiteSpace($du)) "(value: $du)"
} else {
    Assert "AuthBridge\DeviceUrn populated" $false "(registry key missing)"
}

# ── Summary ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "=========================================="
Write-Host ("  Branch A: PASS={0}, FAIL={1}" -f $pass, $fail) -ForegroundColor (& { if ($fail -eq 0) { 'Green' } else { 'Red' } })
Write-Host "=========================================="
exit ($(if ($fail -eq 0) { 0 } else { 1 }))
