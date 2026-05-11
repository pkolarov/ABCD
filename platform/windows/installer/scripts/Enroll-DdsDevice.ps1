<#
.SYNOPSIS
    Post-provision device-enrollment helper. Used by Branch B (Join Domain)
    of the onboarding wizard, after `dds-node provision <bundle>` has
    written domain.toml + admission.cbor + node.toml.

.DESCRIPTION
    Equivalent to steps 6-9 of Bootstrap-DdsDomain.ps1, factored out so
    they can run after `dds-node provision`. Specifically:

      6. Start DdsNode service and wait for the named-pipe API.
      7. POST /v1/enroll/device with this machine's hostname/OS.
      8. Stamp DeviceUrn + PinnedNodePubkeyB64 into appsettings.json
         and HKLM\SOFTWARE\DDS\AuthBridge\DeviceUrn.
      9. Start DdsAuthBridge and DdsPolicyAgent.

    Self-elevates via UAC if not already running as Administrator.

.PARAMETER OrgUnit
    Organization-unit tag for /v1/enroll/device (typically the same
    `org_hash` the domain was bootstrapped with). Read from node.toml's
    `org_hash` field if not supplied.

.PARAMETER InstallRoot
    DDS install dir. Defaults to "C:\Program Files\DDS".

.PARAMETER DataRoot
    DDS data dir. Defaults to "C:\ProgramData\DDS".

.OUTPUTS
    Writes ##DDS-DEVICE-ENROLL## markers to stdout the wizard tails:
      ##DDS-DEVICE-ENROLL## phase=start
      ##DDS-DEVICE-ENROLL## phase=node-started
      ##DDS-DEVICE-ENROLL## phase=device-enrolled urn=<urn>
      ##DDS-DEVICE-ENROLL## phase=appsettings-stamped
      ##DDS-DEVICE-ENROLL## phase=services-started
      ##DDS-DEVICE-ENROLL## phase=done
#>
[CmdletBinding()]
param(
    [string]$OrgUnit     = "",
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
    if ($OrgUnit) { $argList += @("-OrgUnit", "`"$OrgUnit`"") }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

# ── Paths ─────────────────────────────────────────────────────────
$NodeBin     = Join-Path $InstallRoot "bin\dds-node.exe"
$ConfigDir   = Join-Path $InstallRoot "config"
$NodeToml    = Join-Path $ConfigDir   "node.toml"
$AppSettings = Join-Path $ConfigDir   "appsettings.json"

if (-not (Test-Path $NodeBin))    { throw "dds-node.exe not found at $NodeBin." }
if (-not (Test-Path $NodeToml))   { throw "node.toml not found at $NodeToml. Run 'dds-node provision <bundle>' first." }
if (-not (Test-Path $AppSettings)) { throw "appsettings.json not found at $AppSettings (MSI install incomplete?)." }

# Recover OrgUnit from node.toml when not supplied.
if ([string]::IsNullOrWhiteSpace($OrgUnit)) {
    $tomlText = Get-Content $NodeToml -Raw
    if ($tomlText -match '(?m)^\s*org_hash\s*=\s*"([^"]+)"') {
        $OrgUnit = $Matches[1]
    } else {
        throw "Cannot read org_hash from $NodeToml — pass -OrgUnit explicitly."
    }
}

Write-Host "##DDS-DEVICE-ENROLL## phase=start"

# ── 6. start DdsNode + wait for pipe ──────────────────────────────
foreach ($svc in @('DdsNode','DdsAuthBridge','DdsPolicyAgent')) {
    if (-not (Get-Service -Name $svc -ErrorAction SilentlyContinue)) {
        throw "Service '$svc' is not registered. Reinstall the DDS MSI."
    }
}

Write-Host ""
Write-Host "[1/4] Starting DdsNode service..." -ForegroundColor Green
Start-Service -Name DdsNode

$pipePath = "\\.\pipe\dds-api"
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    if (Test-Path $pipePath) { $ready = $true; break }
    Start-Sleep -Milliseconds 500
}
if (-not $ready) { throw "DdsNode pipe $pipePath did not appear within 15s" }
Write-Host "  Pipe ready: $pipePath"
Write-Host "##DDS-DEVICE-ENROLL## phase=node-started"

# ── 7. enroll device ──────────────────────────────────────────────
function Invoke-DdsNodePipe {
    param(
        [string]$Method,
        [string]$Path,
        [string]$Body = ""
    )
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'dds-api',
        [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $client.Connect(5000)
        $bodyBytes = [Text.Encoding]::UTF8.GetBytes($Body)
        $req = "$Method $Path HTTP/1.1`r`nHost: localhost`r`nUser-Agent: Enroll-DdsDevice/1.0`r`nConnection: close`r`n"
        if ($Body) {
            $req += "Content-Type: application/json`r`nContent-Length: $($bodyBytes.Length)`r`n"
        }
        $req += "`r`n"
        $reqBytes = [Text.Encoding]::UTF8.GetBytes($req)
        $client.Write($reqBytes, 0, $reqBytes.Length)
        if ($Body) { $client.Write($bodyBytes, 0, $bodyBytes.Length) }
        $client.Flush()

        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 8192
        while (($n = $client.Read($buf, 0, $buf.Length)) -gt 0) {
            $ms.Write($buf, 0, $n)
        }
        $raw = [Text.Encoding]::UTF8.GetString($ms.ToArray())
        $sep = $raw.IndexOf("`r`n`r`n")
        $head = $raw.Substring(0, $sep)
        $payload = $raw.Substring($sep + 4)
        $statusLine = ($head -split "`r`n")[0]
        if ($statusLine -notmatch '\s2\d\d\s') {
            throw "API $Method $Path failed: $statusLine`n$payload"
        }
        return $payload
    } finally {
        $client.Dispose()
    }
}

Write-Host ""
Write-Host "[2/4] Enrolling this device via /v1/enroll/device..." -ForegroundColor Green
$hostName  = $env:COMPUTERNAME
$deviceId  = "DDS-WIN-$($hostName.ToUpper())"
$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
$enrollBody = @{
    label       = $hostName
    device_id   = $deviceId
    hostname    = $hostName
    os          = "Windows"
    os_version  = $osVersion
    tpm_ek_hash = $null
    org_unit    = $OrgUnit
    tags        = @("joined-node")
} | ConvertTo-Json -Compress
$enrollResp = Invoke-DdsNodePipe -Method POST -Path "/v1/enroll/device" -Body $enrollBody
$deviceUrn = ($enrollResp | ConvertFrom-Json).urn
if (-not $deviceUrn) { throw "Failed to extract urn from /v1/enroll/device response: $enrollResp" }
Write-Host "  device_urn: $deviceUrn"

$nodeInfo = Invoke-DdsNodePipe -Method GET -Path "/v1/node/info"
$nodePubkeyB64 = ($nodeInfo | ConvertFrom-Json).node_pubkey_b64
if (-not $nodePubkeyB64) { throw "Failed to extract node_pubkey_b64 from /v1/node/info response: $nodeInfo" }
Write-Host "##DDS-DEVICE-ENROLL## phase=device-enrolled urn=$deviceUrn"

# ── 8. stamp appsettings.json + AuthBridge registry value ─────────
Write-Host ""
Write-Host "[3/4] Stamping appsettings.json with DeviceUrn + PinnedNodePubkeyB64..." -ForegroundColor Green
$cfg = Get-Content $AppSettings -Raw | ConvertFrom-Json
if (-not $cfg.PSObject.Properties.Match('DdsPolicyAgent').Count) {
    $cfg | Add-Member -NotePropertyName DdsPolicyAgent -NotePropertyValue (New-Object PSObject)
}
$cfg.DdsPolicyAgent | Add-Member -NotePropertyName DeviceUrn -NotePropertyValue $deviceUrn -Force
$cfg.DdsPolicyAgent | Add-Member -NotePropertyName PinnedNodePubkeyB64 -NotePropertyValue $nodePubkeyB64 -Force
# BOM-less UTF-8 — see Bootstrap-DdsDomain.ps1 step 8 for rationale.
$json = $cfg | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText($AppSettings, $json, (New-Object Text.UTF8Encoding $false))
Write-Host "  Updated: $AppSettings"

$bridgeKey = 'HKLM:\SOFTWARE\DDS\AuthBridge'
if (Test-Path $bridgeKey) {
    Set-ItemProperty -Path $bridgeKey -Name DeviceUrn -Value $deviceUrn -Type String
    Write-Host "  Updated: HKLM\SOFTWARE\DDS\AuthBridge\DeviceUrn = $deviceUrn"
} else {
    Write-Host "  WARN: $bridgeKey missing — Auth Bridge config not updated. Reinstall the MSI." -ForegroundColor Yellow
}
Write-Host "##DDS-DEVICE-ENROLL## phase=appsettings-stamped"

# ── 9. start DdsAuthBridge + DdsPolicyAgent ───────────────────────
Write-Host ""
Write-Host "[4/4] Starting DdsAuthBridge and DdsPolicyAgent..." -ForegroundColor Green
Start-Service -Name DdsAuthBridge
Start-Service -Name DdsPolicyAgent
Write-Host "##DDS-DEVICE-ENROLL## phase=services-started"

# ── Bootstrap.env-style summary so siblings tooling stays consistent ──
@"
DEVICE_URN=$deviceUrn
NODE_PUBKEY_B64=$nodePubkeyB64
ORG_HASH=$OrgUnit
"@ | Set-Content -Path (Join-Path $DataRoot "join.env") -Encoding UTF8

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Device enrollment complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Device URN: $deviceUrn"
Write-Host "##DDS-DEVICE-ENROLL## phase=done"
