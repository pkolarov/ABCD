<#
.SYNOPSIS
    Bootstrap a brand-new DDS domain on this Windows host.

.DESCRIPTION
    Windows analog of platform/macos/packaging/dds-bootstrap-domain.sh.
    Run after installing the DDS MSI. The MSI installs all binaries and
    registers services in the stopped state; this script:

      1. Creates the domain (init-domain --fido2 — touch your FIDO2 key)
      2. Generates this node's libp2p identity (gen-node-key)
      3. Self-admits this node into the domain (admit)
      4. Generates the provision bundle for sibling nodes
      5. Writes a real node.toml with org_hash + domain section
      6. Starts the DdsNode service and waits for the API
      7. Calls /v1/enroll/device to register this machine
      8. Stamps DeviceUrn + PinnedNodePubkeyB64 into appsettings.json
      9. Starts DdsAuthBridge and DdsPolicyAgent

    Self-elevates via UAC if not already running as Administrator.

.PARAMETER Name
    Domain name (e.g. acme.corp). Prompted if not supplied.

.PARAMETER OrgHash
    Short organization hash for gossip topic partitioning (e.g. acme).
    Prompted if not supplied.

.PARAMETER NoFido2
    Protect the domain key with a passphrase instead of a FIDO2 hardware
    key. The default is FIDO2.

.PARAMETER InstallRoot
    DDS install dir. Defaults to "C:\Program Files\DDS".

.PARAMETER DataRoot
    DDS data dir. Defaults to "C:\ProgramData\DDS".

.EXAMPLE
    .\Bootstrap-DdsDomain.ps1 -Name acme.corp -OrgHash acme

    Single-prompt flow: type the FIDO2 PIN if your key requires one,
    then touch the key when prompted.
#>
[CmdletBinding()]
param(
    [string]$Name     = "",
    [string]$OrgHash  = "",
    [switch]$NoFido2,
    [switch]$Force,
    [string]$InstallRoot = "C:\Program Files\DDS",
    [string]$DataRoot    = "C:\ProgramData\DDS"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Self-elevate ─────────────────────────────────────────────────
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($Name)    { $argList += @("-Name", "`"$Name`"") }
    if ($OrgHash) { $argList += @("-OrgHash", "`"$OrgHash`"") }
    if ($NoFido2) { $argList += "-NoFido2" }
    if ($Force)   { $argList += "-Force" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

# ── Paths ──────────────────────────────────────────────────────────
$NodeBin    = Join-Path $InstallRoot "bin\dds-node.exe"
$ConfigDir  = Join-Path $InstallRoot "config"
$NodeToml   = Join-Path $ConfigDir   "node.toml"
$AppSettings = Join-Path $ConfigDir  "appsettings.json"
$NodeData   = Join-Path $DataRoot    "node-data"
$ProvisionBundle = Join-Path $DataRoot "provision.dds"

# Transcript log so even an instant-close window leaves an inspectable record.
$logPath = Join-Path $env:TEMP ("dds-bootstrap-{0:yyyyMMdd-HHmmss}.log" -f (Get-Date))
try { Start-Transcript -Path $logPath -Force | Out-Null } catch { }

# Always pause before exiting (success or failure), so a Start-menu-launched
# PowerShell window stays open long enough for the operator to read the result.
trap {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host "  Bootstrap FAILED" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.InvocationInfo) {
        Write-Host "  at $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor DarkGray
        Write-Host "  $($_.InvocationInfo.Line.Trim())" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host "Full transcript: $logPath" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to close"
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

Write-Host ""
Write-Host "=== DDS Domain Bootstrap ===" -ForegroundColor Cyan
Write-Host "(transcript: $logPath)"
Write-Host ""

# ── Preflight ──────────────────────────────────────────────────────
if (-not (Test-Path $NodeBin)) {
    Write-Error "dds-node.exe not found at $NodeBin. Install the DDS MSI first."
    exit 1
}

# ── Check service registration first ──────────────────────────────
foreach ($svc in @("DdsNode","DdsAuthBridge","DdsPolicyAgent")) {
    if (-not (Get-Service -Name $svc -ErrorAction SilentlyContinue)) {
        Write-Error "Service '$svc' is not registered. Reinstall the DDS MSI."
        exit 1
    }
}

# ── Detect existing bootstrap state ──────────────────────────────
$existing = @()
if (Test-Path (Join-Path $NodeData "domain.toml"))      { $existing += "node-data\domain.toml" }
if (Test-Path (Join-Path $NodeData "domain_key.bin"))   { $existing += "node-data\domain_key.bin (FIDO2-bound)" }
if (Test-Path (Join-Path $NodeData "p2p_key.bin"))      { $existing += "node-data\p2p_key.bin" }
if (Test-Path (Join-Path $NodeData "admission.cbor"))   { $existing += "node-data\admission.cbor" }
if (Test-Path (Join-Path $DataRoot "node_key.bin"))     { $existing += "node_key.bin (Vouchsafe identity)" }
if (Test-Path $NodeToml)                                { $existing += "config\node.toml" }

if ($existing.Count -gt 0) {
    Write-Host ""
    Write-Host "Existing DDS state detected:" -ForegroundColor Yellow
    foreach ($f in $existing) { Write-Host "  - $f" }
    Write-Host ""
    Write-Host "Bootstrapping a new domain will WIPE all of the above." -ForegroundColor Yellow
    Write-Host "  - You'll need to touch your FIDO2 key again."
    Write-Host "  - Any previously-enrolled users in this domain will be unreachable."
    Write-Host "  - The provision bundle for sibling nodes will be regenerated (old bundles invalid)."
    Write-Host ""
    if ($Force) {
        Write-Host "  -Force given, wiping without confirmation." -ForegroundColor Yellow
    } else {
        $resp = Read-Host "Wipe and re-bootstrap? Type 'WIPE' to confirm, anything else to cancel"
        if ($resp -ne 'WIPE') {
            Write-Host "Aborted. Existing state preserved." -ForegroundColor Cyan
            Read-Host "Press Enter to exit"
            exit 0
        }
    }

    Write-Host ""
    Write-Host "Stopping services and removing existing state..." -ForegroundColor Yellow
    foreach ($svc in @("DdsPolicyAgent","DdsAuthBridge","DdsNode")) {
        $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($s -and $s.Status -ne 'Stopped') {
            Write-Host "  Stopping $svc..."
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        }
    }
    if (Test-Path $NodeData) { Remove-Item -Recurse -Force $NodeData }
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $DataRoot "node_key.bin")
    Remove-Item -Force -ErrorAction SilentlyContinue $NodeToml
    Write-Host "  Wiped." -ForegroundColor Green
}

# ── Stop services if running (clean state for first-time bootstrap) ──
foreach ($svc in @("DdsPolicyAgent","DdsAuthBridge","DdsNode")) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Stopped') {
        Write-Host "Stopping $svc (currently $($s.Status))..." -ForegroundColor Yellow
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    }
}

# ── Collect inputs ─────────────────────────────────────────────────
if (-not $Name)    { $Name    = Read-Host "Domain name (e.g. acme.corp)" }
if (-not $OrgHash) { $OrgHash = Read-Host "Organization hash (short ID, e.g. acme)" }
if (-not $Name)    { Write-Error "Domain name is required."; exit 1 }
if (-not $OrgHash) { Write-Error "Organization hash is required."; exit 1 }

$useFido2 = -not $NoFido2
$fido2Args = @()
if ($useFido2) {
    $fido2Args = @("--fido2")
    Write-Host "  Domain key will be protected by your FIDO2 hardware key."
    Write-Host "  You will need to touch the key during creation."
} else {
    $passphrase = Read-Host "Domain key passphrase" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($passphrase)
    $env:DDS_DOMAIN_PASSPHRASE = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

# ── 1. init-domain ─────────────────────────────────────────────────
Write-Host ""
Write-Host "[1/9] Creating domain '$Name'..." -ForegroundColor Green
New-Item -ItemType Directory -Force -Path $NodeData | Out-Null
& $NodeBin init-domain --name $Name --dir $NodeData @fido2Args
if ($LASTEXITCODE -ne 0) { throw "init-domain failed" }

# Parse domain.toml for id + pubkey (used to populate node.toml)
$domainToml = Get-Content (Join-Path $NodeData "domain.toml") -Raw
$domainId     = if ($domainToml -match '(?m)^id\s*=\s*"([^"]+)"')     { $Matches[1] } else { $null }
$domainPubkey = if ($domainToml -match '(?m)^pubkey\s*=\s*"([^"]+)"') { $Matches[1] } else { $null }
if (-not $domainId -or -not $domainPubkey) {
    throw "Could not parse domain id/pubkey from $NodeData\domain.toml"
}
Write-Host "  domain_id: $domainId"

# ── 2. provision bundle ────────────────────────────────────────────
Write-Host ""
Write-Host "[2/9] Creating provision bundle for sibling nodes..." -ForegroundColor Green
& $NodeBin create-provision-bundle --dir $NodeData --org $OrgHash --out $ProvisionBundle
if ($LASTEXITCODE -ne 0) { throw "create-provision-bundle failed" }
Write-Host "  Bundle: $ProvisionBundle"

# ── 3. node identity ───────────────────────────────────────────────
Write-Host ""
Write-Host "[3/9] Generating node libp2p identity..." -ForegroundColor Green
$genOut = & $NodeBin gen-node-key --data-dir $NodeData 2>&1
$genOut | Tee-Object -FilePath (Join-Path $NodeData "gen-node-key.out")
$peerId = ($genOut | Select-String -Pattern 'peer_id:\s*(\S+)' | Select-Object -Last 1).Matches.Groups[1].Value
if (-not $peerId) { throw "Failed to determine peer_id from gen-node-key output" }
Write-Host "  peer_id: $peerId"

# ── 4. self-admit ──────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/9] Self-admitting this node..." -ForegroundColor Green
& $NodeBin admit `
    --domain-key (Join-Path $NodeData "domain_key.bin") `
    --domain     (Join-Path $NodeData "domain.toml") `
    --peer-id    $peerId `
    --out        (Join-Path $NodeData "admission.cbor") `
    --ttl-days   3650
if ($LASTEXITCODE -ne 0) { throw "admit failed" }

# ── 5. node.toml ───────────────────────────────────────────────────
Write-Host ""
Write-Host "[5/9] Writing node configuration..." -ForegroundColor Green
$tomlContent = @"
# DDS Node Configuration — generated by Bootstrap-DdsDomain.ps1
data_dir = '$NodeData'
org_hash = "$OrgHash"
trusted_roots = []

[network]
listen_addr = "/ip4/0.0.0.0/tcp/4001"
bootstrap_peers = []
mdns_enabled = true
heartbeat_secs = 5
idle_timeout_secs = 60
# A-2: named-pipe transport so /v1/* admin endpoints see a real CallerIdentity.
api_addr = "pipe:dds-api"

[network.api_auth]
# A-2: refuse anonymous loopback-TCP fallback to admin endpoints.
trust_loopback_tcp_admin = false
node_hmac_secret_path = '$DataRoot\node-hmac.key'

[domain]
name = "$Name"
id = "$domainId"
pubkey = "$domainPubkey"
admission_path = '$NodeData\admission.cbor'
audit_log_enabled = false
"@
$tomlContent | Set-Content -Path $NodeToml -Encoding UTF8
Write-Host "  Written: $NodeToml"

# ── 6. start dds-node + wait for pipe ──────────────────────────────
Write-Host ""
Write-Host "[6/9] Starting DdsNode service..." -ForegroundColor Green
Start-Service -Name DdsNode

$pipePath = "\\.\pipe\dds-api"
$ready = $false
for ($i = 0; $i -lt 30; $i++) {
    if (Test-Path $pipePath) { $ready = $true; break }
    Start-Sleep -Milliseconds 500
}
if (-not $ready) { throw "DdsNode pipe $pipePath did not appear within 15s" }
Write-Host "  Pipe ready: $pipePath"

# ── 7. enroll device + read node pubkey via named-pipe HTTP ────────
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
        $req = "$Method $Path HTTP/1.1`r`nHost: localhost`r`nUser-Agent: Bootstrap-DdsDomain/1.0`r`nConnection: close`r`n"
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
Write-Host "[7/9] Enrolling this device via /v1/enroll/device..." -ForegroundColor Green
$hostName = $env:COMPUTERNAME
$deviceId = "DDS-WIN-$($hostName.ToUpper())"
$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
$enrollBody = @{
    label       = $hostName
    device_id   = $deviceId
    hostname    = $hostName
    os          = "Windows"
    os_version  = $osVersion
    tpm_ek_hash = $null
    org_unit    = $OrgHash
    tags        = @("bootstrap-node")
} | ConvertTo-Json -Compress
$enrollResp = Invoke-DdsNodePipe -Method POST -Path "/v1/enroll/device" -Body $enrollBody
$deviceUrn = ($enrollResp | ConvertFrom-Json).urn
if (-not $deviceUrn) { throw "Failed to extract urn from /v1/enroll/device response: $enrollResp" }
Write-Host "  device_urn: $deviceUrn"

$nodeInfo = Invoke-DdsNodePipe -Method GET -Path "/v1/node/info"
$nodePubkeyB64 = ($nodeInfo | ConvertFrom-Json).node_pubkey_b64
if (-not $nodePubkeyB64) { throw "Failed to extract node_pubkey_b64 from /v1/node/info response: $nodeInfo" }

# ── 8. stamp appsettings.json ──────────────────────────────────────
Write-Host ""
Write-Host "[8/9] Stamping appsettings.json with DeviceUrn + PinnedNodePubkeyB64..." -ForegroundColor Green
if (-not (Test-Path $AppSettings)) {
    throw "appsettings.json not found at $AppSettings (MSI install incomplete?)"
}
$cfg = Get-Content $AppSettings -Raw | ConvertFrom-Json
if (-not $cfg.PSObject.Properties.Match('DdsPolicyAgent').Count) {
    $cfg | Add-Member -NotePropertyName DdsPolicyAgent -NotePropertyValue (New-Object PSObject)
}
$cfg.DdsPolicyAgent | Add-Member -NotePropertyName DeviceUrn -NotePropertyValue $deviceUrn -Force
$cfg.DdsPolicyAgent | Add-Member -NotePropertyName PinnedNodePubkeyB64 -NotePropertyValue $nodePubkeyB64 -Force
$cfg | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettings -Encoding UTF8
Write-Host "  Updated: $AppSettings"

# ── 9. start auth bridge + policy agent ────────────────────────────
Write-Host ""
Write-Host "[9/9] Starting DdsAuthBridge and DdsPolicyAgent..." -ForegroundColor Green
Start-Service -Name DdsAuthBridge
Start-Service -Name DdsPolicyAgent

# ── Bootstrap.env ──────────────────────────────────────────────────
@"
DOMAIN_NAME=$Name
DOMAIN_ID=$domainId
DOMAIN_PUBKEY=$domainPubkey
ORG_HASH=$OrgHash
DEVICE_URN=$deviceUrn
PEER_ID=$peerId
"@ | Set-Content -Path (Join-Path $DataRoot "bootstrap.env") -Encoding UTF8

# ── Summary ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  DDS Domain Bootstrap Complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Domain:     $Name"
Write-Host "  Domain ID:  $domainId"
Write-Host "  Device URN: $deviceUrn"
Write-Host "  Peer ID:    $peerId"
Write-Host ""
Write-Host "  Domain key: $NodeData\domain_key.bin (KEEP SAFE)"
Write-Host "  Config:     $NodeToml"
Write-Host ""
Write-Host "  Provision bundle: $ProvisionBundle"
Write-Host "  (Copy to a USB stick to add a sibling node.)"
Write-Host ""
Write-Host "  Service status:"
Get-Service Dds* | Format-Table Name, Status, StartType -AutoSize | Out-String | Write-Host
Write-Host "  Next: launch DDS Tray Agent from Start menu to enroll users."
Write-Host ""
try { Stop-Transcript | Out-Null } catch { }
Read-Host "Press Enter to close"
