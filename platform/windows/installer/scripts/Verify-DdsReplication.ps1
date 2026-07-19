<#
.SYNOPSIS
  Verify a DDS node is healthy and (optionally) that a change replicates to a
  connected peer. Safe to run on a live installed node (talks to the dds-api
  named pipe). Non-mutating by default; add -EnrollTest to mint a throwaway
  test device and confirm it replicates to a peer.

.DESCRIPTION
  Run this on BOTH boxes after upgrading to v1.5.7.4 to confirm the enc-v3
  epoch-key fix took effect:
    1. Status          - token count, connected peers.
    2. KEM self-repair - admission.cbor now carries a pq_kem_pubkey.
    3. Log evidence    - self-repair / reconcile / no err_count loop.
  Then, on ONE box, run with -EnrollTest to prove replication end to end.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File Verify-DdsReplication.ps1

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File Verify-DdsReplication.ps1 -EnrollTest
#>
[CmdletBinding()]
param(
    [string]$DataRoot = 'C:\ProgramData\DDS',
    [string]$Pipe     = 'dds-api',
    [switch]$EnrollTest
)

$ErrorActionPreference = 'Stop'
$NodeData      = Join-Path $DataRoot 'node-data'
$AdmissionCert = Join-Path $NodeData 'admission.cbor'

function Invoke-PipeHttp {
    param([string]$Method = 'GET', [string]$Path = '/v1/status', [string]$Body = $null)
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', $Pipe, [System.IO.Pipes.PipeDirection]::InOut)
    $client.Connect(8000)
    try {
        $bodyBytes = if ($Body) { [Text.Encoding]::UTF8.GetBytes($Body) } else { New-Object byte[] 0 }
        $req = "$Method $Path HTTP/1.0`r`nHost: dds`r`n"
        if ($Body) { $req += "Content-Type: application/json`r`nContent-Length: $($bodyBytes.Length)`r`n" }
        $req += "`r`n"
        $reqBytes = [Text.Encoding]::UTF8.GetBytes($req) + $bodyBytes
        $client.Write($reqBytes, 0, $reqBytes.Length); $client.Flush()
        $ms = New-Object System.IO.MemoryStream
        $buf = New-Object byte[] 65536
        while (($n = $client.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n) }
        $text = [Text.Encoding]::UTF8.GetString($ms.ToArray())
        $idx = $text.IndexOf("`r`n`r`n")
        if ($idx -ge 0) { return $text.Substring($idx + 4) } else { return $text }
    } finally { $client.Dispose() }
}

Write-Host "=== DDS node health ($env:COMPUTERNAME) ===" -ForegroundColor Cyan
if (-not (Test-Path "\\.\pipe\$Pipe")) {
    Write-Host "  dds-api pipe not found - is the DdsNode service running?" -ForegroundColor Red
    exit 1
}
$status = Invoke-PipeHttp -Path '/v1/status' | ConvertFrom-Json
$nodeExe = Join-Path $env:ProgramFiles 'DDS\bin\dds-node.exe'
if (Test-Path $nodeExe) {
    $ver = (Get-Item $nodeExe).VersionInfo.ProductVersion
    Write-Host ("  dds-node.exe   : {0}" -f $ver)
}
Write-Host ("  tokens (graph) : {0}" -f $status.trust_graph_tokens)
Write-Host ("  store tokens   : {0}" -f $status.store_tokens)
Write-Host ("  trusted roots  : {0}" -f $status.trusted_roots)
Write-Host ("  connected peers: {0}" -f $status.connected_peers)

# --- KEM self-repair evidence: admission.cbor should now carry a KEM pubkey ---
Write-Host "`n=== enc-v3 KEM self-repair ===" -ForegroundColor Cyan
if (Test-Path $AdmissionCert) {
    $bytes = [IO.File]::ReadAllBytes($AdmissionCert)
    $ascii = -join ($bytes | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
    if ($ascii -match 'pq_kem_pubkey') {
        Write-Host "  admission.cbor carries pq_kem_pubkey  [OK]" -ForegroundColor Green
    } else {
        Write-Host "  admission.cbor has NO pq_kem_pubkey - self-repair has not run yet." -ForegroundColor Yellow
        Write-Host "  (Restart the DdsNode service once; it attaches the key at startup on hybrid domains.)"
    }
} else {
    Write-Host "  admission.cbor not found at $AdmissionCert (node not joined to a domain?)" -ForegroundColor Yellow
}

# --- Log evidence ---
$log = Get-ChildItem (Join-Path $DataRoot 'logs') -Filter '*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($log) {
    Write-Host "`n=== recent log signals ($($log.Name)) ===" -ForegroundColor Cyan
    $lines = Get-Content $log.FullName -Tail 4000
    $repair  = $lines | Select-String 'pq_kem_pubkey was missing or stale|attached our' | Select-Object -Last 1
    $reconc  = $lines | Select-String 'reconciled stored tokens' | Select-Object -Last 1
    $errloop = $lines | Select-String 'err_count=[1-9]' | Select-Object -Last 3
    if ($repair)  { Write-Host "  self-repair : $($repair.Line.Trim())" -ForegroundColor Green }
    if ($reconc)  { Write-Host "  reconcile   : $($reconc.Line.Trim())" -ForegroundColor Green }
    if ($errloop) { Write-Host "  WARNING err_count>0 still present:"; $errloop | ForEach-Object { Write-Host "    $($_.Line.Trim())" -ForegroundColor Yellow } }
    else          { Write-Host "  no err_count>0 in recent log  [OK]" -ForegroundColor Green }
}

# --- Optional end-to-end replication proof (mints a throwaway device token) ---
if ($EnrollTest) {
    Write-Host "`n=== replication proof (test device enrollment) ===" -ForegroundColor Cyan
    if ($status.connected_peers -lt 1) {
        Write-Host "  No connected peer to confirm against - skip. Run on the box that sees a peer." -ForegroundColor Yellow
        return
    }
    $suffix = (Get-Random -Maximum 0xFFFFFF).ToString('x6')
    $body = '{"label":"repltest-' + $suffix + '","device_id":"repltest-' + $suffix + '","hostname":"' + $env:COMPUTERNAME + '","os":"windows","os_version":"11","tags":["replication-test"]}'
    $enroll = Invoke-PipeHttp -Method 'POST' -Path '/v1/enroll/device' -Body $body | ConvertFrom-Json
    $jti = $enroll.jti
    Write-Host "  minted test token jti=$jti published=$($enroll.published)"
    Write-Host "  waiting 5s for gossip..."
    Start-Sleep -Seconds 5
    $probe = Invoke-PipeHttp -Path "/v1/replication/confirm?jtis=$jti" | ConvertFrom-Json
    Write-Host ("  admitted_connected : {0}" -f $probe.admitted_connected)
    if ($probe.confirmed_jtis -contains $jti) {
        Write-Host "  CONFIRMED replicated to a peer  [OK]" -ForegroundColor Green
    } else {
        $inconclusive = @($probe.results | Where-Object { $_.error })
        if ($inconclusive.Count -gt 0) {
            Write-Host "  INCONCLUSIVE (epoch key still settling): $($inconclusive[0].error)" -ForegroundColor Yellow
            Write-Host "  Re-run in ~30s; the probe triggers the key exchange."
        } else {
            Write-Host "  NOT yet confirmed on any peer." -ForegroundColor Yellow
        }
    }
    Write-Host "  (This test token can be offboarded from the Console; tag=replication-test.)"
}
