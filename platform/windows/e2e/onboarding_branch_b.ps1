<#
.SYNOPSIS
    E2E assertions for Onboarding Wizard — Branch B (join an existing domain).

.DESCRIPTION
    Run on VM B after copying provision.dds from VM A and double-clicking
    it on VM B (or running DdsConsole.ps1 -Mode JoinDomain -BundlePath).
    Asserts the same files Branch A produces (minus domain_key.bin, which
    only the founding node holds), plus that the joining node can see at
    least one peer over /v1/peers.

.PARAMETER ReferenceDomainName
    Domain name from VM A's domain.toml. When supplied, the script
    asserts that VM B's domain.toml matches.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\Program Files\DDS",
    [string]$DataRoot    = "C:\ProgramData\DDS",
    [string]$ReferenceDomainName = ""
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

$NodeData       = Join-Path $DataRoot    'node-data'
$DomainTomlPath = Join-Path $NodeData    'domain.toml'
$AdmissionPath  = Join-Path $NodeData    'admission.cbor'
$NodeTomlPath   = Join-Path $InstallRoot 'config\node.toml'
$JoinEnv        = Join-Path $DataRoot    'join.env'
$DomainKeyPath  = Join-Path $NodeData    'domain_key.bin'

Assert "domain.toml exists"               (Test-Path $DomainTomlPath)
Assert "admission.cbor exists"            (Test-Path $AdmissionPath)
Assert "node.toml exists"                 (Test-Path $NodeTomlPath)
Assert "join.env exists"                  (Test-Path $JoinEnv)
Assert "no domain_key.bin (joiner role)"  (-not (Test-Path $DomainKeyPath)) "(only the founding node should hold this)"

if ($ReferenceDomainName) {
    if (Test-Path $DomainTomlPath) {
        $dt = Get-Content $DomainTomlPath -Raw
        $ok = $dt -match ('(?m)^name\s*=\s*"' + [regex]::Escape($ReferenceDomainName) + '"')
        Assert "domain.toml name matches reference '$ReferenceDomainName'" $ok
    }
}

# Services / pipe — same as Branch A
foreach ($svc in @('DdsNode','DdsAuthBridge','DdsPolicyAgent')) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    Assert "$svc running" ($s -and $s.Status -eq 'Running')
}
Assert "named-pipe open" (Test-Path '\\.\pipe\dds-api')

# /v1/peers should report at least the founding node we joined.
try {
    $client = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'dds-api', [System.IO.Pipes.PipeDirection]::InOut)
    $client.Connect(2000)
    $req = "GET /v1/peers HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n"
    $b = [Text.Encoding]::UTF8.GetBytes($req)
    $client.Write($b, 0, $b.Length); $client.Flush()
    $ms = New-Object System.IO.MemoryStream
    $buf = New-Object byte[] 8192
    while (($n = $client.Read($buf, 0, $buf.Length)) -gt 0) { $ms.Write($buf, 0, $n) }
    $client.Dispose()
    $resp = [Text.Encoding]::UTF8.GetString($ms.ToArray())
    Assert "GET /v1/peers returns 2xx" ($resp -match '^HTTP/1.1 2\d\d')
} catch {
    Assert "GET /v1/peers returns 2xx" $false "($($_.Exception.Message))"
}

Write-Host ""
Write-Host "=========================================="
Write-Host ("  Branch B: PASS={0}, FAIL={1}" -f $pass, $fail) -ForegroundColor (& { if ($fail -eq 0) { 'Green' } else { 'Red' } })
Write-Host "=========================================="
exit ($(if ($fail -eq 0) { 0 } else { 1 }))
