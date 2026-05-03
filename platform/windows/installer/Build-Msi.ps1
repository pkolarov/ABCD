# #Requires -Version 7.0  -- relaxed: script uses only 5.1-compatible features
<#
.SYNOPSIS
    Builds DDS Windows MSI installers for x64 and/or ARM64 platforms.

.DESCRIPTION
    Orchestrates the full build pipeline:
      1. Rust binaries (dds-node) via cargo
      2. C++ native components via MSBuild (DdsNative.sln)
      3. .NET Policy Agent via dotnet publish
      4. WiX v5 MSI packaging

    Produces per-platform MSI files in the output directory.

.PARAMETER Platform
    Target platform(s): "x64", "arm64", or "both" (default: "both").

.PARAMETER Configuration
    Build configuration: "Release" or "Debug" (default: "Release").

.PARAMETER OutputDir
    Directory for final MSI files (default: .\out).

.PARAMETER Version
    MSI product version in Major.Minor.Patch.Build format. When omitted, the
    last component is auto-bumped from a counter persisted at
    target\.msi_build_counter so each build produces a strictly-greater
    version that MajorUpgrade will accept (msiexec /i works without
    REINSTALL=ALL gymnastics). Pass an explicit -Version to override.

.PARAMETER SkipRust
    Skip the Rust build step (use pre-built binaries).

.PARAMETER SkipNative
    Skip the C++ native build step.

.PARAMETER SkipDotnet
    Skip the .NET build step.

.EXAMPLE
    .\Build-Msi.ps1 -Platform both
    .\Build-Msi.ps1 -Platform x64 -Configuration Debug
    .\Build-Msi.ps1 -Platform arm64 -Version "1.2.0.0"
#>
[CmdletBinding()]
param(
    [ValidateSet("x64", "arm64", "both")]
    [string]$Platform = "both",

    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",

    [string]$OutputDir = "",

    [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
    [string]$Version = "1.0.0.0",

    [switch]$SkipRust,
    [switch]$SkipNative,
    [switch]$SkipDotnet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrEmpty($OutputDir)) { $OutputDir = Join-Path $PSScriptRoot "out" }

# ── Paths ──────────────────────────────���───────────────────────────
$RepoRoot      = Resolve-Path (Join-Path $PSScriptRoot "..\..\..")
$InstallerDir  = $PSScriptRoot
$NativeSln     = Join-Path $RepoRoot "platform\windows\native\DdsNative.sln"
$DotnetProj    = Join-Path $RepoRoot "platform\windows\DdsPolicyAgent\DdsPolicyAgent.csproj"
$WxsFile       = Join-Path $InstallerDir "DdsBundle.wxs"
$ConfigDir     = Join-Path $InstallerDir "config"
$StageRoot     = Join-Path $InstallerDir "stage"

# ── Platform mapping ──────────────────────────────────────────────
$PlatformMap = @{
    "x64"   = @{
        RustTarget   = "x86_64-pc-windows-msvc"
        MsbuildPlat  = "x64"
        DotnetRid    = "win-x64"
        WixPlatform  = "x64"
        NativeSuffix = ""           # C++ output: build\Release\
    }
    "arm64" = @{
        RustTarget   = "aarch64-pc-windows-msvc"
        MsbuildPlat  = "ARM64"
        DotnetRid    = "win-arm64"
        WixPlatform  = "arm64"
        NativeSuffix = "-ARM64"     # C++ output: build\Release-ARM64\
    }
}

# ── Resolve which platforms to build ──────────────────────────────
if ($Platform -eq "both") {
    $Targets = @("x64", "arm64")
} else {
    $Targets = @($Platform)
}

# ── Auto-bump build counter when no explicit -Version was supplied ────
# Each invocation persists an incrementing counter at target\.msi_build_counter
# and uses 1.0.0.<counter> as the MSI version. This keeps `msiexec /i` happy
# without REINSTALL=ALL on dev iteration. The counter is uint16-bounded to fit
# the MSI version field (Major.Minor.Build.Revision are each 0..65535).
if (-not $PSBoundParameters.ContainsKey('Version')) {
    $counterFile = Join-Path $RepoRoot "target\.msi_build_counter"
    $counter = 0
    if (Test-Path $counterFile) {
        $raw = (Get-Content $counterFile -Raw -ErrorAction SilentlyContinue)
        if ($null -ne $raw -and $raw.Trim() -match '^\d+$') {
            $counter = [int]$raw.Trim()
        }
    }
    $counter++
    if ($counter -gt 65535) {
        Write-Warning "Build counter exceeded 65535 -- wrapping to 1. Bump Major/Minor in Build-Msi.ps1 if you need to keep going."
        $counter = 1
    }
    New-Item -ItemType Directory -Path (Split-Path $counterFile) -Force | Out-Null
    Set-Content -Path $counterFile -Value $counter -Encoding ASCII -NoNewline
    $Version = "1.0.0.$counter"
}

# ── Prerequisite checks ──────────────────────────────────────────
function Assert-Command($cmd, $hint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        throw "'$cmd' not found on PATH. $hint"
    }
}

Write-Host "`n=== DDS MSI Build ===" -ForegroundColor Cyan
Write-Host "  Platforms:     $($Targets -join ', ')"
Write-Host "  Configuration: $Configuration"
Write-Host "  Version:       $Version"
Write-Host "  Output:        $OutputDir"
Write-Host ""

if (-not $SkipRust)   { Assert-Command "cargo"   "Install Rust: https://rustup.rs" }
if (-not $SkipNative) { Assert-Command "msbuild" "Run from a Visual Studio Developer Command Prompt" }
if (-not $SkipDotnet) { Assert-Command "dotnet"  "Install .NET SDK: https://dot.net" }
Assert-Command "wix" "Install WiX: dotnet tool install --global wix --version 5.0.2"

# Ensure output and config directories exist
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
if (-not (Test-Path $ConfigDir)) {
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

# Create default node.toml if it doesn't exist
$NodeToml = Join-Path $ConfigDir "node.toml"
if (-not (Test-Path $NodeToml)) {
    Write-Host "  Creating default node.toml config template..." -ForegroundColor Yellow
    @"
# DDS Node Configuration
# Edit this file after installation: C:\Program Files\DDS\config\node.toml

# Data directory for vault, certificates, and replication state
data_dir = 'C:\ProgramData\DDS'

[network]
# HTTP API listen address (used by Auth Bridge and Policy Agent).
# A-2 (security review): default to the named-pipe transport so the
# admin gate sees a verified caller SID.
api_addr = 'pipe:dds-api'

# P2P listen addresses (multiaddr format)
# listen = ['/ip4/0.0.0.0/tcp/4001', '/ip4/0.0.0.0/udp/4001/quic-v1']

[network.api_auth]
# A-2: refuse loopback-TCP admin callers; safe because api_addr ships as a
# named pipe and the LocalSystem services match the built-in S-1-5-18 allowlist.
trust_loopback_tcp_admin = false

# Trusted root identities (URNs of domain founders)
# trusted_roots = []

# Bootstrap peers for initial mesh join
# bootstrap_peers = []
"@ | Set-Content -Path $NodeToml -Encoding UTF8
}

# ── Build functions ───────────────────────────────────────────────

function Build-Rust([string]$target, [string]$stageDir) {
    Write-Host "`n--- [Rust] Building dds-node for $target ---" -ForegroundColor Green

    # Ensure the target is installed (avoid 2>&1 — PS 5.1 turns native stderr into terminating ErrorRecords)
    & rustup target add $target | Out-Null

    # MSI ships the bootstrap wizard + Bootstrap-DdsDomain.ps1, both of
    # which call `dds-node init-domain --fido2`. The fido2 cargo feature
    # is opt-in (gates the ctap-hid-fido2 dep), so it must be explicitly
    # enabled here or the binary refuses --fido2 with
    # "Error: --fido2 requires dds-node built with --features fido2".
    $cargoArgs = @("build", "--package", "dds-node", "--target", $target, "--features", "fido2")
    if ($Configuration -eq "Release") { $cargoArgs += "--release" }

    Push-Location $RepoRoot
    try {
        & cargo @cargoArgs
        if ($LASTEXITCODE -ne 0) { throw "Cargo build failed for target $target" }
    } finally {
        Pop-Location
    }

    # Copy binary to stage
    $profile = if ($Configuration -eq "Release") { "release" } else { "debug" }
    $src = Join-Path $RepoRoot "target\$target\$profile\dds-node.exe"
    Copy-Item $src -Destination $stageDir -Force
    Write-Host "  -> Staged: $stageDir\dds-node.exe"
}

function Build-Native([string]$msbuildPlatform, [string]$stageDir, [string]$nativeSuffix) {
    Write-Host "`n--- [C++] Building native components for $msbuildPlatform ---" -ForegroundColor Green

    & msbuild $NativeSln `
        /p:Configuration=$Configuration `
        /p:Platform=$msbuildPlatform `
        /m `
        /verbosity:minimal
    if ($LASTEXITCODE -ne 0) { throw "MSBuild failed for platform $msbuildPlatform" }

    # Copy outputs to stage
    $nativeBuildDir = Join-Path $RepoRoot "platform\windows\native\build\$Configuration$nativeSuffix"

    $nativeBinaries = @(
        "DdsAuthBridge.exe",
        "DdsCredentialProvider.dll",
        "DdsTrayAgent.exe"
    )
    foreach ($bin in $nativeBinaries) {
        $src = Join-Path $nativeBuildDir $bin
        if (Test-Path $src) {
            Copy-Item $src -Destination $stageDir -Force
            Write-Host "  -> Staged: $stageDir\$bin"
        } else {
            Write-Warning "  Native binary not found: $src"
        }
    }
}

function Build-Dotnet([string]$rid, [string]$stageDir) {
    Write-Host "`n--- [.NET] Building DdsPolicyAgent for $rid ---" -ForegroundColor Green

    $dotnetConfig = if ($Configuration -eq "Release") { "Release" } else { "Debug" }

    & dotnet publish $DotnetProj `
        --configuration $dotnetConfig `
        --runtime $rid `
        --self-contained true `
        --framework net9.0 `
        --output (Join-Path $StageRoot "dotnet-$rid") `
        /p:PublishSingleFile=true `
        /p:IncludeNativeLibrariesForSelfExtract=true
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for RID $rid" }

    # Copy the single-file executable to stage
    $src = Join-Path (Join-Path $StageRoot "dotnet-$rid") "DdsPolicyAgent.exe"
    if (Test-Path $src) {
        Copy-Item $src -Destination $stageDir -Force
        Write-Host "  -> Staged: $stageDir\DdsPolicyAgent.exe"
    } else {
        throw "DdsPolicyAgent.exe not found after publish: $src"
    }
}

function Build-Msi([string]$platformKey, [string]$stageDir) {
    $info = $PlatformMap[$platformKey]
    $wixPlatform = $info.WixPlatform
    $msiName = "DDS-$Version-$platformKey.msi"
    $msiPath = Join-Path $OutputDir $msiName

    Write-Host "`n--- [WiX] Packaging MSI: $msiName ---" -ForegroundColor Green

    & wix build $WxsFile `
        -o $msiPath `
        -d BuildDir="$stageDir" `
        -d ConfigDir="$ConfigDir" `
        -d Platform="$wixPlatform" `
        -d Version="$Version" `
        -arch $wixPlatform
    if ($LASTEXITCODE -ne 0) { throw "WiX build failed for $platformKey" }

    Write-Host "  -> MSI: $msiPath" -ForegroundColor Cyan
    return $msiPath
}

# ── Main build loop ──────────────────────────────────────────────
$results = @()

foreach ($plat in $Targets) {
    $info = $PlatformMap[$plat]
    $stageDir = Join-Path $StageRoot $plat

    # Clean and create stage directory
    if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force }
    New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

    Write-Host "`n======================================" -ForegroundColor Cyan
    Write-Host " Building for: $plat" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan

    # Step 1: Rust
    if (-not $SkipRust) {
        Build-Rust -target $info.RustTarget -stageDir $stageDir
    }

    # Step 2: C++ native
    if (-not $SkipNative) {
        Build-Native -msbuildPlatform $info.MsbuildPlat -stageDir $stageDir -nativeSuffix $info.NativeSuffix
    }

    # Step 3: .NET
    if (-not $SkipDotnet) {
        Build-Dotnet -rid $info.DotnetRid -stageDir $stageDir
    }

    # Step 3.5: copy installer-side scripts into stage so WiX can reference them
    $scriptDir = Join-Path $InstallerDir "scripts"
    if (Test-Path $scriptDir) {
        foreach ($ps1 in Get-ChildItem -Path $scriptDir -Filter '*.ps1') {
            Copy-Item $ps1.FullName -Destination $stageDir -Force
            Write-Host "  -> Staged: $stageDir\$($ps1.Name)"
        }
    } else {
        Write-Warning "  Installer scripts dir not found: $scriptDir"
    }

    # Step 4: WiX MSI
    $msi = Build-Msi -platformKey $plat -stageDir $stageDir
    $results += @{ Platform = $plat; MSI = $msi }
}

# ── Summary ──���───────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Build Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
foreach ($r in $results) {
    $size = if (Test-Path $r.MSI) {
        $len = (Get-Item $r.MSI).Length
        "{0:N1} MB" -f ($len / 1MB)
    } else { "N/A" }
    Write-Host "  $($r.Platform): $($r.MSI)  ($size)"
}
Write-Host ""
Write-Host "Install with: msiexec /i <path-to-msi> /qb" -ForegroundColor Yellow
Write-Host ""
