<#
.SYNOPSIS
    Probe the DDS install + provisioning state on the local machine.

.DESCRIPTION
    Returns a [pscustomobject] the wizard binds to so the Welcome page can
    pick the right branch. Read-only — no side effects.

    Probed signals:
      - InstallRoot  / DataRoot existence
      - domain.toml  / admission.cbor / node.toml present?
      - DdsNode service registered, status, pipe open?
      - Vault entry for the current user SID (best-effort heuristic)
      - Bootstrap resume marker present?

    Recommended branch:
      'NewDomain'   — no domain.toml present
      'JoinDomain'  — no domain.toml AND a -BundlePath was supplied
      'EnrollUser'  — provisioned, services up, current user has no vault entry
      'Health'      — fully provisioned + current user enrolled
      'ResumeBootstrap' — .in-progress marker present (offer Resume / Restart)

.PARAMETER InstallRoot
    DDS install dir. Defaults to "C:\Program Files\DDS".

.PARAMETER DataRoot
    DDS data dir. Defaults to "C:\ProgramData\DDS".

.PARAMETER BundlePath
    Optional path to a *.dds provision bundle (from file association /
    "-BundlePath %1"). When set and there's no existing domain, the
    wizard should branch to JoinDomain pre-loaded.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\Program Files\DDS",
    [string]$DataRoot    = "C:\ProgramData\DDS",
    [string]$BundlePath  = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Paths ──────────────────────────────────────────────────────────
$NodeData       = Join-Path $DataRoot    "node-data"
$DomainTomlPath = Join-Path $NodeData    "domain.toml"
$AdmissionPath  = Join-Path $NodeData    "admission.cbor"
$NodeTomlPath   = Join-Path $InstallRoot "config\node.toml"
$VaultPath      = Join-Path $DataRoot    "vault.dat"
$ResumeMarker   = Join-Path $DataRoot    "bootstrap\.in-progress.json"
$NodeBin        = Join-Path $InstallRoot "bin\dds-node.exe"

# ── Get current user SID ───────────────────────────────────────────
function Get-CurrentUserSid {
    try {
        return ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    } catch {
        return $null
    }
}

# ── Vault probe ────────────────────────────────────────────────────
# The vault is DPAPI-machine-scope encrypted, so a non-elevated user
# cannot decrypt it themselves. The wizard either (a) is elevated and
# can call the helper exe, or (b) treats "no read access" as "I don't
# know — assume not enrolled". For the auto-launch path the wizard
# self-elevates so it's option (a).
#
# When the file is absent: definitely no enrolled users.
# When the file is present but unreadable: returns $null (unknown).
function Test-CurrentUserHasVaultEntry {
    if (-not (Test-Path $VaultPath)) { return $false }
    $sid = Get-CurrentUserSid
    if (-not $sid) { return $null }

    # The DPAPI blob is opaque to us from PowerShell. We do a best-effort
    # substring search for the SID encoded as UTF-16LE bytes — the vault
    # serialization format embeds the SID as a wide string. If we can't
    # read the file (ACL), we return $null and let the wizard decide.
    try {
        $bytes = [IO.File]::ReadAllBytes($VaultPath)
        $needle = [Text.Encoding]::Unicode.GetBytes($sid)
        # Tiny KMP-free search: cheap and the vault file is small.
        for ($i = 0; $i -le ($bytes.Length - $needle.Length); $i++) {
            $match = $true
            for ($j = 0; $j -lt $needle.Length; $j++) {
                if ($bytes[$i + $j] -ne $needle[$j]) { $match = $false; break }
            }
            if ($match) { return $true }
        }
        return $false
    } catch {
        return $null
    }
}

# ── Service / pipe probes ──────────────────────────────────────────
function Test-DdsNodePipeOpen {
    # Cheap test: the pipe shows up in \\.\pipe\ when the service is bound.
    return [bool](Test-Path '\\.\pipe\dds-api')
}

function Get-DdsNodeServiceState {
    $s = Get-Service -Name DdsNode -ErrorAction SilentlyContinue
    if ($s) { return $s.Status.ToString() }
    return 'NotRegistered'
}

# ── Bundle probe ───────────────────────────────────────────────────
function Test-BundlePathValid {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if ([IO.Path]::GetExtension($Path).ToLowerInvariant() -ne '.dds') { return $false }
    return $true
}

# ── Resume marker ──────────────────────────────────────────────────
function Read-ResumeMarker {
    if (-not (Test-Path $ResumeMarker)) { return $null }
    try {
        return Get-Content $ResumeMarker -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
}

# ── Compose state ──────────────────────────────────────────────────
$domainProvisioned = (Test-Path $DomainTomlPath) -and (Test-Path $AdmissionPath)
$nodeConfigPresent = Test-Path $NodeTomlPath
$nodeServiceState  = Get-DdsNodeServiceState
$nodePipeOpen      = Test-DdsNodePipeOpen
$bundleValid       = Test-BundlePathValid -Path $BundlePath
$resume            = Read-ResumeMarker
$userSid           = Get-CurrentUserSid
$vaultHasUser      = $null
if ($domainProvisioned) {
    $vaultHasUser = Test-CurrentUserHasVaultEntry
}

# ── Branch recommendation ──────────────────────────────────────────
$branch = 'Welcome'
if ($resume) {
    $branch = 'ResumeBootstrap'
}
elseif (-not $domainProvisioned -and $bundleValid) {
    $branch = 'JoinDomain'
}
elseif (-not $domainProvisioned) {
    $branch = 'NewDomain'
}
elseif ($vaultHasUser -eq $false) {
    $branch = 'EnrollUser'
}
elseif ($vaultHasUser -eq $true) {
    $branch = 'Health'
}
else {
    # Provisioned, but vault state unknown — let the user decide.
    $branch = 'Welcome'
}

[pscustomobject]@{
    InstallRoot        = $InstallRoot
    DataRoot           = $DataRoot
    NodeBin            = $NodeBin
    DomainProvisioned  = $domainProvisioned
    NodeConfigPresent  = $nodeConfigPresent
    NodeServiceState   = $nodeServiceState
    NodePipeOpen       = $nodePipeOpen
    BundlePath         = $BundlePath
    BundleValid        = $bundleValid
    ResumeMarker       = $resume
    CurrentUserSid     = $userSid
    VaultHasCurrentUser = $vaultHasUser   # $true / $false / $null (unknown)
    DomainTomlPath     = $DomainTomlPath
    AdmissionPath      = $AdmissionPath
    NodeTomlPath       = $NodeTomlPath
    VaultPath          = $VaultPath
    Branch             = $branch
}
