<#
.SYNOPSIS
    Fully uninstall the DDS Windows Platform from this machine, including
    the Credential Provider that MSI uninstall leaves behind on purpose.

.DESCRIPTION
    Resolves every installed ProductCode under the DDS UpgradeCode, runs
    `msiexec /x` against each (stops + removes DdsNode, DdsAuthBridge,
    DdsPolicyAgent and clears C:\Program Files\DDS), then force-removes
    the residue the MSI deliberately keeps:

      - C:\Windows\System32\DdsCredentialProvider.dll  (Permanent="yes" in
        DdsBundle.wxs — logonui.exe may have it loaded, so this script
        schedules a delete-on-reboot via MoveFileEx if a live delete fails)
      - HKLM\SOFTWARE\Classes\CLSID\{a7f3b2c1-9d4e-4f8a-b6c5-2e1d0a3f7b9c}
      - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\
        Credential Providers\{a7f3b2c1-9d4e-4f8a-b6c5-2e1d0a3f7b9c}
      - HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\
        DdsAuthBridge   (event-log source registered by EventLogger.cpp)
      - HKLM\SOFTWARE\DDS (entire subtree)
      - C:\ProgramData\DDS (node identity, vault, FIDO2 state, audit logs)
      - %LOCALAPPDATA%\DDS
      - %TEMP%\dds-bootstrap-*.log, dds-console-*.log, dds-deviceenroll-*.log,
        dds-enroll-*.log, dds-join-*.log  (wizard transcripts)

    The script's own uninstall logs (%TEMP%\dds-uninstall-*.log) are kept
    so a failed uninstall remains debuggable.

    Self-elevates via UAC if not already running as Administrator.

    One-line invocation (from any directory):

        powershell -NoProfile -ExecutionPolicy Bypass -File `
            "C:\ABCD\platform\windows\installer\scripts\Uninstall-Dds.ps1" -Force

.PARAMETER Force
    Skip the WIPE confirmation prompt.

.PARAMETER KeepData
    Uninstall the MSI and remove the Credential Provider, but leave
    C:\ProgramData\DDS, per-user state, and TEMP transcripts in place.
    Useful when reinstalling the same domain identity.

.PARAMETER InstallRoot
    DDS install dir. Defaults to "C:\Program Files\DDS".

.PARAMETER DataRoot
    DDS data dir. Defaults to "C:\ProgramData\DDS".
#>
[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$KeepData,
    [string]$InstallRoot = "C:\Program Files\DDS",
    [string]$DataRoot    = "C:\ProgramData\DDS"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Must match DdsBundle.wxs UpgradeCode.
$UpgradeCode = '{F1A2B3C4-D5E6-7890-ABCD-123456789012}'

# Credential Provider CLSID — DdsBundle.wxs:419 marks the component
# Permanent="yes" so msiexec /x leaves the DLL and these reg keys in
# place. We strip them by hand below.
$CredProvClsid = '{a7f3b2c1-9d4e-4f8a-b6c5-2e1d0a3f7b9c}'
$CredProvDll   = Join-Path $env:SystemRoot 'System32\DdsCredentialProvider.dll'

$UserAppData = Join-Path $env:LOCALAPPDATA 'DDS'

# Self-elevate
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"")
    if ($Force)    { $argList += "-Force" }
    if ($KeepData) { $argList += "-KeepData" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList -Wait
    exit
}

# Resolve every installed ProductCode under the DDS UpgradeCode. Using
# the COM Installer object so the script survives version bumps without
# the ProductCode being hardcoded.
$installer = New-Object -ComObject WindowsInstaller.Installer
$productCodes = @($installer.RelatedProducts($UpgradeCode))

Write-Host ""
Write-Host "=== DDS Uninstall ===" -ForegroundColor Yellow
if ($productCodes.Count -eq 0) {
    Write-Host "No installed DDS MSI found under UpgradeCode $UpgradeCode." -ForegroundColor Cyan
} else {
    Write-Host "Will remove MSI product(s):"
    foreach ($pc in $productCodes) {
        $name = try { $installer.ProductInfo($pc, 'ProductName') } catch { '<unknown>' }
        $ver  = try { $installer.ProductInfo($pc, 'VersionString') } catch { '<unknown>' }
        Write-Host "  - $name $ver  $pc"
    }
}
Write-Host "Will stop services: DdsPolicyAgent, DdsAuthBridge, DdsNode"
Write-Host "Will force-remove Credential Provider residue:"
if (Test-Path $CredProvDll) { Write-Host "  - $CredProvDll" }
Write-Host "  - HKLM\SOFTWARE\Classes\CLSID\$CredProvClsid"
Write-Host "  - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CredProvClsid"
Write-Host "Will remove event-log source: DdsAuthBridge"
if (-not $KeepData) {
    Write-Host "Will wipe:"
    foreach ($p in @($DataRoot, $UserAppData)) {
        if (Test-Path $p) { Write-Host "  - $p" }
    }
    Write-Host "  - HKLM\SOFTWARE\DDS (entire subtree)"
    Write-Host "  - %TEMP%\dds-{bootstrap,console,deviceenroll,enroll,join}-*.log"
} else {
    Write-Host "Data dir, registry subtree, and TEMP transcripts preserved (-KeepData)." -ForegroundColor Cyan
}
Write-Host ""

if (-not $Force) {
    $resp = Read-Host "Type 'WIPE' to confirm"
    if ($resp -ne 'WIPE') {
        Write-Host "Aborted." -ForegroundColor Cyan
        exit 0
    }
}

# Stop services up-front. msiexec stops them too, but doing it here makes
# the failure mode explicit if a handle is being held.
Write-Host "Stopping services..." -ForegroundColor Yellow
foreach ($svc in @('DdsPolicyAgent','DdsAuthBridge','DdsNode')) {
    $s = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($s -and $s.Status -ne 'Stopped') {
        Write-Host "  Stopping $svc..."
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    }
}

# Run msiexec for each ProductCode. /qn = silent, /norestart = never
# reboot, /l*v = verbose log so a failed uninstall is debuggable.
foreach ($pc in $productCodes) {
    $log = Join-Path $env:TEMP "dds-uninstall-$($pc.Trim('{','}')).log"
    Write-Host "Uninstalling $pc ..." -ForegroundColor Yellow
    Write-Host "  log: $log"
    $p = Start-Process -FilePath 'msiexec.exe' `
        -ArgumentList @('/x', $pc, '/qn', '/norestart', '/l*v', "`"$log`"") `
        -Wait -PassThru
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) {
        throw "msiexec /x $pc exited $($p.ExitCode). See $log."
    }
}

# Belt-and-suspenders: any service the MSI left behind gets sc.exe deleted.
foreach ($svc in @('DdsPolicyAgent','DdsAuthBridge','DdsNode')) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Write-Host "  Force-deleting leftover service $svc..." -ForegroundColor Yellow
        & sc.exe delete $svc | Out-Null
    }
}

# Credential Provider — Permanent="yes" means MSI never touches it.
# Strip the two registry locations first (cheap, always succeeds), then
# try to delete the DLL. logonui.exe may have it mapped at LSA-logon
# time, so a live delete can fail with sharing violation. In that case
# we schedule MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) and tell the user.
Write-Host "Removing Credential Provider residue..." -ForegroundColor Yellow
$cpRegKeys = @(
    "HKLM:\SOFTWARE\Classes\CLSID\$CredProvClsid",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\$CredProvClsid"
)
foreach ($k in $cpRegKeys) {
    if (Test-Path -LiteralPath $k) {
        Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction SilentlyContinue
    }
}
$rebootRequired = $false
if (Test-Path $CredProvDll) {
    try {
        Remove-Item -LiteralPath $CredProvDll -Force -ErrorAction Stop
        Write-Host "  Removed $CredProvDll"
    } catch {
        # File is in use (typically by logonui.exe). Schedule a
        # delete-on-reboot via MoveFileEx with lpNewFileName=NULL.
        Add-Type -ErrorAction SilentlyContinue -Namespace DdsUninstall -Name MoveFileEx -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
        $MOVEFILE_DELAY_UNTIL_REBOOT = 4
        if ([DdsUninstall.MoveFileEx]::MoveFileEx($CredProvDll, $null, $MOVEFILE_DELAY_UNTIL_REBOOT)) {
            Write-Host "  $CredProvDll is in use; scheduled for delete on reboot." -ForegroundColor Yellow
            $rebootRequired = $true
        } else {
            Write-Host "  WARNING: failed to delete or schedule $CredProvDll. Reboot to Safe Mode and remove manually." -ForegroundColor Red
        }
    }
}

# Event-log source registered by EventLogger.cpp.
Write-Host "Removing event-log source DdsAuthBridge..." -ForegroundColor Yellow
try { Remove-EventLog -Source 'DdsAuthBridge' -ErrorAction Stop }
catch {
    # Remove-EventLog only works when the source resolves. Fall back to
    # nuking the registry key directly.
    $elKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\DdsAuthBridge'
    if (Test-Path -LiteralPath $elKey) {
        Remove-Item -LiteralPath $elKey -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (-not $KeepData) {
    Write-Host "Removing data..." -ForegroundColor Yellow
    foreach ($p in @($DataRoot, $UserAppData)) {
        if (Test-Path $p) {
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $p
        }
    }
    # Whole HKLM\SOFTWARE\DDS subtree — covers AuthBridge stamp,
    # Version key, and any future stamps without per-key maintenance.
    $ddsKey = 'HKLM:\SOFTWARE\DDS'
    if (Test-Path -LiteralPath $ddsKey) {
        Remove-Item -LiteralPath $ddsKey -Recurse -Force -ErrorAction SilentlyContinue
    }

    # %TEMP% wizard transcripts. We keep our own dds-uninstall-*.log
    # files so a failed run remains debuggable.
    Write-Host "Removing TEMP transcripts..." -ForegroundColor Yellow
    $patterns = @(
        'dds-bootstrap-*.log',
        'dds-bootstrap-console-*.log',
        'dds-console-*.log',
        'dds-deviceenroll-*.log',
        'dds-enroll-*.log',
        'dds-enroll-out-*.log',
        'dds-join-*.log'
    )
    foreach ($pat in $patterns) {
        Get-ChildItem -Path $env:TEMP -Filter $pat -File -ErrorAction SilentlyContinue |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

# Sanity check
$leftServices = Get-Service Dds* -ErrorAction SilentlyContinue
$leftInstall  = Test-Path $InstallRoot
$leftData     = (-not $KeepData) -and (Test-Path $DataRoot)
$leftCpReg    = $cpRegKeys | Where-Object { Test-Path -LiteralPath $_ }

if ($leftServices -or $leftInstall -or $leftData -or $leftCpReg) {
    Write-Host ""
    Write-Host "Uninstall finished with residue:" -ForegroundColor Yellow
    if ($leftServices) { Write-Host "  services: $(($leftServices | ForEach-Object Name) -join ', ')" }
    if ($leftInstall)  { Write-Host "  $InstallRoot still exists" }
    if ($leftData)     { Write-Host "  $DataRoot still exists" }
    if ($leftCpReg)    { Write-Host "  credprov reg: $($leftCpReg -join ', ')" }
    exit 1
}

Write-Host ""
if ($rebootRequired) {
    Write-Host "DDS uninstalled. REBOOT REQUIRED to finalize Credential Provider DLL removal." -ForegroundColor Yellow
} else {
    Write-Host "DDS fully uninstalled. Ready for fresh MSI install." -ForegroundColor Green
}
