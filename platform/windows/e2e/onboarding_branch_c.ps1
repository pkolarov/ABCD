<#
.SYNOPSIS
    E2E assertions for Onboarding Wizard — Branch C (enroll FIDO2 key on
    an existing account).

.DESCRIPTION
    Run on a VM where Branch A or Branch B has already completed (machine
    is part of a domain) and a user has driven the wizard's
    "Set up passwordless sign-in for this account" branch.

    Asserts:
      * vault.dat exists at %ProgramData%\DDS\vault.dat
      * vault.dat references the current user SID (best-effort byte search)
      * dds-enroll-user.exe is on disk (sanity-check the MSI staged it)

    The Branch C wizard also POSTs /v1/enroll/user — verifying that
    server-side requires admin approval over a separate session, so this
    e2e only checks the local artifacts. Caller can run a separate
    "list pending enrollments" check if it has admin context.
#>
[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\Program Files\DDS",
    [string]$DataRoot    = "C:\ProgramData\DDS"
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

$VaultPath     = Join-Path $DataRoot    'vault.dat'
$EnrollUserExe = Join-Path $InstallRoot 'bin\dds-enroll-user.exe'

Assert "dds-enroll-user.exe staged" (Test-Path $EnrollUserExe)
Assert "vault.dat exists"           (Test-Path $VaultPath)

if (Test-Path $VaultPath) {
    $sid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    try {
        $bytes = [IO.File]::ReadAllBytes($VaultPath)
        $needle = [Text.Encoding]::Unicode.GetBytes($sid)
        $found = $false
        for ($i = 0; $i -le ($bytes.Length - $needle.Length); $i++) {
            $m = $true
            for ($j = 0; $j -lt $needle.Length; $j++) {
                if ($bytes[$i + $j] -ne $needle[$j]) { $m = $false; break }
            }
            if ($m) { $found = $true; break }
        }
        Assert "vault.dat references current user SID ($sid)" $found
    } catch {
        Assert "vault.dat readable from this context" $false "($($_.Exception.Message))"
    }
}

# Sanity-check the wizard helpers were installed.
foreach ($p in @(
    'bin\DdsConsole.ps1',
    'bin\Get-DdsOnboardingState.ps1',
    'bin\Bootstrap-DdsDomain.ps1',
    'bin\Enroll-DdsDevice.ps1',
    'bin\Reset-DdsBootstrap.ps1'
)) {
    Assert "$p staged" (Test-Path (Join-Path $InstallRoot $p))
}

# .dds file association
$progid = (Get-ItemProperty -Path 'HKLM:\Software\Classes\.dds' -ErrorAction SilentlyContinue).'(default)'
Assert "*.dds file association registered" (-not [string]::IsNullOrWhiteSpace($progid))

# Active Setup entry
$activeSetupKey = 'HKLM:\Software\Microsoft\Active Setup\Installed Components\{F1A2B3C4-DDS0-0000-0000-DDSONBOARD01}'
Assert "Active Setup entry registered" (Test-Path $activeSetupKey)

Write-Host ""
Write-Host "=========================================="
Write-Host ("  Branch C: PASS={0}, FAIL={1}" -f $pass, $fail) -ForegroundColor (& { if ($fail -eq 0) { 'Green' } else { 'Red' } })
Write-Host "=========================================="
exit ($(if ($fail -eq 0) { 0 } else { 1 }))
