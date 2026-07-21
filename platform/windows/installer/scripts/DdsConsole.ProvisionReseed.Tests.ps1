<#
.SYNOPSIS
    Plain-PowerShell (no external module) regression test for the FIX 2
    provision-bundle reseed wiring in DdsConsole.ps1.

.DESCRIPTION
    DdsConsole.ps1 self-elevates and builds a WPF window on load, so it
    cannot be dot-sourced headless to invoke Invoke-ProvisionBundleReseed
    directly (unlike Watchdog-DdsNode.ps1, whose executable body is guarded
    behind a not-dot-sourced check). Instead this parses DdsConsole.ps1 with
    the PowerShell AST and asserts the load-bearing facts of FIX 2 against
    the source of the relevant functions — deterministic and reflow-proof:

      * Invoke-ProvisionBundleReseed exists and its create-provision-bundle
        payload passes --config '__CFG__' (TEST PLAN item 18) and NOT the old
        --bootstrap-admin-urn.
      * __CFG__ is substituted from $NodeConfigFile (the flag the prior
        workflow added; dds-node reads bootstrap_admin_urn back out of it).
      * Tick-AdminSetupWait's success branch invokes Invoke-ProvisionBundleReseed
        (the real admin-setup completion hook), guarded by
        -not $script:provisionBundleSeeded and Test-Path $domainKeyPath.
      * Run-NewDomainSaveBundle delegates to the same shared reseed function.

    Run:  powershell -NoProfile -ExecutionPolicy Bypass -File DdsConsole.ProvisionReseed.Tests.ps1
    Exit code is 0 iff every assertion passed.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptUnderTest = Join-Path $PSScriptRoot "DdsConsole.ps1"

# -- Tiny assertion harness (mirrors Watchdog-DdsNode.Tests.ps1) ----------
$script:passed   = 0
$script:failed   = 0
$script:messages = New-Object System.Collections.Generic.List[string]

function Assert-True {
    param([bool]$Condition, [Parameter(Mandatory)] [string]$Label)
    if ($Condition) {
        $script:passed++
        $script:messages.Add("  [PASS] $Label")
    } else {
        $script:failed++
        $script:messages.Add("  [FAIL] $Label  -- condition was false")
    }
}

# -- Parse the script under test ------------------------------------------
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $scriptUnderTest, [ref]$tokens, [ref]$errors)
Assert-True (-not ($errors -and $errors.Count -gt 0)) "DdsConsole.ps1 parses with no syntax errors"

function Get-FunctionText {
    param([string]$Name)
    $fn = $ast.FindAll({
            param($n) ($n -is [System.Management.Automation.Language.FunctionDefinitionAst]) -and
                      ($n.Name -eq $Name)
        }, $true) | Select-Object -First 1
    if ($null -eq $fn) { return $null }
    return $fn.Extent.Text
}

# -- Invoke-ProvisionBundleReseed: the shared reseed function --------------
$reseed = Get-FunctionText 'Invoke-ProvisionBundleReseed'
Assert-True ($null -ne $reseed) "Invoke-ProvisionBundleReseed is defined"
if ($reseed) {
    Assert-True ($reseed -match 'create-provision-bundle') `
        "reseed payload runs create-provision-bundle"
    Assert-True ($reseed -match "--config\s+'__CFG__'") `
        "reseed payload passes --config '__CFG__' (item 18)"
    Assert-True ($reseed -notmatch '--bootstrap-admin-urn') `
        "reseed payload no longer passes --bootstrap-admin-urn (item 18)"
    Assert-True ($reseed -match "-replace\s+'__CFG__',.*\`$NodeConfigFile") `
        "__CFG__ is substituted from `$NodeConfigFile"
    Assert-True ($reseed -match 'param\(\[scriptblock\]\$OnDone\)') `
        "reseed takes an [scriptblock]`$OnDone completion callback"
    Assert-True ($reseed -match '\$script:provisionBundleSeeded\s*=\s*\$true') `
        "reseed sets `$script:provisionBundleSeeded = `$true on exit 0"
}

# -- Tick-AdminSetupWait: the real admin-setup completion hook -------------
$tick = Get-FunctionText 'Tick-AdminSetupWait'
Assert-True ($null -ne $tick) "Tick-AdminSetupWait is defined"
if ($tick) {
    Assert-True ($tick -match 'if\s*\(\$script:adminSetupOk\)') `
        "Tick-AdminSetupWait branches on `$script:adminSetupOk"
    Assert-True ($tick -match 'Invoke-ProvisionBundleReseed') `
        "Tick-AdminSetupWait invokes Invoke-ProvisionBundleReseed (the hook)"
    Assert-True ($tick -match '-not\s+\$script:provisionBundleSeeded') `
        "hook guards on -not `$script:provisionBundleSeeded (fires at most once)"
    Assert-True ($tick -match 'Test-Path\s+\$domainKeyPath') `
        "hook guards on Test-Path `$domainKeyPath (domain key still present)"
}

# -- Run-NewDomainSaveBundle: delegates to the shared reseed ---------------
$save = Get-FunctionText 'Run-NewDomainSaveBundle'
Assert-True ($null -ne $save) "Run-NewDomainSaveBundle is defined"
if ($save) {
    Assert-True ($save -match 'Invoke-ProvisionBundleReseed') `
        "Run-NewDomainSaveBundle delegates to the shared Invoke-ProvisionBundleReseed"
}

# -- Report ----------------------------------------------------------------
$script:messages | ForEach-Object { Write-Host $_ }
Write-Host ""
Write-Host ("Result: {0} passed, {1} failed" -f $script:passed, $script:failed)
if ($script:failed -gt 0) { exit 1 } else { exit 0 }
