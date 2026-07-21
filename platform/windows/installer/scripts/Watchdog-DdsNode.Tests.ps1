<#
.SYNOPSIS
    Plain-PowerShell (no external module) unit tests for Watchdog-DdsNode.ps1.

.DESCRIPTION
    Dot-sources Watchdog-DdsNode.ps1 -- whose executable body is guarded
    behind a not-dot-sourced check, so loading it here defines the functions
    WITHOUT polling the node or restarting any service -- and exercises:

      * Get-WatchdogDecision, the pure decision (all TEST PLAN item 17 cases:
        i..viii), covering equal->reset, mismatch<threshold->increment,
        >=threshold under cap->restart+record, >=threshold at cap->
        capped/no-restart, admitted-absent->reset, rolling-24h pruning, and
        the rolling-upgrade-churn guard.

      * The absent-field guard: a status payload missing `admitted_peers`
        must yield $null (unknown), not throw, under Set-StrictMode Latest.

      * Invoke-WatchdogDecision, the executor, with the restart action MOCKED
        (injected scriptblock). No test ever calls the real Restart-Service:
        'restart' invokes the mock + logs EventId 1000; a failing restart
        logs EventId 1001; 'capped' logs EventId 1002 and does NOT restart;
        'none' does neither.

    Run:  powershell -NoProfile -ExecutionPolicy Bypass -File Watchdog-DdsNode.Tests.ps1
    Exit code is 0 iff every assertion passed.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Dot-source the script under test (guard skips its main body for '.').
. (Join-Path $PSScriptRoot "Watchdog-DdsNode.ps1")

# -- Tiny assertion harness -----------------------------------------------
$script:passed   = 0
$script:failed   = 0
$script:messages = New-Object System.Collections.Generic.List[string]

function Assert-Equal {
    param($Expected, $Actual, [Parameter(Mandatory)] [string]$Label)
    if ($Expected -eq $Actual) {
        $script:passed++
        $script:messages.Add("  [PASS] $Label  (=[$Actual])")
    } else {
        $script:failed++
        $script:messages.Add("  [FAIL] $Label  -- expected [$Expected], got [$Actual]")
    }
}

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

function Section { param([string]$Name) $script:messages.Add(""); $script:messages.Add($Name) }

# Build a prior-state object shaped like Read-WatchdogState's output.
function New-PriorState {
    param(
        [int]$ConsecutiveMismatches = 0,
        [object[]]$RestartTimestampsUtc = @(),
        $PrevAdmitted = $null
    )
    [pscustomobject]@{
        ConsecutiveMismatches = $ConsecutiveMismatches
        RestartTimestampsUtc  = @($RestartTimestampsUtc)
        PrevAdmitted          = $PrevAdmitted
    }
}

# Convenience: count a possibly-scalar/possibly-null collection safely.
function CountOf { param($x) @($x).Count }

# Fixed "now" so history math is deterministic.
$now = (Get-Date).ToUniversalTime()
function AgoIso { param([double]$Hours) $now.AddHours(-$Hours).ToString("o") }

$REQ = 3   # RequiredConsecutiveMismatches
$MAX = 3   # MaxRestartsPer24h

# -------------------------------------------------------------------------
# (i) connected == admitted, prior streak 2  ->  none, counter reset to 0
# (bottom-of-prompt: "equal -> reset")
Section "(i) equal counts (3/3), prior streak 2 -> none, reset"
$d = Get-WatchdogDecision -Connected 3 -Admitted 3 `
        -PriorState (New-PriorState -ConsecutiveMismatches 2 -PrevAdmitted 3) `
        -NowUtc $now -RequiredConsecutiveMismatches $REQ -MaxRestartsPer24h $MAX
Assert-Equal 'none' $d.Action                      '(i) Action'
Assert-Equal 0      $d.ConsecutiveMismatches       '(i) ConsecutiveMismatches'

# -------------------------------------------------------------------------
# (ii) mismatch (4/2), prior streak 1  ->  none, counter increments to 2
# (bottom-of-prompt: "mismatch < threshold -> increment")
Section "(ii) mismatch (4/2), prior streak 1 -> none, counter=2"
$d = Get-WatchdogDecision -Connected 4 -Admitted 2 `
        -PriorState (New-PriorState -ConsecutiveMismatches 1 -PrevAdmitted 2) `
        -NowUtc $now -RequiredConsecutiveMismatches $REQ -MaxRestartsPer24h $MAX
Assert-Equal 'none' $d.Action                      '(ii) Action'
Assert-Equal 2      $d.ConsecutiveMismatches       '(ii) ConsecutiveMismatches'

# -------------------------------------------------------------------------
# (iii) mismatch (4/2), prior streak 2, EMPTY history -> reaches threshold ->
#       restart, counter reset to 0, history now has 1 entry (the new restart)
# (bottom-of-prompt: ">= threshold under cap -> restart + record")
Section "(iii) mismatch (4/2), prior streak 2, empty history -> restart, reset, hist 1"
$d = Get-WatchdogDecision -Connected 4 -Admitted 2 `
        -PriorState (New-PriorState -ConsecutiveMismatches 2 -PrevAdmitted 2 -RestartTimestampsUtc @()) `
        -NowUtc $now -RequiredConsecutiveMismatches $REQ -MaxRestartsPer24h $MAX
Assert-Equal 'restart' $d.Action                       '(iii) Action'
Assert-Equal 0         $d.ConsecutiveMismatches        '(iii) ConsecutiveMismatches'
Assert-Equal 1         (CountOf $d.RestartTimestampsUtc) '(iii) history count'

# -------------------------------------------------------------------------
# (iv) mismatch (4/2), prior streak 2, 3 restarts within the last hour ->
#      threshold reached but cap already spent -> CAPPED, counter unchanged
#      (stays at prior 2 -- no reset, no climb), history unchanged (3)
# (bottom-of-prompt: ">= threshold at cap -> capped / no restart / error")
Section "(iv) mismatch (4/2), prior streak 2, 3x(now-1h) -> capped, counter unchanged (2), hist 3"
$d = Get-WatchdogDecision -Connected 4 -Admitted 2 `
        -PriorState (New-PriorState -ConsecutiveMismatches 2 -PrevAdmitted 2 `
                        -RestartTimestampsUtc @((AgoIso 1), (AgoIso 1), (AgoIso 1))) `
        -NowUtc $now -RequiredConsecutiveMismatches $REQ -MaxRestartsPer24h $MAX
Assert-Equal 'capped' $d.Action                        '(iv) Action'
Assert-Equal 2        $d.ConsecutiveMismatches         '(iv) ConsecutiveMismatches unchanged'
Assert-Equal 3        (CountOf $d.RestartTimestampsUtc) '(iv) history count unchanged'

# -------------------------------------------------------------------------
# (v) Admitted unknown ($null) -> none, counter reset, history PRESERVED
#     (pruned). Plus the absent-field parse guard: a JSON status lacking
#     admitted_peers must extract as $null, not throw, under strict mode.
# (bottom-of-prompt: "admitted absent -> reset + exit")
Section "(v) Admitted=`$null -> none, reset, history preserved; + absent-field parse guard"
$d = Get-WatchdogDecision -Connected 4 -Admitted $null `
        -PriorState (New-PriorState -ConsecutiveMismatches 2 -PrevAdmitted 2 `
                        -RestartTimestampsUtc @((AgoIso 1), (AgoIso 2))) `
        -NowUtc $now -RequiredConsecutiveMismatches $REQ -MaxRestartsPer24h $MAX
Assert-Equal 'none' $d.Action                        '(v) Action (unknown)'
Assert-Equal 0      $d.ConsecutiveMismatches         '(v) counter reset'
Assert-Equal 2      (CountOf $d.RestartTimestampsUtc) '(v) history preserved (2 recent entries)'

# absent-field guard: strict-mode-safe extraction must yield $null, not throw
$threw = $false
$admittedFromJson = 'sentinel'
try {
    $status = '{ "node": { "connected_peers": 4 } }' | ConvertFrom-Json
    $node   = Get-PropOrNull $status 'node'
    $admittedFromJson = Get-PropOrNull $node 'admitted_peers'
} catch {
    $threw = $true
}
Assert-True (-not $threw)              '(v) extracting absent admitted_peers does not throw'
Assert-True ($null -eq $admittedFromJson) '(v) absent admitted_peers extracts as $null'

# and a payload missing the whole `node` object is likewise unknown, not a throw
$threw2 = $false
$connFromJson = 'sentinel'
try {
    $status2 = '{ "other": 1 }' | ConvertFrom-Json
    $node2   = Get-PropOrNull $status2 'node'
    $connFromJson = Get-PropOrNull $node2 'connected_peers'
} catch {
    $threw2 = $true
}
Assert-True (-not $threw2)             '(v) missing node object does not throw'
Assert-True ($null -eq $connFromJson)  '(v) missing node -> connected extracts as $null'

# -------------------------------------------------------------------------
# (vi) mismatch (4/2), prior streak 2, 3 restarts all 25h ago -> all pruned
#      -> history empty at threshold -> restart allowed, history now 1
# (bottom-of-prompt: "old timestamps pruned -> restart allowed")
Section "(vi) mismatch (4/2), prior streak 2, 3x(now-25h) -> pruned -> restart, hist 1"
$d = Get-WatchdogDecision -Connected 4 -Admitted 2 `
        -PriorState (New-PriorState -ConsecutiveMismatches 2 -PrevAdmitted 2 `
                        -RestartTimestampsUtc @((AgoIso 25), (AgoIso 25), (AgoIso 25))) `
        -NowUtc $now -RequiredConsecutiveMismatches $REQ -MaxRestartsPer24h $MAX
Assert-Equal 'restart' $d.Action                        '(vi) Action'
Assert-Equal 0         $d.ConsecutiveMismatches         '(vi) counter reset'
Assert-Equal 1         (CountOf $d.RestartTimestampsUtc) '(vi) history count (old pruned, 1 new)'

# -------------------------------------------------------------------------
# (vii) mismatch (4/2), prior streak 2, 2 old (25h) + 1 recent (1h) ->
#       prune keeps the 1 recent -> under cap -> restart, history now 2
Section "(vii) mismatch (4/2), 2x(now-25h)+1x(now-1h) -> restart, hist 2"
$d = Get-WatchdogDecision -Connected 4 -Admitted 2 `
        -PriorState (New-PriorState -ConsecutiveMismatches 2 -PrevAdmitted 2 `
                        -RestartTimestampsUtc @((AgoIso 25), (AgoIso 25), (AgoIso 1))) `
        -NowUtc $now -RequiredConsecutiveMismatches $REQ -MaxRestartsPer24h $MAX
Assert-Equal 'restart' $d.Action                        '(vii) Action'
Assert-Equal 2         (CountOf $d.RestartTimestampsUtc) '(vii) history count (1 kept + 1 new)'

# -------------------------------------------------------------------------
# (viii) connected > admitted (4/2) but admitted ROSE past the prior baseline
#        (PrevAdmitted 1 < admitted 2) -> rolling-upgrade churn, NOT a mismatch
#        -> none, counter reset
Section "(viii) 4/2 but admitted rose (PrevAdmitted 1 < 2) -> none (churn guard)"
$d = Get-WatchdogDecision -Connected 4 -Admitted 2 `
        -PriorState (New-PriorState -ConsecutiveMismatches 2 -PrevAdmitted 1) `
        -NowUtc $now -RequiredConsecutiveMismatches $REQ -MaxRestartsPer24h $MAX
Assert-Equal 'none' $d.Action                      '(viii) Action'
Assert-Equal 0      $d.ConsecutiveMismatches       '(viii) counter reset'

# -------------------------------------------------------------------------
# EXECUTOR tests -- restart action MOCKED; the real Restart-Service is never
# invoked. (bottom-of-prompt: "inject/mock the restart action.")
# -------------------------------------------------------------------------

# shared mock state + factory
$script:restartCalls = 0
$script:restartArg   = $null
$script:events       = New-Object System.Collections.Generic.List[object]
function Reset-Mocks {
    $script:restartCalls = 0
    $script:restartArg   = $null
    $script:events       = New-Object System.Collections.Generic.List[object]
}
$restartMock       = { param($svc) $script:restartCalls++; $script:restartArg = $svc }
$restartThrowsMock = { param($svc) $script:restartCalls++; throw "simulated restart failure" }
$eventMock         = { param($msg, $type, $id) $script:events.Add([pscustomobject]@{ Type = $type; Id = $id; Msg = $msg }) }

# (ix) Action 'restart' -> mock restart invoked once (with service name),
#      event logged at EventId 1000 / Warning.
Section "(ix) executor: 'restart' -> mocked restart called once + EventId 1000 Warning"
Reset-Mocks
$dec = [pscustomobject]@{ Action = 'restart'; ConsecutiveMismatches = 0; RestartTimestampsUtc = @(); PrevAdmitted = 2; Reason = 'test restart' }
Invoke-WatchdogDecision -Decision $dec -ServiceName 'DdsNode' -RestartAction $restartMock -EventWriter $eventMock
Assert-Equal 1        $script:restartCalls           '(ix) restart action invoked exactly once'
Assert-Equal 'DdsNode' $script:restartArg            '(ix) restart action received service name'
Assert-Equal 1        $script:events.Count         '(ix) exactly one event logged'
Assert-Equal 1000     $script:events[0].Id           '(ix) event id 1000'
Assert-True  ($script:events[0].Type -eq [System.Diagnostics.EventLogEntryType]::Warning) '(ix) event type Warning'

# (x) Action 'capped' -> restart NOT invoked, event logged at EventId 1002 / Error.
Section "(x) executor: 'capped' -> NO restart + EventId 1002 Error"
Reset-Mocks
$dec = [pscustomobject]@{ Action = 'capped'; ConsecutiveMismatches = 2; RestartTimestampsUtc = @((AgoIso 1)); PrevAdmitted = 2; Reason = 'test capped' }
Invoke-WatchdogDecision -Decision $dec -ServiceName 'DdsNode' -RestartAction $restartMock -EventWriter $eventMock
Assert-Equal 0    $script:restartCalls               '(x) restart action NOT invoked'
Assert-Equal 1    $script:events.Count             '(x) exactly one event logged'
Assert-Equal 1002 $script:events[0].Id               '(x) event id 1002'
Assert-True  ($script:events[0].Type -eq [System.Diagnostics.EventLogEntryType]::Error) '(x) event type Error'

# (xi) Action 'none' -> neither restart nor event.
Section "(xi) executor: 'none' -> no restart, no event"
Reset-Mocks
$dec = [pscustomobject]@{ Action = 'none'; ConsecutiveMismatches = 1; RestartTimestampsUtc = @(); PrevAdmitted = 2; Reason = 'test none' }
Invoke-WatchdogDecision -Decision $dec -ServiceName 'DdsNode' -RestartAction $restartMock -EventWriter $eventMock
Assert-Equal 0 $script:restartCalls                  '(xi) restart action NOT invoked'
Assert-Equal 0 $script:events.Count               '(xi) no event logged'

# (xii) Action 'restart' but the restart action throws -> caught, logged at
#       EventId 1001 / Error. Still no real service touched (mock only).
Section "(xii) executor: 'restart' failing -> EventId 1001 Error (restart mocked, service never touched)"
Reset-Mocks
$dec = [pscustomobject]@{ Action = 'restart'; ConsecutiveMismatches = 0; RestartTimestampsUtc = @((AgoIso 0)); PrevAdmitted = 2; Reason = 'test restart-fail' }
Invoke-WatchdogDecision -Decision $dec -ServiceName 'DdsNode' -RestartAction $restartThrowsMock -EventWriter $eventMock
Assert-Equal 1    $script:restartCalls               '(xii) restart action attempted once'
Assert-Equal 1    $script:events.Count             '(xii) exactly one event logged'
Assert-Equal 1001 $script:events[0].Id               '(xii) event id 1001'
Assert-True  ($script:events[0].Type -eq [System.Diagnostics.EventLogEntryType]::Error) '(xii) event type Error'

# -- Report ---------------------------------------------------------------
$script:messages.Add("")
$script:messages.Add("------------------------------------------------------")
foreach ($m in $script:messages) { Write-Host $m }
$total = $script:passed + $script:failed
Write-Host ""
Write-Host ("RESULT: {0}/{1} assertions passed, {2} failed." -f $script:passed, $total, $script:failed)

if ($script:failed -gt 0) { exit 1 } else { exit 0 }
