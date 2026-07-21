<#
.SYNOPSIS
    External backstop watchdog for the DdsNode service (watchdog plan Step 7).

.DESCRIPTION
    Registered as a SYSTEM Scheduled Task ("DDS Node Watchdog", every 5
    minutes) by DdsBundle.wxs's CA_RegisterWatchdogTask. Polls the node's
    own `/v1/status` (via `dds.exe stats --format json` over the pipe
    transport -- zero new client plumbing, same CLI an operator would run
    by hand) and compares `connected_peers` to `admitted_peers`
    (watchdog plan Step 5).

    Root cause this backstops: a peer can stay libp2p-connected but never
    complete the H-12 admission handshake if its one-shot `AdmissionRequest`
    (sent from `ConnectionEstablished`) is dropped or times out. Watchdog
    plan Step 6 already fixed the primary case in-process --
    `DdsNode::retry_unadmitted_peers`, called from the ~60s anti-entropy
    tick, re-issues that request for any still-connected-but-unadmitted
    peer. This script is the deliberately separate, external backstop for
    when that in-process retry has *itself* failed to recover the peer --
    it deliberately waits far longer (3 consecutive 5-minute polls, ~15
    min) than the in-process retry cadence so it only ever fires after the
    primary fix has had ample opportunity to work.

    State is persisted to a small JSON file under %ProgramData%\DDS so it
    survives across the independent process launches the Task Scheduler
    makes every 5 minutes. It carries:
      * ConsecutiveMismatches -- the streak counter.
      * PrevAdmitted          -- last observed admitted_peers, used to
                                 distinguish a genuinely stuck peer (admitted
                                 count flat/shrinking) from normal rolling
                                 churn (admitted count still climbing).
      * RestartTimestampsUtc  -- ISO-8601 ("o") timestamps of the restarts
                                 this watchdog has issued, for the rolling
                                 24-hour restart cap.

    On threshold, force-restarts the DdsNode service -- the one recovery
    mechanism already empirically proven to clear a stuck peer end-to-end
    -- and logs a Warning (EventId 1000), or Error (EventId 1001) if the
    restart itself fails. To stop an unbounded restart loop when a restart
    does not actually cure the mismatch, restarts are capped at
    $MaxRestartsPer24h within any rolling 24-hour window; once the cap is
    hit the watchdog stops restarting and logs an Error (EventId 1002)
    asking for operator intervention rather than continuing to bounce the
    service.

    Any inability to determine the node's admission state at all -- service
    down, pipe not yet ready, malformed output, or a status payload missing
    the expected fields -- is treated as UNKNOWN (a different failure mode
    than "connected but unadmitted"): it resets the streak counter and
    never feeds an unrelated outage into the admission-mismatch trigger,
    while preserving the (pruned) restart history so the 24h cap is not
    forgotten across transient outages.

    The core decision is a pure function, `Get-WatchdogDecision`, that takes
    the observed counts and prior state and returns an Action without any
    side effects. The script guards its executable body behind a
    not-dot-sourced check so the test suite can dot-source it, exercise the
    pure function directly, and mock the restart action -- see
    Watchdog-DdsNode.Tests.ps1.

.PARAMETER ServiceName
    Windows service to restart on threshold. Defaults to "DdsNode".

.PARAMETER RequiredConsecutiveMismatches
    Number of consecutive polls with connected_peers > admitted_peers
    required before restarting. Defaults to 3 (~15 min at the 5-minute
    Scheduled Task cadence this script is registered with).

.PARAMETER MaxRestartsPer24h
    Maximum service restarts this watchdog will issue within any rolling
    24-hour window before giving up and escalating to the operator (EventId
    1002) instead of restarting again. Defaults to 3.

.PARAMETER StateFile
    Path to the persisted watchdog state. Defaults to
    %ProgramData%\DDS\watchdog-state.json.

.PARAMETER EventSource
    Application event log source name. Defaults to "DDS Node Watchdog".
    Self-registers on first use (SYSTEM has the required rights).
#>
[CmdletBinding()]
param(
    [string]$ServiceName = "DdsNode",
    [int]$RequiredConsecutiveMismatches = 3,
    [int]$MaxRestartsPer24h = 3,
    [string]$StateFile = (Join-Path $env:ProgramData "DDS\watchdog-state.json"),
    [string]$EventSource = "DDS Node Watchdog"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# dds.exe is staged into the same DIR_BIN directory as this script (see
# CG_Watchdog / CG_DdsCli in DdsBundle.wxs). Resolve relative to
# $PSScriptRoot rather than relying on PATH: a SYSTEM Scheduled Task's
# process environment may not yet reflect the machine PATH entry
# (E_PathDdsBin) added by the same MSI transaction that installs this
# script, particularly right after a fresh install/upgrade.
$ddsExe = Join-Path $PSScriptRoot "dds.exe"

# -- Pure helpers (side-effect free, unit-tested by Watchdog-DdsNode.Tests.ps1) --

function Get-PropOrNull {
    # Strict-mode-safe property read: returns the property value or $null if
    # the property is absent (Set-StrictMode -Version Latest throws on a bare
    # reference to a non-existent property, so callers must go through this).
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-PrunedHistory {
    # Return the subset of $History (ISO-8601 strings and/or [datetime]s)
    # strictly newer than $WindowHours before $NowUtc, normalised to ISO
    # "o" UTC strings. Unparseable entries are dropped (cannot prove recent).
    param(
        [object[]]$History,
        [Parameter(Mandatory)] [datetime]$NowUtc,
        [int]$WindowHours = 24
    )
    $cutoff = $NowUtc.ToUniversalTime().AddHours(-$WindowHours)
    $kept = @()
    if ($null -ne $History) {
        foreach ($entry in $History) {
            if ($null -eq $entry) { continue }
            $dt = $null
            try {
                if ($entry -is [datetime]) {
                    $dt = ([datetime]$entry).ToUniversalTime()
                } else {
                    $dt = [datetime]::Parse(
                        [string]$entry,
                        [System.Globalization.CultureInfo]::InvariantCulture,
                        [System.Globalization.DateTimeStyles]::RoundtripKind
                    ).ToUniversalTime()
                }
            } catch {
                continue
            }
            if ($dt -gt $cutoff) {
                $kept += ,$dt.ToString("o")
            }
        }
    }
    # Emit elements normally; every caller re-wraps with @(...) so an empty or
    # single-element result is normalised there. (Returning ,$kept here would
    # nest the array and inflate counts.)
    return $kept
}

function Get-WatchdogDecision {
    # The core decision. Pure: given the observed counts, the prior persisted
    # state, and the current time, it returns what to do WITHOUT touching the
    # service, the event log, or the state file.
    #
    # $Connected / $Admitted are [int] when the node's status could be read,
    # or $null when it could not (service down, malformed payload, or a
    # payload missing the expected fields) -- in which case the state is
    # "unknown" and the streak resets.
    #
    # Returns a pscustomobject:
    #   Action                -- 'none' | 'restart' | 'capped'
    #   ConsecutiveMismatches -- streak counter to persist
    #   RestartTimestampsUtc  -- rolling-24h restart history to persist
    #   PrevAdmitted          -- admitted_peers to remember for next poll
    #   Reason                -- human-readable explanation (logged verbatim)
    [CmdletBinding()]
    param(
        $Connected,
        $Admitted,
        [Parameter(Mandatory)] $PriorState,
        [datetime]$NowUtc = (Get-Date).ToUniversalTime(),
        [int]$RequiredConsecutiveMismatches = 3,
        [int]$MaxRestartsPer24h = 3
    )

    $now = $NowUtc.ToUniversalTime()

    $priorConsecutive = Get-PropOrNull $PriorState 'ConsecutiveMismatches'
    if ($null -eq $priorConsecutive) { $priorConsecutive = 0 } else { $priorConsecutive = [int]$priorConsecutive }

    $priorHistory      = Get-PropOrNull $PriorState 'RestartTimestampsUtc'
    $priorPrevAdmitted = Get-PropOrNull $PriorState 'PrevAdmitted'

    # The rolling-24h restart history is always pruned first, so it stays
    # bounded and current no matter which branch we take below.
    $pruned = @(Get-PrunedHistory -History $priorHistory -NowUtc $now)

    # -- Unknown: could not read the node's admission state this poll. --
    # Reset the streak but PRESERVE the (pruned) restart history and the last
    # known PrevAdmitted, so a transient outage cannot make us forget the cap
    # nor lose our churn baseline.
    if ($null -eq $Connected -or $null -eq $Admitted) {
        return [pscustomobject]@{
            Action                = 'none'
            ConsecutiveMismatches = 0
            RestartTimestampsUtc  = @($pruned)
            PrevAdmitted          = $priorPrevAdmitted
            Reason                = 'status unknown (node unreachable or admission fields absent); counter reset, restart history preserved'
        }
    }

    $connectedInt = [int]$Connected
    $admittedInt  = [int]$Admitted

    # A poll counts as a mismatch ONLY when connected exceeds admitted AND
    # admitted is not growing. If admitted rose since last poll (rolling
    # upgrade / normal admission churn) the node is making forward progress,
    # so we must not trip on it. When we have no prior baseline (first poll),
    # treat the baseline as +inf so a real stuck mismatch still counts.
    $prevAdmittedForCompare = if ($null -ne $priorPrevAdmitted) { [int]$priorPrevAdmitted } else { [int]::MaxValue }
    $isMismatch = ($connectedInt -gt $admittedInt) -and ($admittedInt -le $prevAdmittedForCompare)

    if (-not $isMismatch) {
        $reason = if ($connectedInt -le $admittedInt) {
            "connected ($connectedInt) <= admitted ($admittedInt); no mismatch, counter reset"
        } else {
            "connected ($connectedInt) > admitted ($admittedInt) but admitted rose past prior baseline ($prevAdmittedForCompare) -- progress, counter reset"
        }
        return [pscustomobject]@{
            Action                = 'none'
            ConsecutiveMismatches = 0
            RestartTimestampsUtc  = @($pruned)
            PrevAdmitted          = $admittedInt
            Reason                = $reason
        }
    }

    # Mismatch this poll -- advance the streak.
    $consecutive = $priorConsecutive + 1

    if ($consecutive -lt $RequiredConsecutiveMismatches) {
        return [pscustomobject]@{
            Action                = 'none'
            ConsecutiveMismatches = $consecutive
            RestartTimestampsUtc  = @($pruned)
            PrevAdmitted          = $admittedInt
            Reason                = "connected ($connectedInt) > admitted ($admittedInt); consecutive mismatch $consecutive of $RequiredConsecutiveMismatches"
        }
    }

    # -- Threshold reached. Restart, unless the rolling-24h cap is spent. --
    $recentRestarts = @($pruned).Count
    if ($recentRestarts -ge $MaxRestartsPer24h) {
        # Cap hit: a restart is evidently not curing the mismatch. Stop
        # bouncing the service; leave the counter unchanged (no reset so we
        # keep re-evaluating, no climb so it does not grow unbounded) and
        # escalate to the operator.
        return [pscustomobject]@{
            Action                = 'capped'
            ConsecutiveMismatches = $priorConsecutive
            RestartTimestampsUtc  = @($pruned)
            PrevAdmitted          = $admittedInt
            Reason                = "connected ($connectedInt) > admitted ($admittedInt) for $consecutive consecutive polls, but $recentRestarts restart(s) already occurred within the last 24h (max $MaxRestartsPer24h); giving up after repeated restarts -- operator intervention required"
        }
    }

    $newHistory = @($pruned) + @($now.ToString("o"))
    return [pscustomobject]@{
        Action                = 'restart'
        ConsecutiveMismatches = 0
        RestartTimestampsUtc  = @($newHistory)
        PrevAdmitted          = $admittedInt
        Reason                = "connected ($connectedInt) > admitted ($admittedInt) for $consecutive consecutive polls; restarting the service (restart $(@($newHistory).Count) within the last 24h)"
    }
}

# -- Side-effecting shell (untested; a thin dispatcher over the decision) --

function Write-WatchdogEvent {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [System.Diagnostics.EventLogEntryType]$EntryType = [System.Diagnostics.EventLogEntryType]::Information,
        [int]$EventId = 1000
    )
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
            New-EventLog -LogName Application -Source $EventSource -ErrorAction Stop
        }
        Write-EventLog -LogName Application -Source $EventSource -EntryType $EntryType -EventId $EventId -Message $Message
    } catch {
        # Event Log registration/write failure (locked-down Application
        # log, race with a concurrent instance also registering the
        # source, etc.) must never block the actual watchdog decision --
        # the service restart below is the load-bearing action, logging
        # is best-effort observability on top of it.
    }
}

function Read-WatchdogState {
    # Load persisted state as a pscustomobject with the three fields the
    # decision needs. Any missing file / corrupt JSON / absent field degrades
    # to a safe default rather than failing the poll.
    $default = [pscustomobject]@{
        ConsecutiveMismatches = 0
        RestartTimestampsUtc  = @()
        PrevAdmitted          = $null
    }
    if (-not (Test-Path -LiteralPath $StateFile)) { return $default }
    try {
        $raw = Get-Content -LiteralPath $StateFile -Raw -ErrorAction Stop
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $default
    }
    $cm   = Get-PropOrNull $obj 'ConsecutiveMismatches'
    $hist = Get-PropOrNull $obj 'RestartTimestampsUtc'
    $prev = Get-PropOrNull $obj 'PrevAdmitted'
    return [pscustomobject]@{
        ConsecutiveMismatches = if ($null -ne $cm) { [int]$cm } else { 0 }
        RestartTimestampsUtc  = @($hist)
        PrevAdmitted          = if ($null -ne $prev) { [int]$prev } else { $null }
    }
}

function Write-WatchdogState {
    param([Parameter(Mandatory)] $Decision)
    $dir = Split-Path -Path $StateFile -Parent
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [pscustomobject]@{
        ConsecutiveMismatches = $Decision.ConsecutiveMismatches
        RestartTimestampsUtc  = @($Decision.RestartTimestampsUtc)
        PrevAdmitted          = $Decision.PrevAdmitted
        LastCheckedUtc        = (Get-Date).ToUniversalTime().ToString("o")
    } | ConvertTo-Json | Set-Content -LiteralPath $StateFile -Encoding UTF8
}

function Invoke-WatchdogDecision {
    # Thin executor: dispatches on $Decision.Action. Restart and event-log
    # writes are injected as scriptblocks so the tests can mock them and
    # assert no real service is ever touched.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Decision,
        [string]$ServiceName = "DdsNode",
        [scriptblock]$RestartAction = { param($svc) Restart-Service -Name $svc -Force -ErrorAction Stop },
        [scriptblock]$EventWriter   = { param($msg, $type, $id) Write-WatchdogEvent -Message $msg -EntryType $type -EventId $id }
    )
    switch ($Decision.Action) {
        'restart' {
            try {
                & $RestartAction $ServiceName
                & $EventWriter $Decision.Reason ([System.Diagnostics.EventLogEntryType]::Warning) 1000
            } catch {
                & $EventWriter "$($Decision.Reason) -- Restart-Service failed: $($_.Exception.Message)" ([System.Diagnostics.EventLogEntryType]::Error) 1001
            }
        }
        'capped' {
            & $EventWriter $Decision.Reason ([System.Diagnostics.EventLogEntryType]::Error) 1002
        }
        default {
            # 'none' -- nothing to do beyond the state already persisted.
        }
    }
}

# -- Main body ----------------------------------------------------------
# Skipped when the script is dot-sourced (InvocationName '.') so the test
# suite can load the functions above without polling or restarting anything.
if ($MyInvocation.InvocationName -ne '.') {

    if (-not (Test-Path -LiteralPath $ddsExe)) {
        # Nothing to poll with. A missing binary is an installer/staging
        # problem, not a peer-admission problem -- don't touch state, just
        # exit quietly and let the next poll try again.
        exit 0
    }

    # Poll the node. Any inability to read a well-formed status with the
    # expected admission fields leaves $connected/$admitted at $null, which
    # the decision treats as UNKNOWN.
    $connected = $null
    $admitted  = $null

    # Avoid `2>&1`: on a native command that merges stderr into an
    # ErrorRecord-wrapped stream even on a clean exit. `2>$null` discards
    # stderr text without affecting $LASTEXITCODE.
    $raw = & $ddsExe stats --format json 2>$null
    $exitCode = $LASTEXITCODE

    if ($exitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($raw)) {
        try {
            $status = $raw | ConvertFrom-Json -ErrorAction Stop
            # Presence-tested extraction: under Set-StrictMode -Version Latest
            # a bare `$status.node.admitted_peers` throws if any hop is absent.
            # A payload missing `node`, `connected_peers`, or `admitted_peers`
            # (e.g. a much older node build) is UNKNOWN, not a mismatch.
            $node         = Get-PropOrNull $status 'node'
            $connectedRaw = Get-PropOrNull $node 'connected_peers'
            $admittedRaw  = Get-PropOrNull $node 'admitted_peers'
            if ($null -ne $connectedRaw) { $connected = [int]$connectedRaw }
            if ($null -ne $admittedRaw)  { $admitted  = [int]$admittedRaw }
        } catch {
            # Malformed/unexpected JSON -- leave both $null (UNKNOWN).
            $connected = $null
            $admitted  = $null
        }
    }

    $prior    = Read-WatchdogState
    $now      = (Get-Date).ToUniversalTime()
    $decision = Get-WatchdogDecision `
        -Connected $connected `
        -Admitted $admitted `
        -PriorState $prior `
        -NowUtc $now `
        -RequiredConsecutiveMismatches $RequiredConsecutiveMismatches `
        -MaxRestartsPer24h $MaxRestartsPer24h

    # Persist first (so a recorded restart timestamp counts toward the cap
    # even if the restart attempt below fails), then act.
    Write-WatchdogState -Decision $decision
    Invoke-WatchdogDecision -Decision $decision -ServiceName $ServiceName
}
