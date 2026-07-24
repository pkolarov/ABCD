#!/usr/bin/env bash
# DDS Node Watchdog — external backstop for stuck peer admission.
#
# Linux port of platform/windows/installer/scripts/Watchdog-DdsNode.ps1
# (watchdog plan Step 7); see also the macOS twin,
# platform/macos/packaging/helpers/dds-watchdog.sh. Run every 5 minutes
# by dds-watchdog.timer (OnUnitActiveSec=5min).
#
# Root cause this backstops: a peer can stay libp2p-connected but never
# complete the H-12 admission handshake. The in-process fix
# (DdsNode::retry_unadmitted_peers, ~60s anti-entropy tick) handles the
# primary case; this external watchdog only fires after that retry has
# itself failed for ~15 minutes (3 consecutive 5-minute polls), and
# restarts are capped at 3 per rolling 24h before escalating to the
# operator instead of bouncing the service forever.
#
# Decision-state parity with the Windows script:
#   * UNKNOWN (node unreachable / fields absent) resets the streak but
#     preserves the pruned restart history and the admitted baseline.
#   * A poll only counts as a mismatch when connected > admitted AND
#     admitted is not growing (progress guard; first poll baseline +inf).
#   * State is persisted BEFORE the restart is attempted, so a restart
#     that fails still counts toward the 24h cap.
#
# State: /var/lib/dds/watchdog-state.json
# Logs:  journal via logger -t dds-watchdog (Warning on restart, Error
#        on restart-failure or cap-hit — mirrors EventIds 1000/1001/1002).
set -uo pipefail

DATA_DIR="/var/lib/dds"
API_SOCK="${DATA_DIR}/dds.sock"
STATE_FILE="${DATA_DIR}/watchdog-state.json"
REQUIRED_CONSECUTIVE="${DDS_WATCHDOG_REQUIRED_CONSECUTIVE:-3}"
MAX_RESTARTS_24H="${DDS_WATCHDOG_MAX_RESTARTS_24H:-3}"
RESTART_CMD=(systemctl restart dds-node.service)

CONNECTED=""
ADMITTED=""
STATUS_JSON="$(curl -sf --max-time 10 --unix-socket "${API_SOCK}" "http://localhost/v1/status" 2>/dev/null)" || STATUS_JSON=""
if [[ -n "${STATUS_JSON}" ]]; then
  PARSED="$(printf '%s' "${STATUS_JSON}" | python3 -c '
import sys, json
try:
    s = json.load(sys.stdin)
    c = s.get("connected_peers")
    a = s.get("admitted_peers")
    if isinstance(c, int) and isinstance(a, int):
        print(f"{c} {a}")
except Exception:
    pass
' 2>/dev/null)" || PARSED=""
  if [[ -n "${PARSED}" ]]; then
    CONNECTED="${PARSED%% *}"
    ADMITTED="${PARSED##* }"
  fi
fi

# Pure decision + state persistence (port of Get-WatchdogDecision).
# Prints "<action>\t<reason>" and writes the new state file; the shell
# below only dispatches the action. Keep this python block in lockstep
# with the macOS twin.
DECISION_TMP="$(mktemp /tmp/dds-watchdog-decision.XXXXXX)"
trap 'rm -f "${DECISION_TMP}"' EXIT
STATE_FILE="${STATE_FILE}" \
CONNECTED="${CONNECTED}" \
ADMITTED="${ADMITTED}" \
REQUIRED_CONSECUTIVE="${REQUIRED_CONSECUTIVE}" \
MAX_RESTARTS_24H="${MAX_RESTARTS_24H}" \
python3 > "${DECISION_TMP}" <<'PYEOF'
import json, os, sys
from datetime import datetime, timedelta, timezone

state_file = os.environ["STATE_FILE"]
required = int(os.environ["REQUIRED_CONSECUTIVE"])
cap = int(os.environ["MAX_RESTARTS_24H"])
connected_raw = os.environ.get("CONNECTED", "")
admitted_raw = os.environ.get("ADMITTED", "")

now = datetime.now(timezone.utc)

# Load prior state; any missing/corrupt file degrades to safe defaults.
prior = {}
try:
    with open(state_file) as f:
        prior = json.load(f)
    if not isinstance(prior, dict):
        prior = {}
except Exception:
    prior = {}

prior_consecutive = prior.get("consecutive_mismatches")
prior_consecutive = int(prior_consecutive) if isinstance(prior_consecutive, (int, float)) else 0
prior_history = prior.get("restart_timestamps_utc")
prior_history = prior_history if isinstance(prior_history, list) else []
prior_prev_admitted = prior.get("prev_admitted")
prior_prev_admitted = int(prior_prev_admitted) if isinstance(prior_prev_admitted, (int, float)) else None

# Prune the rolling-24h restart history first (always, every branch).
cutoff = now - timedelta(hours=24)
pruned = []
for entry in prior_history:
    try:
        dt = datetime.fromisoformat(str(entry).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt > cutoff:
            pruned.append(dt.astimezone(timezone.utc).isoformat())
    except Exception:
        continue  # unparseable: cannot prove recent, drop

def emit(action, consecutive, history, prev_admitted, reason):
    state = {
        "consecutive_mismatches": consecutive,
        "restart_timestamps_utc": history,
        "prev_admitted": prev_admitted,
        "last_checked_utc": now.isoformat(),
    }
    tmp = state_file + ".tmp"
    os.makedirs(os.path.dirname(state_file), exist_ok=True)
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, state_file)
    sys.stdout.write(f"{action}\t{reason}\n")
    sys.exit(0)

# UNKNOWN: reset streak, preserve pruned history + admitted baseline.
if not connected_raw or not admitted_raw:
    emit("none", 0, pruned, prior_prev_admitted,
         "status unknown (node unreachable or admission fields absent); "
         "counter reset, restart history preserved")

connected = int(connected_raw)
admitted = int(admitted_raw)

# Mismatch only when connected exceeds admitted AND admitted is not
# growing (first poll: baseline +inf so a real stuck mismatch counts).
prev_for_compare = prior_prev_admitted if prior_prev_admitted is not None else float("inf")
is_mismatch = connected > admitted and admitted <= prev_for_compare

if not is_mismatch:
    if connected <= admitted:
        reason = f"connected ({connected}) <= admitted ({admitted}); no mismatch, counter reset"
    else:
        reason = (f"connected ({connected}) > admitted ({admitted}) but admitted rose past "
                  f"prior baseline ({prev_for_compare}) -- progress, counter reset")
    emit("none", 0, pruned, admitted, reason)

consecutive = prior_consecutive + 1

if consecutive < required:
    emit("none", consecutive, pruned, admitted,
         f"connected ({connected}) > admitted ({admitted}); "
         f"consecutive mismatch {consecutive} of {required}")

if len(pruned) >= cap:
    # Cap hit: restarts evidently aren't curing it. Keep the counter
    # unchanged (no reset so we keep re-evaluating, no climb so it
    # doesn't grow unbounded); escalate to the operator.
    emit("capped", prior_consecutive, pruned, admitted,
         f"connected ({connected}) > admitted ({admitted}) for {consecutive} consecutive "
         f"polls, but {len(pruned)} restart(s) already occurred within the last 24h "
         f"(max {cap}); giving up after repeated restarts -- operator intervention required")

new_history = pruned + [now.isoformat()]
emit("restart", 0, new_history, admitted,
     f"connected ({connected}) > admitted ({admitted}) for {consecutive} consecutive "
     f"polls; restarting the service (restart {len(new_history)} within the last 24h)")
PYEOF

DECISION="$(cat "${DECISION_TMP}")"
ACTION="${DECISION%%	*}"
REASON="${DECISION#*	}"

case "${ACTION}" in
  restart)
    if "${RESTART_CMD[@]}" 2>/dev/null; then
      logger -t dds-watchdog -p user.warning "${REASON}"
    else
      logger -t dds-watchdog -p user.err "${REASON} -- restart command failed"
    fi
    ;;
  capped)
    logger -t dds-watchdog -p user.err "${REASON}"
    ;;
  *)
    ;;
esac
exit 0
