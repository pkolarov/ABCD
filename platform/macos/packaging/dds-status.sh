#!/bin/zsh
# DDS Status — one-glance health + mesh monitor for a DDS node.
#
# The macOS/Linux answer to the Windows console's Health tab: services,
# API socket, node identity, mesh peers, readiness, on-disk state, and
# recent log signals — in one command, refreshable with --watch.
#
#   dds-status              one snapshot, human-readable
#   dds-status --watch      refresh every 2s until Ctrl-C
#   dds-status --watch 5    refresh every 5s
#   dds-status --json       machine-readable (services + /v1/status + /readyz)
#
# Safe on a live node: every call is read-only (GET) over the peer-cred
# UDS. Runs without sudo, but file-state and log checks need root to read
# the 0700 node-data dir — it says so rather than guessing.
set -uo pipefail

# Paths default to the packaged install layout but honor env overrides so
# the e2e harness (and non-standard installs) can point at a test node.
DDS_ROOT="${DDS_ROOT:-/Library/Application Support/DDS}"
API_SOCK="${DDS_API_SOCK:-${DDS_ROOT}/dds.sock}"
API_URL="http://localhost"
NODE_DATA="${DDS_NODE_DATA:-${DDS_ROOT}/node-data}"
NODE_BIN="${DDS_NODE_BIN:-/usr/local/bin/dds-node}"
LOG_OUT="${DDS_LOG_OUT:-/var/log/dds/dds-node.out}"

WATCH=0
INTERVAL=2
JSON=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --watch) WATCH=1; [[ "${2:-}" == <-> ]] && { INTERVAL="$2"; shift; } ;;
    --json)  JSON=1 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '2,12p'; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# curl the UDS; prints body on success, nothing on failure. Never aborts
# the script (callers tolerate an empty result and report it as such).
api() { curl -sf --max-time 5 --unix-socket "${API_SOCK}" "${API_URL}$1" 2>/dev/null || true; }

# Extract one field from a JSON object on stdin; empty string if absent.
jget() { python3 -c "import sys,json
try: print(json.load(sys.stdin).get('$1',''))
except Exception: pass" 2>/dev/null || true; }

svc_state() {
  # macOS launchd: 'running' / 'not running' / 'not loaded'. Note: `status`
  # is a read-only special in zsh, so locals here avoid that name.
  local label="$1" out
  out="$(launchctl print "system/${label}" 2>/dev/null || true)"
  if [[ -z "${out}" ]]; then echo "not loaded"; return; fi
  # Capture everything after "state = " (keeps internal spaces like
  # "not running"); trim the trailing whitespace awk leaves.
  echo "${out}" | awk -F'state = ' '/state = /{sub(/[ \t]+$/,"",$2); print $2; exit}'
}

emit_json() {
  DDS_NODE_STATE="$(svc_state com.dds.node)" \
  DDS_PA_STATE="$(svc_state com.dds.policyagent)" \
  DDS_WD_STATE="$(svc_state com.dds.watchdog)" \
  SOCK_PRESENT="$([[ -S "${API_SOCK}" ]] && echo true || echo false)" \
  DDS_STATUS_JSON="$(api /v1/status)" \
  DDS_READYZ_JSON="$(api /readyz)" \
  python3 -c "
import json, os, sys
def load(s):
    try: return json.loads(s)
    except Exception: return None
out = {
  'services': {
    'dds-node': os.environ['DDS_NODE_STATE'],
    'dds-policy-agent': os.environ['DDS_PA_STATE'],
    'dds-watchdog': os.environ['DDS_WD_STATE'],
  },
  'api_socket_present': os.environ['SOCK_PRESENT'] == 'true',
  'status': load(os.environ.get('DDS_STATUS_JSON', '')),
  'readyz': load(os.environ.get('DDS_READYZ_JSON', '')),
}
json.dump(out, sys.stdout, indent=2); print()
"
}

render() {
  local host; host="$(hostname -s)"
  echo "=== DDS status — ${host} — $(date '+%Y-%m-%d %H:%M:%S') ==="

  # --- node version + services ---
  local nver
  nver="$("${NODE_BIN}" version 2>/dev/null | grep -oE 'dds-node [0-9.]+' | head -1 || true)"
  echo "  node binary   : ${nver:-unknown}"
  printf "  services      : node=%s  policy-agent=%s  watchdog=%s\n" \
    "$(svc_state com.dds.node)" "$(svc_state com.dds.policyagent)" "$(svc_state com.dds.watchdog)"

  # --- API socket ---
  if [[ -S "${API_SOCK}" ]]; then
    echo "  api socket    : OPEN (${API_SOCK})"
  else
    echo "  api socket    : CLOSED — dds-node not serving (${API_SOCK})"
    echo ""
    echo "  Node is not reachable; nothing more to report. Start it with:"
    echo "    sudo launchctl kickstart -k system/com.dds.node"
    return
  fi

  # --- node identity ---
  local info nurn pid
  info="$(api /v1/node/info)"
  nurn="$(printf '%s' "${info}" | jget node_urn)"
  pid="$(printf '%s' "${info}" | jget peer_id)"
  [[ -n "${nurn}" ]] && echo "  node urn      : ${nurn}"
  [[ -n "${pid}" ]] && echo "  peer id       : ${pid}"

  # --- mesh / store --- (`status` is a read-only special in zsh)
  local nstatus
  nstatus="$(api /v1/status)"
  if [[ -n "${nstatus}" ]]; then
    printf '%s' "${nstatus}" | python3 -c "
import sys, json
try: s = json.load(sys.stdin)
except Exception: sys.exit(0)
conn = s.get('connected_peers', 0); adm = s.get('admitted_peers', 0)
stuck = max(conn - adm, 0)
flag = '  <- ' + str(stuck) + ' connected but NOT admitted' if stuck else ''
print(f'  peers         : {conn} connected, {adm} admitted{flag}')
print(f'  trusted roots : {s.get(\"trusted_roots\", 0)} (admins this node trusts)')
print(f'  tokens        : {s.get(\"trust_graph_tokens\", 0)} in graph, {s.get(\"store_tokens\", 0)} in store, {s.get(\"store_revoked\", 0)} revoked')
up = s.get('uptime_secs', 0)
print(f'  uptime        : {up//3600}h{(up%3600)//60}m')
ts = s.get('last_admission_failure_ts')
if ts: print(f'  last adm fail : unix {ts} (a peer failed the admission handshake)')
"
  else
    echo "  mesh          : /v1/status did not respond"
  fi

  # --- readiness ---
  local readyz
  readyz="$(api /readyz)"
  if [[ -n "${readyz}" ]]; then
    printf '%s' "${readyz}" | python3 -c "
import sys, json
try: r = json.load(sys.stdin)
except Exception: sys.exit(0)
c = r.get('checks', {})
print(f'  readiness     : {\"READY\" if r.get(\"ready\") else \"NOT READY\"} (store={c.get(\"store\")}, peers={c.get(\"peers\")})')
"
  fi

  # --- on-disk state inventory (needs root to read 0700 node-data) ---
  echo ""
  if [[ $EUID -ne 0 ]]; then
    echo "  state files   : (re-run with sudo to inventory ${NODE_DATA})"
  else
    local found=()
    for pair in \
      "${NODE_DATA}/domain.toml:domain.toml" \
      "${NODE_DATA}/domain_key.bin:domain_key.bin" \
      "${NODE_DATA}/admission.cbor:admission.cbor" \
      "${DDS_ROOT}/dds.toml:dds.toml" \
      "${DDS_ROOT}/provision.dds:provision.dds"; do
      [[ -e "${pair%%:*}" ]] && found+=("${pair##*:}")
    done
    if (( ${#found[@]} )); then echo "  state files   : ${(j:, :)found}"; else echo "  state files   : (none present)"; fi
  fi

  # --- recent log signals ---
  if [[ -r "${LOG_OUT}" ]]; then
    local errloop
    errloop="$(tail -n 2000 "${LOG_OUT}" 2>/dev/null | grep -E "err_count=[1-9]" | tail -1 || true)"
    if [[ -n "${errloop}" ]]; then
      echo "  log signal    : WARNING err_count>0 — ${errloop}"
    else
      echo "  log signal    : no err_count>0 in recent log  [OK]"
    fi
  fi
}

if [[ ${JSON} -eq 1 ]]; then
  emit_json
  exit 0
fi

if [[ ${WATCH} -eq 1 ]]; then
  trap 'echo; exit 0' INT
  while true; do
    clear 2>/dev/null || true
    render
    echo ""
    echo "  (refreshing every ${INTERVAL}s — Ctrl-C to stop)"
    sleep "${INTERVAL}"
  done
else
  render
fi
