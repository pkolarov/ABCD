#!/bin/zsh
# DDS Verify Replication — health + replication check for a live node.
#
# macOS/shell port of
# platform/windows/installer/scripts/Verify-DdsReplication.ps1. Safe to
# run on a live installed node (talks to the dds-api Unix socket).
# Non-mutating by default; pass --enroll-test to mint a throwaway test
# device and confirm it replicates to a peer.
#
#   dds-verify-replication [--enroll-test]
set -euo pipefail

DDS_ROOT="/Library/Application Support/DDS"
API_SOCK="${DDS_ROOT}/dds.sock"
NODE_DATA="${DDS_ROOT}/node-data"
ADMISSION_CERT="${NODE_DATA}/admission.cbor"
LOG_OUT="/var/log/dds/dds-node.out"

ENROLL_TEST=0
for arg in "$@"; do
  case "${arg}" in
    --enroll-test) ENROLL_TEST=1 ;;
    *) echo "Unknown argument: ${arg}" >&2; exit 2 ;;
  esac
done

if [[ ! -S "${API_SOCK}" ]]; then
  echo "  dds-api socket not found at ${API_SOCK} — is dds-node running?"
  exit 1
fi

# The data dir is 0700 root:root, so a non-root run cannot stat the
# admission cert or read the config. Warn once up front rather than
# emitting confusing "not joined to a domain?" findings below.
if [[ $EUID -ne 0 ]]; then
  echo "NOTE: not running as root — checks that read ${NODE_DATA} will be skipped."
  echo "      Re-run with sudo for the full report."
  echo ""
fi

echo "=== DDS node health ($(hostname -s)) ==="
# dds-node has no --version flag; take the version from the Mach-O
# binary's own build info instead of printing a bogus "unknown".
# `|| true`: grep exits 1 when the binary prints no version string, and
# under `set -euo pipefail` a failing substitution in an assignment
# aborts the whole script.
NODE_VER="$(/usr/local/bin/dds-node 2>&1 | grep -oE 'dds-node [0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
if [[ -z "${NODE_VER}" ]]; then
  NODE_VER="$(stat -f '%Sm' -t '%Y-%m-%d %H:%M' /usr/local/bin/dds-node 2>/dev/null || echo unknown)"
  NODE_VER="built ${NODE_VER}"
fi
echo "  dds-node       : ${NODE_VER}"
curl -sf --unix-socket "${API_SOCK}" "http://localhost/v1/status" | python3 -c "
import sys, json
s = json.load(sys.stdin)
print(f\"  tokens (graph) : {s.get('trust_graph_tokens')}\")
print(f\"  store tokens   : {s.get('store_tokens')}\")
print(f\"  trusted roots  : {s.get('trusted_roots')}\")
print(f\"  connected peers: {s.get('connected_peers')}\")
"
CONNECTED_PEERS="$(curl -sf --unix-socket "${API_SOCK}" "http://localhost/v1/status" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("connected_peers", 0))')"

echo ""
echo "=== enc-v3 KEM self-repair ==="
if [[ ! -r "${ADMISSION_CERT}" && $EUID -ne 0 ]]; then
  echo "  skipped (needs root to read ${NODE_DATA})"
elif [[ -f "${ADMISSION_CERT}" ]]; then
  if grep -a -q "pq_kem_pubkey" "${ADMISSION_CERT}"; then
    echo "  admission.cbor carries pq_kem_pubkey  [OK]"
  else
    echo "  admission.cbor has NO pq_kem_pubkey — self-repair has not run yet."
    echo "  (Restart the node once; it attaches the key at startup on hybrid domains.)"
  fi
else
  echo "  admission.cbor not found at ${ADMISSION_CERT} (node not joined to a domain?)"
fi

if [[ -f "${LOG_OUT}" ]]; then
  echo ""
  echo "=== recent log signals ($(basename "${LOG_OUT}")) ==="
  REPAIR="$(tail -n 4000 "${LOG_OUT}" | grep -E "pq_kem_pubkey was missing or stale|attached our" | tail -1 || true)"
  RECONCILE="$(tail -n 4000 "${LOG_OUT}" | grep "reconciled stored tokens" | tail -1 || true)"
  ERRLOOP="$(tail -n 4000 "${LOG_OUT}" | grep -E "err_count=[1-9]" | tail -3 || true)"
  [[ -n "${REPAIR}" ]] && echo "  self-repair : ${REPAIR}"
  [[ -n "${RECONCILE}" ]] && echo "  reconcile   : ${RECONCILE}"
  if [[ -n "${ERRLOOP}" ]]; then
    echo "  WARNING err_count>0 still present:"
    echo "${ERRLOOP}" | while IFS= read -r line; do echo "    ${line}"; done
  else
    echo "  no err_count>0 in recent log  [OK]"
  fi
fi

if [[ ${ENROLL_TEST} -eq 1 ]]; then
  echo ""
  echo "=== replication proof (test device enrollment) ==="
  if [[ "${CONNECTED_PEERS}" -lt 1 ]]; then
    echo "  No connected peer to confirm against — skip. Run on a box that sees a peer."
    exit 0
  fi
  SUFFIX="$(printf '%06x' $((RANDOM % 0xFFFFFF)))"
  BODY="{\"label\":\"repltest-${SUFFIX}\",\"device_id\":\"repltest-${SUFFIX}\",\"hostname\":\"$(hostname)\",\"os\":\"macOS\",\"os_version\":\"unknown\",\"tags\":[\"replication-test\"]}"
  ENROLL_RESP="$(curl -sf --unix-socket "${API_SOCK}" -X POST "http://localhost/v1/enroll/device" -H 'Content-Type: application/json' -d "${BODY}")"
  JTI="$(echo "${ENROLL_RESP}" | python3 -c 'import sys,json; print(json.load(sys.stdin)["jti"])')"
  PUBLISHED="$(echo "${ENROLL_RESP}" | python3 -c 'import sys,json; print(json.load(sys.stdin).get("published"))')"
  echo "  minted test token jti=${JTI} published=${PUBLISHED}"
  echo "  waiting 5s for gossip..."
  sleep 5
  curl -sf --unix-socket "${API_SOCK}" "http://localhost/v1/replication/confirm?jtis=${JTI}" | JTI="${JTI}" python3 -c "
import sys, json, os
p = json.load(sys.stdin)
jti = os.environ['JTI']
print(f\"  admitted_connected : {p.get('admitted_connected')}\")
confirmed = p.get('confirmed_jtis', [])
if jti in confirmed:
    print('  CONFIRMED replicated to a peer  [OK]')
else:
    inconclusive = [r for r in p.get('results', []) if r.get('error')]
    if inconclusive:
        print(f\"  INCONCLUSIVE (epoch key still settling): {inconclusive[0].get('error')}\")
        print('  Re-run in ~30s; the probe triggers the key exchange.')
    else:
        print('  NOT yet confirmed on any peer.')
"
  echo "  (This test token can be offboarded via dds-user; tag=replication-test.)"
fi
