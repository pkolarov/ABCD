#!/bin/zsh
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  collect-summary.sh --node-url <URL> [--machine-id <ID>] [--run-root <DIR>]
EOF
}

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR}/../../.."
E2E_BIN="${REPO_ROOT}/target/debug/dds-macos-e2e"
RUN_ROOT="/tmp/dds-macos-e2e"
NODE_URL=""
MACHINE_ID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --node-url) NODE_URL="$2"; shift 2 ;;
    --machine-id) MACHINE_ID="$2"; shift 2 ;;
    --run-root) RUN_ROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "${NODE_URL}" ]] || { echo "--node-url is required" >&2; exit 2; }
[[ -x "${E2E_BIN}" ]] || { echo "Missing e2e binary at ${E2E_BIN}" >&2; exit 1; }
[[ -f "${RUN_ROOT}/manifest.json" ]] || { echo "Missing ${RUN_ROOT}/manifest.json" >&2; exit 1; }
[[ -f "${RUN_ROOT}/device-urn.txt" ]] || { echo "Missing ${RUN_ROOT}/device-urn.txt" >&2; exit 1; }

if [[ -z "${MACHINE_ID}" && -f "${RUN_ROOT}/machine.env" ]]; then
  MACHINE_ID="$(awk -F= '/^MACHINE_ID=/{ print $2 }' "${RUN_ROOT}/machine.env")"
fi
[[ -n "${MACHINE_ID}" ]] || MACHINE_ID="$(hostname)"

"${E2E_BIN}" collect \
  --manifest "${RUN_ROOT}/manifest.json" \
  --machine-id "${MACHINE_ID}" \
  --node-url "${NODE_URL}" \
  --device-urn-file "${RUN_ROOT}/device-urn.txt" \
  --state-dir "${RUN_ROOT}/state" \
  --managed-preferences-dir "${RUN_ROOT}/ManagedPreferences" \
  --launchd-state-file "${RUN_ROOT}/state/launchd-state.json" \
  --out "${RUN_ROOT}/summary-${MACHINE_ID}.json"

echo "${RUN_ROOT}/summary-${MACHINE_ID}.json"
