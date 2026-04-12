#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR}/../../.."
NODE_BIN="${REPO_ROOT}/target/debug/dds-node"
RUN_ROOT="/tmp/dds-macos-e2e"
API_PORT="5551"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-root) RUN_ROOT="$2"; shift 2 ;;
    --api-port) API_PORT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: start-node.sh [--run-root <DIR>] [--api-port <PORT>]"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -x "${NODE_BIN}" ]] || { echo "Missing dds-node binary at ${NODE_BIN}" >&2; exit 1; }
[[ -f "${RUN_ROOT}/dds.toml" ]] || { echo "Missing ${RUN_ROOT}/dds.toml" >&2; exit 1; }

nohup "${NODE_BIN}" run "${RUN_ROOT}/dds.toml" > "${RUN_ROOT}/logs/node.log" 2>&1 &
echo $! > "${RUN_ROOT}/node.pid"

for _ in {1..40}; do
  if curl -sf "http://127.0.0.1:${API_PORT}/v1/status" >/dev/null 2>&1; then
    echo "node_started"
    exit 0
  fi
  sleep 1
done

echo "Node did not become ready; see ${RUN_ROOT}/logs/node.log" >&2
exit 1
