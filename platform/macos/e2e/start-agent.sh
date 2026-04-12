#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR}/../../.."
AGENT_DLL="${REPO_ROOT}/platform/macos/DdsPolicyAgent/bin/Debug/net9.0/DdsPolicyAgent.MacOS.dll"
RUN_ROOT="/tmp/dds-macos-e2e"
DOTNET_BIN="$(command -v dotnet)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-root) RUN_ROOT="$2"; shift 2 ;;
    --agent-dll) AGENT_DLL="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: start-agent.sh [--run-root <DIR>] [--agent-dll <DLL>]"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -f "${RUN_ROOT}/agent.env" ]] || { echo "Missing ${RUN_ROOT}/agent.env" >&2; exit 1; }
[[ -f "${AGENT_DLL}" ]] || { echo "Missing agent dll at ${AGENT_DLL}" >&2; exit 1; }
[[ -n "${DOTNET_BIN}" ]] || { echo "dotnet not found" >&2; exit 1; }

typeset -a ENV_ARGS
while IFS='=' read -r key value; do
  [[ -z "${key}" ]] && continue
  ENV_ARGS+=("${key}=${value}")
done < "${RUN_ROOT}/agent.env"

nohup sudo env "${ENV_ARGS[@]}" "${DOTNET_BIN}" "${AGENT_DLL}" > "${RUN_ROOT}/logs/agent.log" 2>&1 &
echo $! > "${RUN_ROOT}/agent.pid"
echo "agent_started"
