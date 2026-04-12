#!/bin/zsh
set -euo pipefail

RUN_ROOT="/tmp/dds-macos-e2e"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-root) RUN_ROOT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: cleanup-machine.sh [--run-root <DIR>]"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -f "${RUN_ROOT}/agent.pid" ]]; then
  kill "$(cat "${RUN_ROOT}/agent.pid")" 2>/dev/null || true
fi
if [[ -f "${RUN_ROOT}/node.pid" ]]; then
  kill "$(cat "${RUN_ROOT}/node.pid")" 2>/dev/null || true
fi

sudo launchctl bootout system/com.dds.e2e.marker >/dev/null 2>&1 || true
sudo pkgutil --forget com.dds.e2e.marker >/dev/null 2>&1 || true
rm -rf "${RUN_ROOT}"
