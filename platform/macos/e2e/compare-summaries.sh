#!/bin/zsh
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  compare-summaries.sh --summary-a <FILE> --summary-b <FILE> [--out <FILE>]
EOF
}

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR}/../../.."
E2E_BIN="${REPO_ROOT}/target/debug/dds-macos-e2e"
SUMMARY_A=""
SUMMARY_B=""
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-a) SUMMARY_A="$2"; shift 2 ;;
    --summary-b) SUMMARY_B="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -f "${SUMMARY_A}" ]] || { echo "Missing --summary-a" >&2; exit 2; }
[[ -f "${SUMMARY_B}" ]] || { echo "Missing --summary-b" >&2; exit 2; }
[[ -x "${E2E_BIN}" ]] || { echo "Missing e2e binary at ${E2E_BIN}" >&2; exit 1; }

ARGS=( compare --summary-a "${SUMMARY_A}" --summary-b "${SUMMARY_B}" )
if [[ -n "${OUT}" ]]; then
  ARGS+=( --out "${OUT}" )
fi

"${E2E_BIN}" "${ARGS[@]}"
