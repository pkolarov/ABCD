#!/bin/zsh
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  publish-fixture.sh --domain-key <FILE> --domain-file <FILE> (--bootstrap-peer <MULTIADDR> | --bootstrap-peer-file <FILE>) [--run-root <DIR>]
EOF
}

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR}/../../.."
E2E_BIN="${REPO_ROOT}/target/debug/dds-macos-e2e"
RUN_ROOT="/tmp/dds-macos-e2e"
DOMAIN_KEY=""
DOMAIN_FILE=""
BOOTSTRAP_PEER=""
BOOTSTRAP_PEER_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain-key) DOMAIN_KEY="$2"; shift 2 ;;
    --domain-file) DOMAIN_FILE="$2"; shift 2 ;;
    --bootstrap-peer) BOOTSTRAP_PEER="$2"; shift 2 ;;
    --bootstrap-peer-file) BOOTSTRAP_PEER_FILE="$2"; shift 2 ;;
    --run-root) RUN_ROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -f "${DOMAIN_KEY}" ]] || { echo "Missing --domain-key" >&2; exit 2; }
[[ -f "${DOMAIN_FILE}" ]] || { echo "Missing --domain-file" >&2; exit 2; }
if [[ -z "${BOOTSTRAP_PEER}" && -n "${BOOTSTRAP_PEER_FILE}" ]]; then
  BOOTSTRAP_PEER="$(<"${BOOTSTRAP_PEER_FILE}")"
fi
[[ -n "${BOOTSTRAP_PEER}" ]] || { echo "Missing bootstrap peer" >&2; exit 2; }
[[ -x "${E2E_BIN}" ]] || { echo "Missing e2e binary at ${E2E_BIN}" >&2; exit 1; }

PACKAGE_ID="com.dds.e2e.marker"
[[ -f "${RUN_ROOT}/packages/${PACKAGE_ID}.pkg" ]] || { echo "Missing ${RUN_ROOT}/packages/${PACKAGE_ID}.pkg" >&2; exit 1; }
[[ -f "${RUN_ROOT}/packages/${PACKAGE_ID}.version" ]] || { echo "Missing ${RUN_ROOT}/packages/${PACKAGE_ID}.version" >&2; exit 1; }
[[ -f "${RUN_ROOT}/packages/${PACKAGE_ID}.sha256" ]] || { echo "Missing ${RUN_ROOT}/packages/${PACKAGE_ID}.sha256" >&2; exit 1; }
PACKAGE_VERSION="$(<"${RUN_ROOT}/packages/${PACKAGE_ID}.version")"
PACKAGE_SHA="$(<"${RUN_ROOT}/packages/${PACKAGE_ID}.sha256")"
PACKAGE_SOURCE="file://${RUN_ROOT}/packages/${PACKAGE_ID}.pkg"

"${E2E_BIN}" publish \
  --domain-key "${DOMAIN_KEY}" \
  --domain "${DOMAIN_FILE}" \
  --bootstrap-peer "${BOOTSTRAP_PEER}" \
  --org-hash dds-macos-e2e \
  --tag dds-macos-e2e \
  --policy-id e2e/macos-two-machine \
  --policy-version 1 \
  --package-id "${PACKAGE_ID}" \
  --package-display-name "DDS macOS E2E Marker" \
  --package-version "${PACKAGE_VERSION}" \
  --package-source "${PACKAGE_SOURCE}" \
  --package-sha256 "${PACKAGE_SHA}" \
  --preference-domain com.dds.e2e \
  --preference-key FleetMessage \
  --preference-value-json '"dds-macos-e2e"' \
  --launchd-label com.dds.e2e.marker \
  --launchd-plist-path "${RUN_ROOT}/LaunchDaemons/com.dds.e2e.marker.plist" \
  --launchd-marker-path "${RUN_ROOT}/launchd-fired.txt" \
  --package-marker-path "${RUN_ROOT}/install-root/software-installed.txt" \
  --out "${RUN_ROOT}/manifest.json"

echo "${RUN_ROOT}/manifest.json"
