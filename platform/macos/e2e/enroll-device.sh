#!/bin/zsh
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  enroll-device.sh --machine-id <ID> --node-url <URL> [--run-root <DIR>] [--org-unit <OU>]
EOF
}

RUN_ROOT="/tmp/dds-macos-e2e"
ORG_UNIT="macos-e2e"
MACHINE_ID=""
NODE_URL=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --machine-id) MACHINE_ID="$2"; shift 2 ;;
    --node-url) NODE_URL="$2"; shift 2 ;;
    --run-root) RUN_ROOT="$2"; shift 2 ;;
    --org-unit) ORG_UNIT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "${MACHINE_ID}" ]] || { echo "--machine-id is required" >&2; exit 2; }
[[ -n "${NODE_URL}" ]] || { echo "--node-url is required" >&2; exit 2; }

HOSTNAME_VALUE="$(hostname)"
DEVICE_ID="DDS-MACOS-E2E-${MACHINE_ID:u}"
RESP_JSON="${RUN_ROOT}/enroll-device.json"

curl -sSf \
  -X POST "${NODE_URL%/}/v1/enroll/device" \
  -H 'Content-Type: application/json' \
  -d @- > "${RESP_JSON}" <<EOF
{
  "label": "${MACHINE_ID}",
  "device_id": "${DEVICE_ID}",
  "hostname": "${HOSTNAME_VALUE}",
  "os": "macOS",
  "os_version": "$(sw_vers -productVersion)",
  "tpm_ek_hash": null,
  "org_unit": "${ORG_UNIT}",
  "tags": ["dds-macos-e2e", "${MACHINE_ID}"]
}
EOF

DEVICE_URN="$(plutil -extract urn raw -o - "${RESP_JSON}")"
echo "${DEVICE_URN}" > "${RUN_ROOT}/device-urn.txt"

cat > "${RUN_ROOT}/agent.env" <<EOF
DdsPolicyAgent__DeviceUrn=${DEVICE_URN}
DdsPolicyAgent__NodeBaseUrl=${NODE_URL%/}
DdsPolicyAgent__PollIntervalSeconds=10
DdsPolicyAgent__StateDir=${RUN_ROOT}/state
DdsPolicyAgent__ManagedPreferencesDir=${RUN_ROOT}/ManagedPreferences
DdsPolicyAgent__UserTemplatePreferencesDir=${RUN_ROOT}/UserTemplatePreferences
DdsPolicyAgent__LaunchDaemonPlistDir=${RUN_ROOT}/LaunchDaemons
DdsPolicyAgent__LaunchAgentPlistDir=${RUN_ROOT}/LaunchAgents
DdsPolicyAgent__LaunchdDomain=system
DdsPolicyAgent__LaunchdStateFile=${RUN_ROOT}/state/launchd-state.json
DdsPolicyAgent__PackageCacheDir=${RUN_ROOT}/packages
DdsPolicyAgent__ProfileStateDir=${RUN_ROOT}/profiles
DdsPolicyAgent__PackageInstallTarget=/
DdsPolicyAgent__RequirePackageSignature=false
DdsPolicyAgent__AllowInlinePackageScripts=false
EOF

echo "${DEVICE_URN}"
