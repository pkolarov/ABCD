#!/usr/bin/env bash
# DDS Account — create/modify/disable/enable/delete a local Linux
# account on managed devices, via published policy.
#
# Linux port of platform/macos/packaging/dds-account.sh.
#   sudo dds-account
#
# Thin wrapper around `dds policy publish-linux`. Account directives are
# delivered as policy documents (LinuxPolicyDocument.linux.local_users)
# that the Policy Agent on each matching device applies — this script
# just builds that document and publishes it.
set -euo pipefail

DATA_DIR="/var/lib/dds"
API_SOCK="${DATA_DIR}/dds.sock"
NODE_URL="unix:${API_SOCK}"
FIDO2_CLI="/usr/bin/dds-fido2"
DDS_CLI="/usr/bin/dds-cli"

if [[ $EUID -ne 0 ]]; then
  echo "Error: run with sudo" >&2
  exit 1
fi

curl -sf --unix-socket "${API_SOCK}" "http://localhost/v1/status" > /dev/null 2>&1 || {
  echo "Error: dds-node not running (run dds-domain to bootstrap first)" >&2
  exit 1
}

check_publisher_status() {
  "${DDS_CLI}" --node-url "${NODE_URL}" policy publisher-status --platform linux
}

ensure_publisher_authorized() {
  local status_out
  status_out="$(check_publisher_status)"
  echo "${status_out}"
  if echo "${status_out}" | grep -qE "Can publish:[[:space:]]*YES"; then
    return 0
  fi

  echo ""
  echo "This node is not yet authorized to publish Linux policy."
  printf "Run the one-time authorization now? [Y/n]: "
  read -r RESP
  RESP="${RESP:-Y}"
  [[ "${RESP}" =~ ^[Yy] ]] || return 1

  "${DDS_CLI}" --node-url "${NODE_URL}" policy publisher-init --platform linux

  local node_urn
  node_urn="$(check_publisher_status | awk '/Node URN:/ { print $3 }')"
  [[ -n "${node_urn}" ]] || { echo "Error: could not determine node URN." >&2; return 1; }

  echo ""
  echo "An admin must now authorize this node (purpose: dds:policy-publisher-linux)."
  echo "This requires an ADMIN's FIDO2 key (touch + PIN), not the operator's."
  printf "Continue with an admin FIDO2 key now? [Y/n]: "
  read -r RESP2
  RESP2="${RESP2:-Y}"
  [[ "${RESP2}" =~ ^[Yy] ]] || return 1

  "${FIDO2_CLI}" vouch --node-url "${NODE_URL}" --subject-urn "${node_urn}" --purpose "dds:policy-publisher-linux"

  echo ""
  check_publisher_status
  echo ""
}

split_csv_to_json_array() {
  python3 -c "
import json, sys
raw = sys.argv[1]
items = [s.strip() for s in raw.split(',') if s.strip()]
print(json.dumps(items))
" "$1"
}

echo ""
echo "=== DDS Account ==="
echo ""
echo "1) Create/modify/disable/enable/delete a local account"
echo "2) Check / authorize this node to publish policy"
echo "3) Exit"
echo ""
printf "Choice [1-3]: "
read -r CHOICE

case "${CHOICE}" in
  2)
    ensure_publisher_authorized || true
    exit 0
    ;;
  3)
    exit 0
    ;;
  1)
    ;;
  *)
    echo "Unknown choice." >&2
    exit 1
    ;;
esac

ensure_publisher_authorized || { echo "Publisher not authorized — cannot publish. Aborting." >&2; exit 1; }

echo ""
echo "--- Target scope ---"
echo "Leave blank to skip a scope dimension. At least one is recommended"
echo "(an empty scope on every dimension matches every device)."
printf "Device tags (comma-separated, e.g. linux-eng): "
read -r DEVICE_TAGS
printf "Org units (comma-separated): "
read -r ORG_UNITS
printf "Identity URNs (comma-separated): "
read -r IDENTITY_URNS

echo ""
echo "--- Policy identity ---"
printf "Policy ID (e.g. accounts/engineering-workstations): "
read -r POLICY_ID
[[ -n "${POLICY_ID}" ]] || { echo "Policy ID required" >&2; exit 1; }
printf "Display name: "
read -r DISPLAY_NAME
[[ -n "${DISPLAY_NAME}" ]] || DISPLAY_NAME="${POLICY_ID}"

echo ""
echo "--- Version ---"
echo "The server does NOT enforce version ordering — republishing with a"
echo "version <= the current one silently gossips but never takes effect."
printf "Representative already-enrolled device URN to check the current version against (optional): "
read -r CHECK_DEVICE_URN

CURRENT_VERSION=""
if [[ -n "${CHECK_DEVICE_URN}" ]]; then
  CURRENT_VERSION="$("${DDS_CLI}" --node-url "${NODE_URL}" platform linux policies --device-urn "${CHECK_DEVICE_URN}" --json 2>/dev/null | python3 -c "
import json, sys
try:
    items = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for p in items:
    if p.get('policy_id') == '${POLICY_ID}':
        print(p.get('version', ''))
        break
" 2>/dev/null || true)"
fi

if [[ -n "${CURRENT_VERSION}" ]]; then
  NEW_VERSION=$((CURRENT_VERSION + 1))
  echo "  Current published version for '${POLICY_ID}': ${CURRENT_VERSION}"
  echo "  New version will be: ${NEW_VERSION}"
else
  NEW_VERSION=1
  echo "  Could not determine a current version (no check device given, or"
  echo "  no existing policy with this policy_id visible to it)."
  echo "  Defaulting to version 1 — if this policy_id already exists at a"
  echo "  higher version, this publish will be silently ignored by devices"
  echo "  that already saw the higher version."
  printf "  Override version [${NEW_VERSION}]: "
  read -r VERSION_OVERRIDE
  [[ -n "${VERSION_OVERRIDE}" ]] && NEW_VERSION="${VERSION_OVERRIDE}"
fi

echo ""
echo "--- Enforcement ---"
echo "1) Enforce (default)"
echo "2) Audit (log only, don't apply)"
echo "3) Disabled"
printf "Choice [1-3, default 1]: "
read -r ENF_CHOICE
case "${ENF_CHOICE}" in
  2) ENFORCEMENT="Audit" ;;
  3) ENFORCEMENT="Disabled" ;;
  *) ENFORCEMENT="Enforce" ;;
esac

echo ""
echo "--- Account directive ---"
echo "1) Create"
echo "2) Modify"
echo "3) Delete"
echo "4) Disable"
echo "5) Enable"
printf "Choice [1-5]: "
read -r ACTION_CHOICE
case "${ACTION_CHOICE}" in
  1) ACCOUNT_ACTION="Create" ;;
  2) ACCOUNT_ACTION="Modify" ;;
  3) ACCOUNT_ACTION="Delete" ;;
  4) ACCOUNT_ACTION="Disable" ;;
  5) ACCOUNT_ACTION="Enable" ;;
  *) echo "Unknown choice." >&2; exit 1 ;;
esac

printf "Username: "
read -r USERNAME
[[ -n "${USERNAME}" ]] || { echo "Username required" >&2; exit 1; }

FULL_NAME=""
SHELL_PATH=""
UID_VALUE=""
GROUPS_CSV=""
if [[ "${ACCOUNT_ACTION}" == "Create" || "${ACCOUNT_ACTION}" == "Modify" ]]; then
  printf "Full name (GECOS): "
  read -r FULL_NAME
  printf "Shell [/bin/bash]: "
  read -r SHELL_PATH
  SHELL_PATH="${SHELL_PATH:-/bin/bash}"
  printf "UID (blank = OS-assigned on create): "
  read -r UID_VALUE
  printf "Supplementary groups (comma-separated, e.g. sudo,docker): "
  read -r GROUPS_CSV
fi

DEVICE_TAGS_JSON="$(split_csv_to_json_array "${DEVICE_TAGS}")"
ORG_UNITS_JSON="$(split_csv_to_json_array "${ORG_UNITS}")"
IDENTITY_URNS_JSON="$(split_csv_to_json_array "${IDENTITY_URNS}")"
GROUPS_JSON="$(split_csv_to_json_array "${GROUPS_CSV}")"

TMP_JSON="$(mktemp /tmp/dds-account-XXXXXX.json)"
trap 'rm -f "${TMP_JSON}"' EXIT

POLICY_ID="${POLICY_ID}" DISPLAY_NAME="${DISPLAY_NAME}" NEW_VERSION="${NEW_VERSION}" \
ENFORCEMENT="${ENFORCEMENT}" DEVICE_TAGS_JSON="${DEVICE_TAGS_JSON}" ORG_UNITS_JSON="${ORG_UNITS_JSON}" \
IDENTITY_URNS_JSON="${IDENTITY_URNS_JSON}" USERNAME="${USERNAME}" ACCOUNT_ACTION="${ACCOUNT_ACTION}" \
FULL_NAME="${FULL_NAME}" SHELL_PATH="${SHELL_PATH}" UID_VALUE="${UID_VALUE}" GROUPS_JSON="${GROUPS_JSON}" \
python3 -c "
import json, os

uid_value = os.environ['UID_VALUE'].strip()

doc = {
    'policy_id': os.environ['POLICY_ID'],
    'display_name': os.environ['DISPLAY_NAME'],
    'version': int(os.environ['NEW_VERSION']),
    'scope': {
        'device_tags': json.loads(os.environ['DEVICE_TAGS_JSON']),
        'org_units': json.loads(os.environ['ORG_UNITS_JSON']),
        'identity_urns': json.loads(os.environ['IDENTITY_URNS_JSON']),
    },
    'settings': [],
    'enforcement': os.environ['ENFORCEMENT'],
    'linux': {
        'local_users': [{
            'username': os.environ['USERNAME'],
            'action': os.environ['ACCOUNT_ACTION'],
            'uid': int(uid_value) if uid_value else None,
            'shell': os.environ['SHELL_PATH'] or None,
            'groups': json.loads(os.environ['GROUPS_JSON']),
            'full_name': os.environ['FULL_NAME'] or None,
        }]
    }
}

with open('${TMP_JSON}', 'w') as f:
    json.dump(doc, f, indent=2)
print(json.dumps(doc, indent=2))
"

echo ""
printf "Publish the above policy document? [y/N]: "
read -r PUBLISH_CONFIRM
[[ "${PUBLISH_CONFIRM}" =~ ^[Yy] ]] || { echo "Aborted — nothing published."; exit 0; }

"${DDS_CLI}" --node-url "${NODE_URL}" policy publish-linux --from-file "${TMP_JSON}"
echo ""
echo "Published. Devices matching the scope will apply it on their next"
echo "policy-agent poll."
