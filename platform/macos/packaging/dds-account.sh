#!/bin/zsh
# DDS Account — create/modify/disable/enable/delete a local macOS
# account on managed devices, via published policy.
#
#   sudo dds-account
#
# Thin wrapper around `dds policy publish-macos`. Account directives are
# delivered as policy documents (MacOsPolicyDocument.macos.local_accounts)
# that the Policy Agent on each matching device applies — this script
# just builds that document and publishes it.
set -euo pipefail

DDS_ROOT="/Library/Application Support/DDS"
API_SOCK="${DDS_ROOT}/dds.sock"
NODE_URL="unix:${API_SOCK}"
FIDO2_CLI="/usr/local/bin/dds-fido2"
DDS_CLI="/usr/local/bin/dds"

if [[ $EUID -ne 0 ]]; then
  echo "Error: run with sudo" >&2
  exit 1
fi

curl -sf --unix-socket "${API_SOCK}" "http://localhost/v1/status" > /dev/null 2>&1 || {
  echo "Error: dds-node not running (run dds-domain to bootstrap first)" >&2
  exit 1
}

check_publisher_status() {
  "${DDS_CLI}" --node-url "${NODE_URL}" policy publisher-status --platform macos
}

ensure_publisher_authorized() {
  local status_out
  status_out="$(check_publisher_status)"
  echo "${status_out}"
  if echo "${status_out}" | grep -qE "Can publish:[[:space:]]*YES"; then
    return 0
  fi

  echo ""
  echo "This node is not yet authorized to publish macOS policy."
  printf "Run the one-time authorization now? [Y/n]: "
  read -r RESP
  RESP="${RESP:-Y}"
  [[ "${RESP}" =~ ^[Yy] ]] || return 1

  "${DDS_CLI}" --node-url "${NODE_URL}" policy publisher-init --platform macos

  local node_urn
  node_urn="$(check_publisher_status | awk '/Node URN:/ { print $3 }')"
  [[ -n "${node_urn}" ]] || { echo "Error: could not determine node URN." >&2; return 1; }

  echo ""
  echo "An admin must now authorize this node (purpose: dds:policy-publisher-macos)."
  echo "This requires an ADMIN's FIDO2 key (touch + PIN), not the operator's."
  printf "Continue with an admin FIDO2 key now? [Y/n]: "
  read -r RESP2
  RESP2="${RESP2:-Y}"
  [[ "${RESP2}" =~ ^[Yy] ]] || return 1

  "${FIDO2_CLI}" vouch --node-url "${NODE_URL}" --subject-urn "${node_urn}" --purpose "dds:policy-publisher-macos"

  echo ""
  check_publisher_status
  echo ""
}

# Device URNs are long, opaque, and — critically — a wrong one produces a
# policy that publishes successfully and is then silently never applied.
# So offer a numbered pick-list from the domain's own device inventory
# instead of asking the operator to transcribe URNs between machines.
DEVICE_URNS=()
DEVICE_LABELS=()

load_devices() {
  DEVICE_URNS=()
  DEVICE_LABELS=()
  local json
  json="$("${DDS_CLI}" --node-url "${NODE_URL}" platform devices --json 2>/dev/null || true)"
  [[ -n "${json}" ]] || return 1
  local line
  while IFS=$'\t' read -r urn label; do
    [[ -n "${urn}" ]] || continue
    DEVICE_URNS+=("${urn}")
    DEVICE_LABELS+=("${label}")
  done < <(printf '%s' "${json}" | python3 -c "
import json, sys
try:
    items = json.load(sys.stdin)
except Exception:
    sys.exit(0)
import datetime
for d in items:
    bits = [d.get('hostname') or '?', d.get('os') or '?', d.get('os_version') or '']
    # Enrollment date and the self-marker are what let you tell cloned
    # VMs and stale re-provisioned identities apart -- hostname cannot.
    iat = d.get('enrolled_at') or 0
    if iat:
        bits.append(datetime.datetime.fromtimestamp(iat, datetime.timezone.utc).strftime('(%Y-%m-%d)'))
    tags = d.get('tags') or []
    if tags:
        bits.append('tags: ' + ','.join(tags))
    if d.get('is_self'):
        bits.append('<- THIS MACHINE')
    print('%s\t%s' % (d.get('device_urn', ''), ' '.join(b for b in bits if b)))
" 2>/dev/null)
  [[ ${#DEVICE_URNS[@]} -gt 0 ]]
}

# Prints the chosen URN(s) as a comma-separated list on stdout. Prompts
# go to stderr so callers can capture the result with $(...).
pick_devices() {
  local multi="${1:-single}"
  if ! load_devices; then
    echo "  (no device inventory available — falling back to manual entry)" >&2
    printf "  Enter device URN(s) manually (comma-separated, blank to skip): " >&2
    local manual
    read -r manual
    printf '%s' "${manual}"
    return 0
  fi

  echo "" >&2
  echo "  Devices enrolled in this domain:" >&2
  local i=1
  for label in "${DEVICE_LABELS[@]}"; do
    printf "   %2d) %s\n" "${i}" "${label}" >&2
    printf "       %s\n" "${DEVICE_URNS[$i]}" >&2
    i=$((i + 1))
  done
  echo "" >&2
  if [[ "${multi}" == "multi" ]]; then
    printf "  Select device number(s) (comma-separated, blank for none): " >&2
  else
    printf "  Select device number (blank to skip): " >&2
  fi
  local sel
  read -r sel
  [[ -n "${sel}" ]] || return 0

  local out=""
  local n
  for n in ${(s:,:)sel}; do
    n="${n// /}"
    [[ "${n}" == <-> ]] || { echo "  Ignoring non-numeric '${n}'." >&2; continue; }
    if (( n < 1 || n > ${#DEVICE_URNS[@]} )); then
      echo "  Ignoring out-of-range '${n}'." >&2
      continue
    fi
    [[ -n "${out}" ]] && out="${out},"
    out="${out}${DEVICE_URNS[$n]}"
    [[ "${multi}" == "multi" ]] || break
  done
  printf '%s' "${out}"
}

split_csv_to_json_array() {
  # Prints a JSON array from a comma-separated string (blank -> []).
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
echo ""
echo "Which dimension you use decides whether machines that DO NOT EXIST YET"
echo "are covered:"
echo "  tags / org units  -> yes. Joining self-attests a tag automatically"
echo "                       (auto-provisioned, joined-node, bootstrap-node)."
echo "  device URNs       -> no, and silently. Only the machines you name."
echo "Pick device URNs when you mean *only these machines*; otherwise scope"
echo "by tag or org unit so the policy keeps working as the domain grows."
printf "Device tags (comma-separated, e.g. mac-eng): "
read -r DEVICE_TAGS
printf "Org units (comma-separated): "
read -r ORG_UNITS
echo ""
echo "Device URNs (targets one or more specific machines)."
printf "Pick from the enrolled device list? [Y/n]: "
read -r PICK_RESP
PICK_RESP="${PICK_RESP:-Y}"
if [[ "${PICK_RESP}" =~ ^[Yy] ]]; then
  IDENTITY_URNS="$(pick_devices multi)"
  [[ -n "${IDENTITY_URNS}" ]] && echo "  Selected: ${IDENTITY_URNS}"
else
  printf "Identity URNs (comma-separated): "
  read -r IDENTITY_URNS
fi

echo ""
echo "--- Policy identity ---"
printf "Policy ID (e.g. accounts/engineering-laptops): "
read -r POLICY_ID
[[ -n "${POLICY_ID}" ]] || { echo "Policy ID required" >&2; exit 1; }
printf "Display name: "
read -r DISPLAY_NAME
[[ -n "${DISPLAY_NAME}" ]] || DISPLAY_NAME="${POLICY_ID}"

echo ""
echo "--- Version ---"
echo "The server does NOT enforce version ordering — republishing with a"
echo "version <= the current one silently gossips but never takes effect."
echo "Pick a representative already-enrolled device to check the current"
echo "version against (any device the policy is visible to will do)."
CHECK_DEVICE_URN=""
# If the scope already names devices, the first one is the obvious probe.
if [[ -n "${IDENTITY_URNS}" ]]; then
  CHECK_DEVICE_URN="${IDENTITY_URNS%%,*}"
  echo "  Using the first scoped device: ${CHECK_DEVICE_URN}"
else
  CHECK_DEVICE_URN="$(pick_devices single)"
fi

CURRENT_VERSION=""
if [[ -n "${CHECK_DEVICE_URN}" ]]; then
  CURRENT_VERSION="$("${DDS_CLI}" --node-url "${NODE_URL}" platform macos policies --device-urn "${CHECK_DEVICE_URN}" --json 2>/dev/null | python3 -c "
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
IS_ADMIN="false"
IS_HIDDEN="false"
if [[ "${ACCOUNT_ACTION}" == "Create" || "${ACCOUNT_ACTION}" == "Modify" ]]; then
  printf "Full name: "
  read -r FULL_NAME
  printf "Shell [/bin/zsh]: "
  read -r SHELL_PATH
  SHELL_PATH="${SHELL_PATH:-/bin/zsh}"
  printf "Grant admin? [y/N]: "
  read -r ADMIN_RESP
  [[ "${ADMIN_RESP}" =~ ^[Yy] ]] && IS_ADMIN="true"
  printf "Hide from login window? [y/N]: "
  read -r HIDDEN_RESP
  [[ "${HIDDEN_RESP}" =~ ^[Yy] ]] && IS_HIDDEN="true"
fi

DEVICE_TAGS_JSON="$(split_csv_to_json_array "${DEVICE_TAGS}")"
ORG_UNITS_JSON="$(split_csv_to_json_array "${ORG_UNITS}")"
IDENTITY_URNS_JSON="$(split_csv_to_json_array "${IDENTITY_URNS}")"

TMP_JSON="$(mktemp /tmp/dds-account-XXXXXX.json)"
trap 'rm -f "${TMP_JSON}"' EXIT

POLICY_ID="${POLICY_ID}" DISPLAY_NAME="${DISPLAY_NAME}" NEW_VERSION="${NEW_VERSION}" \
ENFORCEMENT="${ENFORCEMENT}" DEVICE_TAGS_JSON="${DEVICE_TAGS_JSON}" ORG_UNITS_JSON="${ORG_UNITS_JSON}" \
IDENTITY_URNS_JSON="${IDENTITY_URNS_JSON}" USERNAME="${USERNAME}" ACCOUNT_ACTION="${ACCOUNT_ACTION}" \
FULL_NAME="${FULL_NAME}" SHELL_PATH="${SHELL_PATH}" IS_ADMIN="${IS_ADMIN}" IS_HIDDEN="${IS_HIDDEN}" \
python3 -c "
import json, os

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
    'macos': {
        'local_accounts': [{
            'username': os.environ['USERNAME'],
            'action': os.environ['ACCOUNT_ACTION'],
            'full_name': os.environ['FULL_NAME'] or None,
            'shell': os.environ['SHELL_PATH'] or None,
            'admin': os.environ['IS_ADMIN'] == 'true',
            'hidden': os.environ['IS_HIDDEN'] == 'true',
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

"${DDS_CLI}" --node-url "${NODE_URL}" policy publish-macos --from-file "${TMP_JSON}"
echo ""
echo "Published. Devices matching the scope will apply it on their next"
echo "policy-agent poll."
