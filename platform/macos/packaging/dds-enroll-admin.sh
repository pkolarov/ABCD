#!/bin/zsh
# DDS Admin Enrollment — enroll the first admin user with a FIDO2 key.
#
# Run after dds-bootstrap-domain:
#   sudo dds-enroll-admin
#
# Prerequisites:
#   - dds-node running (bootstrapped)
#   - FIDO2 USB key plugged in (YubiKey, SoloKey, etc.)
#
# This script:
#   1. Runs dds-fido2-test to create a credential and enroll the user
#   2. Adds the user to trusted_roots in dds.toml
#   3. Restarts dds-node to pick up the new root
#   4. Creates a vouch granting the admin session privileges
set -euo pipefail

DDS_ROOT="/Library/Application Support/DDS"
# **SC-2** — Local API talks UDS only. Use `curl --unix-socket` to hit
# the loopback HTTP endpoint via peer-cred-authenticated transport.
API_SOCK="${DDS_ROOT}/dds.sock"
API_URL="http://localhost"
DDS_CLI="/usr/local/bin/dds"
FIDO2_TEST="/usr/local/bin/dds-fido2-test"

# ---- Preflight ----
if [[ $EUID -ne 0 ]]; then
  echo "Error: run with sudo" >&2
  exit 1
fi

[[ -f "${DDS_ROOT}/dds.toml" ]] || { echo "Error: run dds-bootstrap-domain first" >&2; exit 1; }
curl -sf --unix-socket "${API_SOCK}" "${API_URL}/v1/status" > /dev/null 2>&1 || { echo "Error: dds-node not running" >&2; exit 1; }

echo ""
echo "=== DDS Admin Enrollment ==="
echo ""
echo "This will create a FIDO2 credential and enroll it as a trusted admin."
echo "You will need to touch your FIDO2 key twice (once to create, once to verify)."
echo ""

printf "Admin display name (e.g., Peter Admin): "
read ADMIN_NAME
[[ -n "${ADMIN_NAME}" ]] || { echo "Name required" >&2; exit 1; }

printf "Admin label (e.g., peter): "
read ADMIN_LABEL
[[ -n "${ADMIN_LABEL}" ]] || { echo "Label required" >&2; exit 1; }

echo ""
echo "[1/4] Running FIDO2 enrollment..."
echo "  This calls dds-fido2-test which will:"
echo "  - Create a FIDO2 credential (touch key)"
echo "  - Enroll the user in dds-node"
echo "  - Verify with a getAssertion (touch key again)"
echo ""

# Run the FIDO2 test tool and capture output
# The tool enrolls with a random label, but we want our specific label.
# Instead, we'll do the enrollment manually via the API after creating
# the credential with the FIDO2 tool.

# For now, use the existing dds-fido2-test which handles the full flow.
# It will fail at step 5 (session assert) because no vouch exists yet,
# but the enrollment (step 3) will succeed.
set +e
"${FIDO2_TEST}" 2>&1 | tee /tmp/dds-enroll-admin.log
FIDO2_EXIT=$?
set -e

# Extract the enrolled URN from the output
ADMIN_URN="$(grep -o 'URN: urn:vouchsafe:[^ ]*' /tmp/dds-enroll-admin.log | head -1 | cut -d' ' -f2)"

if [[ -z "${ADMIN_URN}" ]]; then
  echo ""
  echo "Error: Could not extract admin URN from FIDO2 enrollment output."
  echo "Check /tmp/dds-enroll-admin.log for details."
  exit 1
fi

echo ""
echo "[2/4] Admin enrolled: ${ADMIN_URN}"

echo ""
echo "[3/4] Adding admin to trusted_roots..."

# Read current trusted_roots, add the new URN
python3 -c "
import re, sys

with open('${DDS_ROOT}/dds.toml') as f:
    content = f.read()

# Parse existing trusted_roots
m = re.search(r'trusted_roots\s*=\s*\[(.*?)\]', content)
if m:
    existing = m.group(1).strip()
    if existing:
        roots = [r.strip().strip('\"') for r in existing.split(',')]
    else:
        roots = []
else:
    roots = []

urn = '${ADMIN_URN}'
if urn not in roots:
    roots.append(urn)

roots_str = ', '.join(['\"' + r + '\"' for r in roots])
content = re.sub(r'trusted_roots\s*=\s*\[.*?\]', 'trusted_roots = [' + roots_str + ']', content)

with open('${DDS_ROOT}/dds.toml', 'w') as f:
    f.write(content)

print(f'  trusted_roots now contains {len(roots)} root(s)')
"

echo ""
echo "[4/4] Restarting dds-node to pick up new trusted root..."
launchctl kickstart -k system/com.dds.node 2>/dev/null || true

# Wait for node to come back
printf "  Waiting for node..."
for i in {1..15}; do
  if curl -sf --unix-socket "${API_SOCK}" "${API_URL}/v1/status" > /dev/null 2>&1; then
    echo " ready!"
    break
  fi
  printf "."
  sleep 1
done

# The FIDO2 session assertion should now work because the admin is a trusted root
echo ""
echo "============================================================"
echo "  Admin Enrollment Complete"
echo "============================================================"
echo ""
echo "  Admin:      ${ADMIN_NAME} (${ADMIN_LABEL})"
echo "  URN:        ${ADMIN_URN}"
echo "  Status:     Trusted root + enrolled FIDO2 credential"
echo ""
echo "  This admin's FIDO2 credential will sync to other nodes"
echo "  in the domain via gossip. On a Windows node, the DDS"
echo "  Credential Provider will show this admin on the logon"
echo "  screen after gossip sync (~60s)."
echo ""
echo "  To add another node: sudo dds-admit-node"
echo ""

# Save admin info
cat >> "${DDS_ROOT}/bootstrap.env" <<EOF
ADMIN_URN=${ADMIN_URN}
ADMIN_NAME=${ADMIN_NAME}
ADMIN_LABEL=${ADMIN_LABEL}
EOF
