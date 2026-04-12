#!/bin/zsh
# DDS Admit Node — issue an admission certificate for a second node.
#
# Run on the bootstrap (macOS) machine:
#   sudo dds-admit-node
#
# Then copy the admission.cbor and domain.toml to the second node.
set -euo pipefail

DDS_ROOT="/Library/Application Support/DDS"
NODE_DATA="${DDS_ROOT}/node-data"
NODE_BIN="/usr/local/bin/dds-node"

# ---- Preflight ----
if [[ $EUID -ne 0 ]]; then
  echo "Error: run with sudo" >&2
  exit 1
fi

[[ -f "${NODE_DATA}/domain_key.bin" ]] || { echo "Error: domain key not found. Run dds-bootstrap-domain first." >&2; exit 1; }
[[ -f "${NODE_DATA}/domain.toml" ]] || { echo "Error: domain.toml not found." >&2; exit 1; }

echo ""
echo "=== DDS Admit Node ==="
echo ""
echo "This issues an admission certificate for a new node to join the domain."
echo "You will need the new node's Peer ID."
echo ""
echo "To get the Peer ID on the remote machine:"
echo "  dds-node gen-node-key --data-dir <DATA_DIR>"
echo ""

printf "Peer ID of the new node (12D3KooW...): "
read PEER_ID
[[ -n "${PEER_ID}" ]] || { echo "Peer ID required" >&2; exit 1; }

# Validate format
[[ "${PEER_ID}" == 12D3KooW* ]] || echo "Warning: Peer ID doesn't start with 12D3KooW — are you sure?"

printf "Validity in days [365]: "
read TTL_DAYS
[[ -n "${TTL_DAYS}" ]] || TTL_DAYS="365"

OUT_FILE="${DDS_ROOT}/admission-${PEER_ID:0:12}.cbor"
printf "Output file [${OUT_FILE}]: "
read USER_OUT
[[ -n "${USER_OUT}" ]] && OUT_FILE="${USER_OUT}"

echo ""
# Check if domain key is FIDO2-protected (version 3) by checking file header
# If FIDO2-protected, no passphrase needed — just touch the key
DOMAIN_KEY_VERSION="$(python3 -c "
import sys
with open('${NODE_DATA}/domain_key.bin', 'rb') as f:
    data = f.read(20)
# Look for CBOR map with 'v' key = 3 (FIDO2)
# Simple heuristic: if file contains 'credential_id' it's FIDO2
print('fido2' if b'credential_id' in open('${NODE_DATA}/domain_key.bin','rb').read() else 'passphrase')
" 2>/dev/null || echo "passphrase")"

if [[ "${DOMAIN_KEY_VERSION}" == "fido2" ]]; then
  echo "Domain key is FIDO2-protected — you will need to touch your key."
else
  echo "Domain key passphrase:"
  read -s DOMAIN_PASSPHRASE
  echo ""
  export DDS_DOMAIN_PASSPHRASE="${DOMAIN_PASSPHRASE}"
fi

echo "Issuing admission certificate..."
"${NODE_BIN}" admit \
  --domain-key "${NODE_DATA}/domain_key.bin" \
  --domain "${NODE_DATA}/domain.toml" \
  --peer-id "${PEER_ID}" \
  --out "${OUT_FILE}" \
  --ttl-days "${TTL_DAYS}"

# Get this node's info for bootstrap peer
source "${DDS_ROOT}/bootstrap.env" 2>/dev/null || true

echo ""
echo "============================================================"
echo "  Admission Certificate Issued"
echo "============================================================"
echo ""
echo "  Peer ID:   ${PEER_ID}"
echo "  Valid for: ${TTL_DAYS} days"
echo "  Cert file: ${OUT_FILE}"
echo ""
echo "  Copy these files to the new node:"
echo "    1. ${NODE_DATA}/domain.toml"
echo "    2. ${OUT_FILE}"
echo ""
echo "  Nodes on the same LAN will auto-discover each other via mDNS."
echo "  No manual address configuration needed."
echo ""
echo "  Windows quick-start:"
echo "    1. Copy domain.toml → C:\\ProgramData\\DDS\\node-data\\"
echo "    2. Copy admission cert → C:\\ProgramData\\DDS\\node-data\\admission.cbor"
echo "    3. Edit C:\\ProgramData\\DDS\\dds.toml with domain info from domain.toml"
echo "    4. Start DdsNode service"
echo "    5. Wait ~60s for mDNS discovery + gossip sync"
echo "    6. Check: curl http://localhost:5551/v1/enrolled-users"
echo ""
