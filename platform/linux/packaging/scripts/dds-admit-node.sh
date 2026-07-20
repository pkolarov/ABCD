#!/usr/bin/env bash
# DDS Admit Node — issue an admission certificate for a second node.
#
# Linux port of platform/macos/packaging/dds-admit-node.sh. Run on the
# bootstrap (Linux) machine:
#   sudo dds-admit-node
#
# Then copy the admission.cbor and domain.toml to the second node.
set -euo pipefail

DATA_DIR="/var/lib/dds"
NODE_DATA="${DATA_DIR}/node"
NODE_BIN="/usr/bin/dds-node"

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
read -r PEER_ID
[[ -n "${PEER_ID}" ]] || { echo "Peer ID required" >&2; exit 1; }

[[ "${PEER_ID}" == 12D3KooW* ]] || echo "Warning: Peer ID doesn't start with 12D3KooW — are you sure?"

# PQ-DEFAULT-2: on a hybrid domain, the new node's own `gen-node-key` run
# also printed a `kem_pubkey_hex:` line alongside peer_id. Without it here,
# this admission cert can't carry a KEM pubkey and encrypted-gossip
# (enc-v3) peers can never deliver epoch-key releases to the new node
# until it self-repairs at first start. Optional — leave blank on a
# non-hybrid domain.
printf "KEM pubkey hex from the new node's gen-node-key output (blank if none): "
read -r KEM_HEX

printf "Validity in days [365]: "
read -r TTL_DAYS
TTL_DAYS="${TTL_DAYS:-365}"

OUT_FILE="${DATA_DIR}/admission-${PEER_ID:0:12}.cbor"
printf "Output file [${OUT_FILE}]: "
read -r USER_OUT
[[ -n "${USER_OUT}" ]] && OUT_FILE="${USER_OUT}"

echo ""
# Check if domain key is FIDO2-protected by checking file contents
# (same heuristic as the macOS script — "credential_id" substring).
if grep -q "credential_id" "${NODE_DATA}/domain_key.bin" 2>/dev/null; then
  echo "Domain key is FIDO2-protected — you will need to touch your key."
else
  printf "Domain key passphrase: "
  read -rs DOMAIN_PASSPHRASE
  echo ""
  export DDS_DOMAIN_PASSPHRASE="${DOMAIN_PASSPHRASE}"
fi

echo "Issuing admission certificate..."
ADMIT_ARGS=(
  admit
  --domain-key "${NODE_DATA}/domain_key.bin"
  --domain "${NODE_DATA}/domain.toml"
  --peer-id "${PEER_ID}"
  --out "${OUT_FILE}"
  --ttl-days "${TTL_DAYS}"
)
[[ -n "${KEM_HEX}" ]] && ADMIT_ARGS+=(--kem-pubkey "${KEM_HEX}")
"${NODE_BIN}" "${ADMIT_ARGS[@]}"

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
