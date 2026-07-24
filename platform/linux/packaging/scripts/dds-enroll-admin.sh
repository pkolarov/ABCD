#!/usr/bin/env bash
# DDS Admin Enrollment — bootstrap the first admin with a FIDO2 key.
#
# Linux port of platform/macos/packaging/dds-enroll-admin.sh. Run after
# dds-bootstrap-domain:
#   sudo dds-enroll-admin
#
# Prerequisites:
#   - dds-node running (bootstrapped)
#   - FIDO2 USB key plugged in (YubiKey, SoloKey, etc.)
#
# This script is a thin wrapper around `dds-fido2 admin-setup`, which
# performs the real vouch/admin-setup ceremony (POST /v1/admin/setup,
# gated by dds-node's C-2 `.bootstrap` sentinel) — the same mechanism
# the Windows console's "Admin Setup" flow uses. Trust is established
# server-side by the ceremony itself; no config edit or service restart
# is needed.
set -euo pipefail

DATA_DIR="/var/lib/dds"
API_SOCK="${DATA_DIR}/dds.sock"
FIDO2_CLI="/usr/bin/dds-fido2"

# ---- Preflight ----
if [[ $EUID -ne 0 ]]; then
  echo "Error: run with sudo" >&2
  exit 1
fi

[[ -f "${DATA_DIR}/dds.toml" ]] || { echo "Error: run dds-bootstrap-domain first" >&2; exit 1; }
curl -sf --unix-socket "${API_SOCK}" "http://localhost/v1/status" > /dev/null 2>&1 || { echo "Error: dds-node not running" >&2; exit 1; }

echo ""
echo "=== DDS Admin Enrollment ==="
echo ""
echo "This creates a FIDO2 credential and bootstraps it as this domain's"
echo "first admin. You will touch your FIDO2 key once (and may be asked"
echo "to set a PIN if this key doesn't have one yet — needed later for"
echo "approving other people)."
echo ""

printf "Admin label (e.g., peter): "
read -r ADMIN_LABEL
[[ -n "${ADMIN_LABEL}" ]] || { echo "Label required" >&2; exit 1; }

echo ""
"${FIDO2_CLI}" admin-setup \
  --node-url "unix:${API_SOCK}" \
  --label "${ADMIN_LABEL}" \
  | tee /tmp/dds-enroll-admin.log

ADMIN_URN="$(awk '/urn:/ { print $2 }' /tmp/dds-enroll-admin.log | tail -n 1)"
if [[ -z "${ADMIN_URN}" ]]; then
  echo ""
  echo "Error: could not extract admin URN from dds-fido2 admin-setup output." >&2
  echo "Check /tmp/dds-enroll-admin.log for details." >&2
  exit 1
fi

# **C-4 (55812b6 port)** — the provision bundle created by
# dds-bootstrap-domain predates this admin, so it seeds joining nodes
# with an empty trust anchor (trusted_roots = []) and no amount of
# gossip ever fixes that (admin_setup deliberately never emits a
# replicable dds:admin vouch). Now that the node has persisted
# bootstrap_admin_urn into dds.toml, regenerate the bundle with the
# admin seeded (`create-provision-bundle --config` reads it back out).
# Mirrors DdsConsole.ps1's Tick-AdminSetupWait reseed point. Signing
# the bundle unwraps the domain key — one more FIDO2 touch (or
# passphrase) is expected here.
NODE_DATA="${DATA_DIR}/node"
if grep -qE '^\s*bootstrap_admin_urn\s*=\s*"[^"]+"' "${DATA_DIR}/dds.toml" 2>/dev/null; then
  ORG_HASH="$(source "${DATA_DIR}/bootstrap.env" 2>/dev/null && echo "${ORG_HASH:-}")"
  if [[ -n "${ORG_HASH}" ]]; then
    echo ""
    echo "Regenerating provision bundle with the admin trust anchor seeded..."
    echo "(this signs the bundle — touch your FIDO2 key / enter the domain"
    echo " passphrase when prompted)"
    /usr/bin/dds-node create-provision-bundle \
      --dir "${NODE_DATA}" \
      --org "${ORG_HASH}" \
      --out "${DATA_DIR}/provision.dds" \
      --config "${DATA_DIR}/dds.toml" \
      || echo "WARN: bundle reseed failed — nodes provisioned from the old bundle will start with an empty trust anchor. Re-run: dds-node create-provision-bundle --dir \"${NODE_DATA}\" --org <org> --out \"${DATA_DIR}/provision.dds\" --config \"${DATA_DIR}/dds.toml\"" >&2
  else
    echo "WARN: could not read ORG_HASH from bootstrap.env — provision bundle NOT reseeded." >&2
    echo "      Nodes provisioned from the existing bundle will start with an empty trust anchor." >&2
  fi
else
  echo "WARN: bootstrap_admin_urn not found in dds.toml after admin-setup — provision bundle NOT reseeded." >&2
fi

echo ""
echo "============================================================"
echo "  Admin Enrollment Complete"
echo "============================================================"
echo ""
echo "  Label:  ${ADMIN_LABEL}"
echo "  URN:    ${ADMIN_URN}"
echo "  Status: bootstrap admin (real vouch/admin-setup trust — not a"
echo "          trusted_roots config hack)"
echo ""
echo "  This admin's FIDO2 credential will sync to other nodes in the"
echo "  domain via gossip. On a Windows node, the DDS Credential"
echo "  Provider will show this admin on the logon screen after gossip"
echo "  sync (~60s)."
echo ""
echo "  To approve additional people or promote sub-admins, use:"
echo "    sudo dds-user"
echo "  To add another node:"
echo "    sudo dds-admit-node"
echo ""

cat >> "${DATA_DIR}/bootstrap.env" <<EOF
ADMIN_URN=${ADMIN_URN}
ADMIN_LABEL=${ADMIN_LABEL}
EOF
