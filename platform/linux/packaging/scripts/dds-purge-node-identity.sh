#!/usr/bin/env bash
# DDS Purge Node Identity — explicitly wipe this node's domain key,
# admission cert, and identity, for operators who intentionally want to
# re-bootstrap or replace a node.
#
#   sudo dds-purge-node-identity [-f|--force]
#
# The dds-linux package's own `postrm purge` deliberately preserves
# /var/lib/dds/node (see platform/linux/packaging/debian/build-deb.sh's
# postrm comment) — removing a node's identity is a decision an
# operator should make explicitly, not something `apt purge` does as a
# side effect. This script is that explicit, manual step. It does NOT
# uninstall the package itself; for that, use `apt remove`/`apt purge
# dds-linux` (which stops/removes services and, on purge, only removes
# the policy-agent state — this script still needs to run separately
# for the node identity).
set -euo pipefail

FORCE=0
for arg in "$@"; do
  case "${arg}" in
    -f|--force) FORCE=1 ;;
    *) echo "Unknown argument: ${arg}" >&2; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Error: run with sudo" >&2
  exit 1
fi

DATA_DIR="/var/lib/dds"
NODE_DATA="${DATA_DIR}/node"

echo ""
echo "=== DDS Purge Node Identity ==="
echo ""
echo "Will stop: dds-node.service, dds-policy-agent.service"
echo "Will WIPE: ${NODE_DATA} (domain key, admission cert, node identity,"
echo "           P2P key, admin FIDO2 credential store)"
echo "Will also remove: ${DATA_DIR}/dds.toml, ${DATA_DIR}/bootstrap.env,"
echo "                   ${DATA_DIR}/provision.dds, ${DATA_DIR}/dds.sock"
echo ""
echo "This does NOT uninstall the dds-linux package — use 'apt remove'/"
echo "'apt purge dds-linux' for that."
echo ""

if [[ ${FORCE} -eq 0 ]]; then
  printf "Type 'WIPE' to confirm: "
  read -r RESP
  if [[ "${RESP}" != "WIPE" ]]; then
    echo "Aborted."
    exit 0
  fi
fi

echo ""
echo "Stopping services..."
systemctl stop dds-policy-agent.service 2>/dev/null || true
systemctl stop dds-node.service 2>/dev/null || true

echo "Wiping node identity..."
rm -rf "${NODE_DATA}"
rm -f "${DATA_DIR}/dds.toml" "${DATA_DIR}/bootstrap.env" "${DATA_DIR}/provision.dds" "${DATA_DIR}/dds.sock"

echo ""
echo "Node identity purged. Re-bootstrap with: sudo dds-bootstrap-domain"
