#!/bin/zsh
# DDS Domain — bootstrap, join, inspect, or decommission this node.
#
#   sudo dds-domain
#
# Thin menu wrapper: each choice below just shells out to an existing,
# already-battle-tested script or CLI call. No logic lives here beyond
# the menu itself.
set -euo pipefail

DDS_ROOT="/Library/Application Support/DDS"
API_SOCK="${DDS_ROOT}/dds.sock"

if [[ $EUID -ne 0 ]]; then
  echo "Error: run with sudo" >&2
  exit 1
fi

show_status() {
  # Pipe the response straight to python over stdin — never through a
  # fixed /tmp path (root writer + world-writable dir = symlink-clobber).
  # `status` is a read-only special in zsh, so use `resp`.
  local resp
  resp="$(curl -sf --unix-socket "${API_SOCK}" "http://localhost/v1/status" 2>/dev/null || true)"
  if [[ -z "${resp}" ]]; then
    echo "dds-node is not running or not yet bootstrapped."
    return
  fi
  echo ""
  printf '%s' "${resp}" | python3 -c "
import json, sys
s = json.load(sys.stdin)
print(f\"  trust_graph_tokens: {s.get('trust_graph_tokens')}\")
print(f\"  store_tokens:       {s.get('store_tokens')}\")
print(f\"  trusted_roots:      {s.get('trusted_roots')}\")
print(f\"  connected_peers:    {s.get('connected_peers')}\")
"
  echo "  (full health + mesh view: sudo dds-status)"
  echo ""
}

echo ""
echo "=== DDS Domain ==="
echo ""
echo "1) Bootstrap this domain (first-time setup on this machine)"
echo "2) Admit another node into this domain"
echo "3) Show domain/node status"
echo "4) Decommission this node (uninstall)"
echo "5) Exit"
echo ""
printf "Choice [1-5]: "
read -r CHOICE

case "${CHOICE}" in
  1) exec /usr/local/bin/dds-bootstrap-domain ;;
  2) exec /usr/local/bin/dds-admit-node ;;
  3) show_status ;;
  4) exec /usr/local/bin/dds-uninstall ;;
  5) exit 0 ;;
  *) echo "Unknown choice." >&2; exit 1 ;;
esac
