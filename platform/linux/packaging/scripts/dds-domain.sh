#!/usr/bin/env bash
# DDS Domain — bootstrap, join, inspect, or decommission this node.
#
# Linux port of platform/macos/packaging/dds-domain.sh.
#   sudo dds-domain
#
# Thin menu wrapper: each choice below just shells out to an existing,
# already-battle-tested script or CLI call. No logic lives here beyond
# the menu itself.
set -euo pipefail

DATA_DIR="/var/lib/dds"
API_SOCK="${DATA_DIR}/dds.sock"

if [[ $EUID -ne 0 ]]; then
  echo "Error: run with sudo" >&2
  exit 1
fi

show_status() {
  if ! curl -sf --unix-socket "${API_SOCK}" "http://localhost/v1/status" > /tmp/dds-domain-status.json 2>/dev/null; then
    echo "dds-node is not running or not yet bootstrapped."
    return
  fi
  echo ""
  python3 -c "
import json
with open('/tmp/dds-domain-status.json') as f:
    s = json.load(f)
print(f\"  trust_graph_tokens: {s.get('trust_graph_tokens')}\")
print(f\"  store_tokens:       {s.get('store_tokens')}\")
print(f\"  trusted_roots:      {s.get('trusted_roots')}\")
print(f\"  connected_peers:    {s.get('connected_peers')}\")
"
  echo ""
}

echo ""
echo "=== DDS Domain ==="
echo ""
echo "1) Bootstrap this domain (first-time setup on this machine)"
echo "2) Admit another node into this domain"
echo "3) Show domain/node status"
echo "4) Decommission this node (remove node identity)"
echo "5) Exit"
echo ""
printf "Choice [1-5]: "
read -r CHOICE

case "${CHOICE}" in
  1) exec /usr/bin/dds-bootstrap-domain ;;
  2) exec /usr/bin/dds-admit-node ;;
  3) show_status ;;
  4) exec /usr/local/sbin/dds-purge-node-identity ;;
  5) exit 0 ;;
  *) echo "Unknown choice." >&2; exit 1 ;;
esac
