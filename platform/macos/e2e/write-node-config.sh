#!/bin/zsh
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  write-node-config.sh --domain-file <FILE> --admission-file <FILE> [--listen-port <PORT>] [--api-port <PORT>] [--org-hash <HASH>] [--bootstrap-peer <MULTIADDR>] [--run-root <DIR>]
EOF
}

RUN_ROOT="/tmp/dds-macos-e2e"
LISTEN_PORT="4001"
API_PORT="5551"
ORG_HASH="dds-macos-e2e"
DOMAIN_FILE=""
ADMISSION_FILE=""
BOOTSTRAP_PEER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain-file) DOMAIN_FILE="$2"; shift 2 ;;
    --admission-file) ADMISSION_FILE="$2"; shift 2 ;;
    --listen-port) LISTEN_PORT="$2"; shift 2 ;;
    --api-port) API_PORT="$2"; shift 2 ;;
    --org-hash) ORG_HASH="$2"; shift 2 ;;
    --bootstrap-peer) BOOTSTRAP_PEER="$2"; shift 2 ;;
    --run-root) RUN_ROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -f "${DOMAIN_FILE}" ]] || { echo "Missing --domain-file" >&2; exit 2; }
[[ -f "${ADMISSION_FILE}" ]] || { echo "Missing --admission-file" >&2; exit 2; }

mkdir -p "${RUN_ROOT}/node-data"
cp "${DOMAIN_FILE}" "${RUN_ROOT}/node-data/domain.toml"
cp "${ADMISSION_FILE}" "${RUN_ROOT}/node-data/admission.cbor"

DOMAIN_NAME="$(awk -F'= ' '/^name = / { gsub(/"/, "", $2); print $2 }' "${DOMAIN_FILE}")"
DOMAIN_ID="$(awk -F'= ' '/^id = / { gsub(/"/, "", $2); print $2 }' "${DOMAIN_FILE}")"
DOMAIN_PUBKEY="$(awk -F'= ' '/^pubkey = / { gsub(/"/, "", $2); print $2 }' "${DOMAIN_FILE}")"

BOOTSTRAP_BLOCK=""
if [[ -n "${BOOTSTRAP_PEER}" ]]; then
  BOOTSTRAP_BLOCK="bootstrap_peers = [\"${BOOTSTRAP_PEER}\"]"
else
  BOOTSTRAP_BLOCK="bootstrap_peers = []"
fi

cat > "${RUN_ROOT}/dds.toml" <<EOF
data_dir = "${RUN_ROOT}/node-data"
org_hash = "${ORG_HASH}"
trusted_roots = []

[network]
listen_addr = "/ip4/0.0.0.0/tcp/${LISTEN_PORT}"
${BOOTSTRAP_BLOCK}
mdns_enabled = false
heartbeat_secs = 1
idle_timeout_secs = 60
api_addr = "127.0.0.1:${API_PORT}"

[domain]
name = "${DOMAIN_NAME}"
id = "${DOMAIN_ID}"
pubkey = "${DOMAIN_PUBKEY}"
admission_path = "${RUN_ROOT}/node-data/admission.cbor"
audit_log_enabled = false
EOF

echo "${RUN_ROOT}/dds.toml"
