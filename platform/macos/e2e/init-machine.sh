#!/bin/zsh
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  init-machine.sh --machine-id <ID> --advertise-ip <IP> [--listen-port <PORT>] [--run-root <DIR>]
EOF
}

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR}/../../.."
NODE_BIN="${REPO_ROOT}/target/debug/dds-node"

RUN_ROOT="/tmp/dds-macos-e2e"
LISTEN_PORT="4001"
MACHINE_ID=""
ADVERTISE_IP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --machine-id) MACHINE_ID="$2"; shift 2 ;;
    --advertise-ip) ADVERTISE_IP="$2"; shift 2 ;;
    --listen-port) LISTEN_PORT="$2"; shift 2 ;;
    --run-root) RUN_ROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

[[ -n "${MACHINE_ID}" ]] || { echo "--machine-id is required" >&2; exit 2; }
[[ -n "${ADVERTISE_IP}" ]] || { echo "--advertise-ip is required" >&2; exit 2; }
[[ -x "${NODE_BIN}" ]] || { echo "Missing dds-node binary at ${NODE_BIN}" >&2; exit 1; }

mkdir -p \
  "${RUN_ROOT}/node-data" \
  "${RUN_ROOT}/logs" \
  "${RUN_ROOT}/packages" \
  "${RUN_ROOT}/state" \
  "${RUN_ROOT}/profiles" \
  "${RUN_ROOT}/ManagedPreferences" \
  "${RUN_ROOT}/UserTemplatePreferences" \
  "${RUN_ROOT}/LaunchDaemons" \
  "${RUN_ROOT}/LaunchAgents" \
  "${RUN_ROOT}/install-root"

"${NODE_BIN}" gen-node-key --data-dir "${RUN_ROOT}/node-data" | tee "${RUN_ROOT}/gen-node-key.out"
PEER_ID="$(awk '/peer_id:/ { print $2 }' "${RUN_ROOT}/gen-node-key.out" | tail -n 1)"
[[ -n "${PEER_ID}" ]] || { echo "Failed to determine peer_id" >&2; exit 1; }

cat > "${RUN_ROOT}/peer-id.txt" <<EOF
${PEER_ID}
EOF

cat > "${RUN_ROOT}/bootstrap-peer.txt" <<EOF
/ip4/${ADVERTISE_IP}/tcp/${LISTEN_PORT}/p2p/${PEER_ID}
EOF

cat > "${RUN_ROOT}/machine.env" <<EOF
MACHINE_ID=${MACHINE_ID}
ADVERTISE_IP=${ADVERTISE_IP}
LISTEN_PORT=${LISTEN_PORT}
PEER_ID=${PEER_ID}
RUN_ROOT=${RUN_ROOT}
EOF

cat > "${RUN_ROOT}/LaunchDaemons/com.dds.e2e.marker.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.dds.e2e.marker</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/zsh</string>
    <string>-lc</string>
    <string>mkdir -p ${RUN_ROOT}/install-root &amp;&amp; date +%s &gt;&gt; ${RUN_ROOT}/launchd-fired.txt</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${RUN_ROOT}/logs/launchd-marker.out</string>
  <key>StandardErrorPath</key>
  <string>${RUN_ROOT}/logs/launchd-marker.err</string>
</dict>
</plist>
EOF

echo "machine_id=${MACHINE_ID}"
echo "peer_id=${PEER_ID}"
echo "bootstrap_peer=$(cat "${RUN_ROOT}/bootstrap-peer.txt")"
echo "launchd_plist=${RUN_ROOT}/LaunchDaemons/com.dds.e2e.marker.plist"
