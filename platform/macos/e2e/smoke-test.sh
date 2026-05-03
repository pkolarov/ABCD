#!/bin/zsh
# DDS macOS single-machine smoke test
#
# Runs the full macOS policy agent e2e loop on one machine:
#   1. init-domain + gen-node-key + admit
#   2. start dds-node
#   3. enroll device
#   4. publish macOS policy fixture (preference + launchd directives)
#   5. run the .NET policy agent for one poll cycle
#   6. validate enforcement outcomes
#   7. cleanup
#
# Usage:
#   platform/macos/e2e/smoke-test.sh           # preference-only (no sudo)
#   platform/macos/e2e/smoke-test.sh --sudo    # full: preferences + launchd + pkg
#
# Exit code 0 = all checks passed.
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
REPO_ROOT="${SCRIPT_DIR}/../../.."
export PATH="$HOME/.cargo/bin:$PATH"
NODE_BIN="${REPO_ROOT}/target/debug/dds-node"
E2E_BIN="${REPO_ROOT}/target/debug/dds-macos-e2e"
AGENT_DLL="${REPO_ROOT}/platform/macos/DdsPolicyAgent/bin/Debug/net9.0/DdsPolicyAgent.MacOS.dll"
DOTNET_BIN="$(command -v dotnet)"
RUN_ROOT="/tmp/dds-macos-smoke-$$"
FULL_MODE=false
FAILED=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sudo) FULL_MODE=true; shift ;;
    --run-root) RUN_ROOT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: smoke-test.sh [--sudo] [--run-root <DIR>]"
      echo "  --sudo    Enable full enforcement (launchd + pkg install, requires sudo)"
      echo "  Default:  Preference enforcement only (no sudo needed)"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ---- Preflight ----
[[ -x "${NODE_BIN}" ]] || { echo "FAIL: missing dds-node binary. Run: cargo build -p dds-node --bin dds-node --bin dds-macos-e2e" >&2; exit 1; }
[[ -x "${E2E_BIN}" ]] || { echo "FAIL: missing dds-macos-e2e binary. Run: cargo build -p dds-node --bin dds-macos-e2e" >&2; exit 1; }
[[ -f "${AGENT_DLL}" ]] || { echo "FAIL: missing agent DLL. Run: dotnet build platform/macos/DdsPolicyAgent/DdsPolicyAgent.MacOS.csproj" >&2; exit 1; }
[[ -n "${DOTNET_BIN}" ]] || { echo "FAIL: dotnet not found" >&2; exit 1; }

cleanup() {
  echo ""
  echo "=== Cleanup ==="
  if [[ -f "${RUN_ROOT}/agent.pid" ]]; then
    kill "$(cat "${RUN_ROOT}/agent.pid")" 2>/dev/null || true
  fi
  if [[ -f "${RUN_ROOT}/node.pid" ]]; then
    kill "$(cat "${RUN_ROOT}/node.pid")" 2>/dev/null || true
  fi
  if ${FULL_MODE}; then
    sudo launchctl bootout system/com.dds.e2e.marker 2>/dev/null || true
    sudo pkgutil --forget com.dds.e2e.marker 2>/dev/null || true
  fi
  rm -rf "${RUN_ROOT}"
  echo "  cleaned ${RUN_ROOT}"
}
if [[ -z "${DDS_SMOKE_KEEP:-}" ]]; then
  trap cleanup EXIT
fi

pass() { echo "  PASS: $1"; }
fail() { echo "  FAIL: $1" >&2; FAILED=true; }

# ---- Pick free ports ----
API_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')
P2P_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("",0)); print(s.getsockname()[1]); s.close()')

echo "=== DDS macOS Smoke Test ==="
echo "  mode:      $(${FULL_MODE} && echo 'full (sudo)' || echo 'preference-only')"
echo "  run_root:  ${RUN_ROOT}"
echo "  api_port:  ${API_PORT}"
echo "  p2p_port:  ${P2P_PORT}"
echo ""

# ---- Setup directories ----
mkdir -p \
  "${RUN_ROOT}/node-data" \
  "${RUN_ROOT}/domain" \
  "${RUN_ROOT}/logs" \
  "${RUN_ROOT}/packages" \
  "${RUN_ROOT}/state" \
  "${RUN_ROOT}/profiles" \
  "${RUN_ROOT}/ManagedPreferences" \
  "${RUN_ROOT}/UserTemplatePreferences" \
  "${RUN_ROOT}/LaunchDaemons" \
  "${RUN_ROOT}/LaunchAgents" \
  "${RUN_ROOT}/install-root"

# ---- Step 1: Init domain ----
echo "=== Step 1: Init domain ==="
"${NODE_BIN}" init-domain --name smoke-test --dir "${RUN_ROOT}/domain"
DOMAIN_FILE="${RUN_ROOT}/domain/domain.toml"
DOMAIN_KEY="${RUN_ROOT}/domain/domain_key.cbor"
# init-domain may write domain_key.bin (unencrypted) or domain_key.cbor
if [[ ! -f "${DOMAIN_KEY}" && -f "${RUN_ROOT}/domain/domain_key.bin" ]]; then
  DOMAIN_KEY="${RUN_ROOT}/domain/domain_key.bin"
fi
[[ -f "${DOMAIN_FILE}" && -f "${DOMAIN_KEY}" ]] || { echo "FAIL: domain init failed" >&2; exit 1; }
echo "  domain initialized"

# ---- Step 2: Gen node key + admit ----
echo "=== Step 2: Gen node key + admit ==="
"${NODE_BIN}" gen-node-key --data-dir "${RUN_ROOT}/node-data" > "${RUN_ROOT}/gen-node-key.out" 2>&1
PEER_ID="$(awk '/peer_id:/ { print $2 }' "${RUN_ROOT}/gen-node-key.out" | tail -n 1)"
[[ -n "${PEER_ID}" ]] || { echo "FAIL: could not determine peer_id" >&2; exit 1; }

"${NODE_BIN}" admit \
  --domain-key "${DOMAIN_KEY}" \
  --domain "${DOMAIN_FILE}" \
  --peer-id "${PEER_ID}" \
  --out "${RUN_ROOT}/node-data/admission.cbor"
echo "  admitted: ${PEER_ID}"

# ---- Step 3: Write config + start node ----
echo "=== Step 3: Start dds-node ==="

DOMAIN_NAME="$(awk -F'= ' '/^name = / { gsub(/"/, "", $2); print $2 }' "${DOMAIN_FILE}")"
DOMAIN_ID="$(awk -F'= ' '/^id = / { gsub(/"/, "", $2); print $2 }' "${DOMAIN_FILE}")"
DOMAIN_PUBKEY="$(awk -F'= ' '/^pubkey = / { gsub(/"/, "", $2); print $2 }' "${DOMAIN_FILE}")"

# C-3: generate a deterministic e2e publisher identity and seed node_a's
# `trusted_roots` with its URN. The publisher then self-vouches for
# `dds:policy-publisher-macos` + `dds:software-publisher` (see
# `publish_fixture` in dds-macos-e2e), and `publisher_capability_ok`
# admits the tokens because the vouch's issuer is a trusted root.
PUBLISHER_SEED="${RUN_ROOT}/publisher-seed.hex"
"${E2E_BIN}" gen-publisher-seed --out "${PUBLISHER_SEED}" > "${RUN_ROOT}/publisher-seed.out"
PUBLISHER_URN="$(awk '/^urn:/ { print $2 }' "${RUN_ROOT}/publisher-seed.out")"
[[ -n "${PUBLISHER_URN}" ]] || { echo "FAIL: could not derive publisher URN" >&2; exit 1; }

cat > "${RUN_ROOT}/dds.toml" <<EOF
data_dir = "${RUN_ROOT}/node-data"
org_hash = "smoke-test"
trusted_roots = ["${PUBLISHER_URN}"]

[network]
listen_addr = "/ip4/127.0.0.1/tcp/${P2P_PORT}"
bootstrap_peers = []
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

"${NODE_BIN}" run "${RUN_ROOT}/dds.toml" > "${RUN_ROOT}/logs/node.log" 2>&1 &
echo $! > "${RUN_ROOT}/node.pid"

NODE_URL="http://127.0.0.1:${API_PORT}"
for _ in {1..30}; do
  curl -sf "${NODE_URL}/v1/status" >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sf "${NODE_URL}/v1/status" >/dev/null 2>&1 || { echo "FAIL: node did not start" >&2; cat "${RUN_ROOT}/logs/node.log"; exit 1; }
echo "  node started at ${NODE_URL}"

# ---- Step 4: Enroll device ----
echo "=== Step 4: Enroll device ==="
curl -sSf \
  -X POST "${NODE_URL}/v1/enroll/device" \
  -H 'Content-Type: application/json' \
  -d "{
    \"label\": \"smoke\",
    \"device_id\": \"DDS-MACOS-SMOKE-$$\",
    \"hostname\": \"$(hostname)\",
    \"os\": \"macOS\",
    \"os_version\": \"$(sw_vers -productVersion)\",
    \"tpm_ek_hash\": null,
    \"org_unit\": \"smoke-test\",
    \"tags\": [\"dds-macos-e2e\", \"smoke\"]
  }" > "${RUN_ROOT}/enroll-device.json"

DEVICE_URN="$(plutil -extract urn raw -o - "${RUN_ROOT}/enroll-device.json")"
echo "${DEVICE_URN}" > "${RUN_ROOT}/device-urn.txt"
echo "  enrolled: ${DEVICE_URN}"

# ---- Step 5: Build marker package ----
echo "=== Step 5: Build marker package ==="
PKG_VERSION="1.0.0"
PKG_ID="com.dds.e2e.marker"
"${SCRIPT_DIR}/build-marker-package.sh" --version "${PKG_VERSION}" --run-root "${RUN_ROOT}"
echo "  marker package built"

# ---- Step 6: Create launchd plist ----
echo "=== Step 6: Create launchd plist ==="
cat > "${RUN_ROOT}/LaunchDaemons/com.dds.e2e.marker.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.dds.e2e.marker</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/true</string>
  </array>
  <key>RunAtLoad</key>
  <false/>
</dict>
</plist>
EOF
echo "  plist created"

# ---- Step 7: Publish fixture into the mesh ----
echo "=== Step 7: Publish fixture ==="
PACKAGE_SHA="$(cat "${RUN_ROOT}/packages/${PKG_ID}.sha256")"
PACKAGE_SOURCE="file://${RUN_ROOT}/packages/${PKG_ID}.pkg"
BOOTSTRAP_PEER="/ip4/127.0.0.1/tcp/${P2P_PORT}/p2p/${PEER_ID}"

"${E2E_BIN}" publish \
  --domain-key "${DOMAIN_KEY}" \
  --domain "${DOMAIN_FILE}" \
  --bootstrap-peer "${BOOTSTRAP_PEER}" \
  --org-hash smoke-test \
  --tag dds-macos-e2e \
  --policy-id e2e/macos-smoke \
  --policy-version 1 \
  --package-id "${PKG_ID}" \
  --package-display-name "DDS macOS Smoke Marker" \
  --package-version "${PKG_VERSION}" \
  --package-source "${PACKAGE_SOURCE}" \
  --package-sha256 "${PACKAGE_SHA}" \
  --preference-domain com.dds.e2e \
  --preference-key FleetMessage \
  --preference-value-json '"smoke-test-pass"' \
  --launchd-label com.dds.e2e.marker \
  --launchd-plist-path "${RUN_ROOT}/LaunchDaemons/com.dds.e2e.marker.plist" \
  --launchd-marker-path "${RUN_ROOT}/launchd-fired.txt" \
  --package-marker-path "${RUN_ROOT}/install-root/software-installed.txt" \
  --out "${RUN_ROOT}/manifest.json" \
  --publisher-seed-file "${PUBLISHER_SEED}" \
  --connect-timeout-secs 30 2>&1 | tail -5
echo "  fixture published"

# Wait for gossip convergence (poll up to 15 s in case the CI runner is slow)
POLICY_COUNT=0
for _pi in {1..15}; do
  POLICY_COUNT=$(curl -sf "${NODE_URL}/v1/macos/policies?device_urn=${DEVICE_URN}" \
    | python3 -c "
import json, sys, base64
env = json.load(sys.stdin)
inner = json.loads(base64.b64decode(env['payload_b64'])) if 'payload_b64' in env else env
print(len(inner.get('policies', [])))
" 2>/dev/null || echo 0)
  [[ "${POLICY_COUNT}" -ge 1 ]] && break
  sleep 1
done
echo "  policies visible: ${POLICY_COUNT}"
if [[ "${POLICY_COUNT}" -lt 1 ]]; then
  echo "FAIL: no policies visible after publish" >&2
  echo "=== Node log (last 120 lines) ===" >&2
  tail -n 120 "${RUN_ROOT}/logs/node.log" >&2 || true
  echo "=== Node status ===" >&2
  curl -sf "${NODE_URL}/v1/status" 2>/dev/null >&2 || true
  exit 1
fi

# ---- Step 8: Run agent for one poll cycle ----
echo "=== Step 8: Run policy agent ==="

export DDS_POLICYAGENT_ASSUME_ROOT=1
export DdsPolicyAgent__DeviceUrn="${DEVICE_URN}"
export DdsPolicyAgent__NodeBaseUrl="${NODE_URL}"

# H-3: the macOS agent pins the running node's Ed25519 pubkey and
# fails startup without it. Pull it from `/v1/node/info` now — in a
# production install this is baked in by the provisioning bundle.
NODE_PUBKEY_B64=$(curl -sf "${NODE_URL}/v1/node/info" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['node_pubkey_b64'])")
[[ -n "${NODE_PUBKEY_B64}" ]] || { echo "FAIL: could not fetch node pubkey" >&2; exit 1; }
export DdsPolicyAgent__PinnedNodePubkeyB64="${NODE_PUBKEY_B64}"
export DdsPolicyAgent__PollIntervalSeconds=5
export DdsPolicyAgent__StateDir="${RUN_ROOT}/state"
export DdsPolicyAgent__ManagedPreferencesDir="${RUN_ROOT}/ManagedPreferences"
export DdsPolicyAgent__UserTemplatePreferencesDir="${RUN_ROOT}/UserTemplatePreferences"
export DdsPolicyAgent__LaunchDaemonPlistDir="${RUN_ROOT}/LaunchDaemons"
export DdsPolicyAgent__LaunchAgentPlistDir="${RUN_ROOT}/LaunchAgents"
export DdsPolicyAgent__LaunchdDomain="system"
export DdsPolicyAgent__LaunchdStateFile="${RUN_ROOT}/state/launchd-state.json"
export DdsPolicyAgent__PackageCacheDir="${RUN_ROOT}/packages"
export DdsPolicyAgent__ProfileStateDir="${RUN_ROOT}/profiles"
export DdsPolicyAgent__PackageInstallTarget="${RUN_ROOT}/install-root"
export DdsPolicyAgent__RequirePackageSignature=false
export DdsPolicyAgent__AllowInlinePackageScripts=false

"${DOTNET_BIN}" "${AGENT_DLL}" > "${RUN_ROOT}/logs/agent.log" 2>&1 &
AGENT_PID=$!
echo $AGENT_PID > "${RUN_ROOT}/agent.pid"
echo "  agent started (pid=${AGENT_PID})"

# Wait for the agent to complete one poll cycle
for _ in {1..40}; do
  if [[ -f "${RUN_ROOT}/state/applied-state.json" ]]; then
    sleep 2  # let it finish writing
    break
  fi
  sleep 1
done

kill "${AGENT_PID}" 2>/dev/null || true
wait "${AGENT_PID}" 2>/dev/null || true
rm -f "${RUN_ROOT}/agent.pid"
echo "  agent stopped after poll cycle"

# ---- Step 9: Validate ----
echo ""
echo "=== Validation ==="
CHECKS_PASSED=0
CHECKS_TOTAL=0

# Check 1: applied-state.json exists
CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
if [[ -f "${RUN_ROOT}/state/applied-state.json" ]]; then
  pass "applied-state.json created"
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
  fail "applied-state.json not created"
fi

# Check 2: Policy was applied
CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
if [[ -f "${RUN_ROOT}/state/applied-state.json" ]] && python3 -c "
import json, sys
state = json.load(open('${RUN_ROOT}/state/applied-state.json'))
policies = state.get('policies', {})
if any('e2e/macos-smoke' in k for k in policies):
    entry = [v for k,v in policies.items() if 'e2e/macos-smoke' in k][0]
    print(f'  status={entry.get(\"status\",\"?\")}, version={entry.get(\"version\",\"?\")}')
    sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
  pass "policy e2e/macos-smoke recorded in applied state"
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
  fail "policy e2e/macos-smoke not found in applied state"
fi

# Check 3: Managed preference was written
CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
PREF_PLIST="${RUN_ROOT}/ManagedPreferences/com.dds.e2e.plist"
if [[ -f "${PREF_PLIST}" ]]; then
  PREF_VALUE="$(plutil -extract FleetMessage raw -o - "${PREF_PLIST}" 2>/dev/null || echo '')"
  if [[ "${PREF_VALUE}" == "smoke-test-pass" ]]; then
    pass "preference com.dds.e2e:FleetMessage = 'smoke-test-pass'"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
  else
    fail "preference value '${PREF_VALUE}' (expected 'smoke-test-pass')"
  fi
else
  fail "managed preference plist not created at ${PREF_PLIST}"
fi

# Check 4: Launchd state file (Configure called — writes binding even without real launchctl)
CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
LAUNCHD_STATE="${RUN_ROOT}/state/launchd-state.json"
if [[ -f "${LAUNCHD_STATE}" ]] && python3 -c "
import json, sys
state = json.load(open('${LAUNCHD_STATE}'))
sys.exit(0 if 'com.dds.e2e.marker' in state else 1)
" 2>/dev/null; then
  pass "launchd state binding for com.dds.e2e.marker"
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
  # Launchd Configure writes the state file and validates the plist label,
  # but the subsequent Load/Kickstart requires real launchctl (root).
  # The Configure step should still succeed and write the binding.
  if [[ -f "${LAUNCHD_STATE}" ]]; then
    fail "launchd state file exists but missing marker entry"
  else
    fail "launchd state file not created (Configure step may have failed)"
  fi
fi

# Check 5: Software state recorded
CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
if [[ -f "${RUN_ROOT}/state/applied-state.json" ]] && python3 -c "
import json, sys
state = json.load(open('${RUN_ROOT}/state/applied-state.json'))
sw = state.get('software', {})
if any('marker' in k for k in sw):
    sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
  pass "software assignment recorded in applied state"
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
  # Software install requires real installer command — may fail without sudo
  if ${FULL_MODE}; then
    fail "software assignment not recorded"
  else
    echo "  SKIP: software install (expected in preference-only mode)"
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
  fi
fi

# Check 6: Node status healthy
CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
if curl -sf "${NODE_URL}/v1/status" | python3 -c "
import json,sys
d = json.load(sys.stdin)
sys.exit(0 if d.get('token_count', d.get('trust_graph_tokens', 0)) > 0 else 1)
" 2>/dev/null; then
  pass "node healthy with tokens in trust graph"
  CHECKS_PASSED=$((CHECKS_PASSED + 1))
else
  fail "node unhealthy or no tokens"
fi

# ---- Summary ----
echo ""
echo "=== Results ==="
echo "  ${CHECKS_PASSED}/${CHECKS_TOTAL} checks passed"

if ${FAILED}; then
  echo ""
  echo "SMOKE TEST FAILED"
  echo ""
  echo "=== Node log (last 150 lines) ==="
  tail -n 150 "${RUN_ROOT}/logs/node.log" 2>/dev/null || echo "(no node log)"
  echo "=== Agent log (last 80 lines) ==="
  tail -n 80 "${RUN_ROOT}/logs/agent.log" 2>/dev/null || echo "(no agent log)"
  # Keep run_root for local inspection
  trap - EXIT
  exit 1
fi

echo ""
echo "SMOKE TEST PASSED"
exit 0
