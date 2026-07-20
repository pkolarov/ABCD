#!/bin/zsh
# DDS Uninstall — fully remove the DDS Platform from this Mac.
#
#   sudo dds-uninstall [-f|--force] [-k|--keep-data]
#
# Mirrors platform/windows/installer/scripts/Uninstall-Dds.ps1's
# -Force/-KeepData/"type WIPE to confirm" pattern: this is a destructive
# operation (it can permanently remove this node's domain key and
# admission cert) and deserves that ceremony even though the rest of
# this project's macOS tooling stays deliberately simple.
#
# -f, --force       Skip the WIPE confirmation prompt.
# -k, --keep-data   Remove binaries/LaunchDaemons/keychain item, but
#                   leave "/Library/Application Support/DDS" (domain
#                   key, admission cert, node identity) in place.
set -euo pipefail

FORCE=0
KEEP_DATA=0
for arg in "$@"; do
  case "${arg}" in
    -f|--force) FORCE=1 ;;
    -k|--keep-data) KEEP_DATA=1 ;;
    *) echo "Unknown argument: ${arg}" >&2; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Error: run with sudo" >&2
  exit 1
fi

DDS_ROOT="/Library/Application Support/DDS"
PKG_ID="com.dds.platform"
BINARIES=(dds-node dds dds-fido2-test dds-fido2 dds-bootstrap-domain dds-enroll-admin \
          dds-admit-node dds-domain dds-user dds-account dds-uninstall)
SBIN_HELPERS=(dds-keychain-seal dds-keychain-unseal dds-launchd-wrapper)
KEYCHAIN_SERVICE="DDS Node Passphrase"
KEYCHAIN_ACCOUNT="$(hostname -s)"

echo ""
echo "=== DDS Uninstall ==="
echo ""
echo "Will stop and unload: com.dds.node, com.dds.policyagent"
echo "Will remove: /usr/local/bin/{${(j:, :)BINARIES}}"
echo "Will remove: /usr/local/sbin/{${(j:, :)SBIN_HELPERS}}"
echo "Will remove: /usr/local/lib/dds, /Library/LaunchDaemons/com.dds.{node,policyagent}.plist"
echo "Will remove pkg receipt: ${PKG_ID}"
echo "Will remove System Keychain item: \"${KEYCHAIN_SERVICE}\" (account ${KEYCHAIN_ACCOUNT})"
if [[ ${KEEP_DATA} -eq 0 ]]; then
  echo "Will WIPE: ${DDS_ROOT} (domain key, admission cert, node identity, credential store)"
else
  echo "Data dir preserved (--keep-data): ${DDS_ROOT}"
fi
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
launchctl bootout system/com.dds.policyagent 2>/dev/null || true
launchctl bootout system/com.dds.node 2>/dev/null || true

echo "Removing LaunchDaemons..."
rm -f /Library/LaunchDaemons/com.dds.node.plist /Library/LaunchDaemons/com.dds.policyagent.plist

echo "Removing binaries..."
for b in "${BINARIES[@]}"; do
  rm -f "/usr/local/bin/${b}"
done

echo "Removing sealed-passphrase helpers..."
for h in "${SBIN_HELPERS[@]}"; do
  rm -f "/usr/local/sbin/${h}"
done

echo "Removing policy agent install dir..."
rm -rf /usr/local/lib/dds

echo "Removing System Keychain item..."
security delete-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" \
  /Library/Keychains/System.keychain 2>/dev/null || true

echo "Forgetting pkg receipt..."
pkgutil --forget "${PKG_ID}" 2>/dev/null || true

if [[ ${KEEP_DATA} -eq 0 ]]; then
  echo "Removing ${DDS_ROOT}..."
  rm -rf "${DDS_ROOT}"
else
  echo "Preserving ${DDS_ROOT} (--keep-data)."
fi

echo ""
LEFT_SERVICES=0
launchctl print system/com.dds.node >/dev/null 2>&1 && LEFT_SERVICES=1
launchctl print system/com.dds.policyagent >/dev/null 2>&1 && LEFT_SERVICES=1
LEFT_DATA=0
[[ ${KEEP_DATA} -eq 0 && -d "${DDS_ROOT}" ]] && LEFT_DATA=1

if [[ ${LEFT_SERVICES} -eq 1 || ${LEFT_DATA} -eq 1 ]]; then
  echo "Uninstall finished with residue:" >&2
  [[ ${LEFT_SERVICES} -eq 1 ]] && echo "  a com.dds.* service is still loaded" >&2
  [[ ${LEFT_DATA} -eq 1 ]] && echo "  ${DDS_ROOT} still exists" >&2
  exit 1
fi

echo "DDS fully uninstalled."
