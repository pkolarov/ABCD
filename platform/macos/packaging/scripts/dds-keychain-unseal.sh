#!/bin/sh
# DDS macOS — unseal DDS_NODE_PASSPHRASE from the System Keychain.
#
# Outputs the base64 passphrase on stdout. Exits 1 silently when the
# item doesn't exist, so the LaunchDaemon wrapper can fall through to
# plaintext-at-rest without breaking service start.
#
# Usage:
#   dds-keychain-unseal [KEYCHAIN]
# Default KEYCHAIN: /Library/Keychains/System.keychain

set -eu

KEYCHAIN="${1:-/Library/Keychains/System.keychain}"
SERVICE="DDS Node Passphrase"
ACCOUNT="$(hostname -s)"

if ! command -v security >/dev/null 2>&1; then exit 1; fi
if [ ! -f "$KEYCHAIN" ]; then exit 1; fi

# `-w` outputs the password only (no metadata).
security find-generic-password -w \
    -s "$SERVICE" \
    -a "$ACCOUNT" \
    "$KEYCHAIN" 2>/dev/null
