#!/bin/sh
# DDS macOS — seal a randomly-generated DDS_NODE_PASSPHRASE into the
# System Keychain. One-time setup; outputs the plaintext passphrase
# (base64) on stdout for the caller to feed into `dds-node provision`.
#
# Usage:
#   dds-keychain-seal [KEYCHAIN]
#
# Default KEYCHAIN: /Library/Keychains/System.keychain (the only
# keychain that's unlocked early in boot by securityd, so it's the
# one a LaunchDaemon can read without user interaction).
#
# Then:
#   pass="$(sudo dds-keychain-seal)"
#   sudo env DDS_NODE_PASSPHRASE="$pass" \
#       dds-node provision <bundle> --no-start
#
# After this the dds-launchd-wrapper unseals at every service start,
# so the operator never re-enters the passphrase.
#
# On Apple Silicon the System Keychain master key is hardware-bound
# (per-machine SystemKey blob); on Intel Macs it's bound to the
# machine via the same blob. Either way the sealed passphrase does
# not unwrap on a different host.

set -eu

KEYCHAIN="${1:-/Library/Keychains/System.keychain}"
SERVICE="DDS Node Passphrase"
ACCOUNT="$(hostname -s)"

if ! command -v security >/dev/null 2>&1; then
    echo "macOS 'security' tool not found" >&2
    exit 1
fi
if [ ! -f "$KEYCHAIN" ]; then
    echo "keychain not found: $KEYCHAIN" >&2
    exit 1
fi

# Refuse to overwrite an existing item — operator must explicitly
# delete (security delete-generic-password ...) so we never silently
# rotate a passphrase out from under encrypted node keys.
if security find-generic-password -s "$SERVICE" -a "$ACCOUNT" "$KEYCHAIN" >/dev/null 2>&1; then
    cat >&2 <<EOF
passphrase already sealed in $KEYCHAIN
  service = $SERVICE
  account = $ACCOUNT
to replace, first delete:
  security delete-generic-password -s "$SERVICE" -a "$ACCOUNT" "$KEYCHAIN"
EOF
    exit 1
fi

# Generate base64-encoded 32 random bytes. DDS_NODE_PASSPHRASE is
# read as a UTF-8 string, so base64-encoding sidesteps NUL handling.
PASS="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"

# -A allows any application to read this item without user prompt.
# The System Keychain ACL is anchored by root context — only root can
# even open the keychain in write mode, so -A is the right tradeoff
# for an unattended LaunchDaemon. If you want tighter ACL, use
# `-T /usr/local/sbin/dds-keychain-unseal -T /usr/bin/security`
# instead, but be aware that ACL breaks if the binary path changes.
security add-generic-password \
    -A \
    -s "$SERVICE" \
    -a "$ACCOUNT" \
    -w "$PASS" \
    "$KEYCHAIN"

printf '%s\n' "$PASS"
