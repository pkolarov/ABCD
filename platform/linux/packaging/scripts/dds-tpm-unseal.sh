#!/bin/sh
# DDS Linux — unseal DDS_NODE_PASSPHRASE from a TPM2-sealed blob.
#
# Outputs the base64 passphrase to stdout, OR (with --env-file) writes
# `DDS_NODE_PASSPHRASE=<base64>` into a file at PATH (suitable for
# systemd EnvironmentFile=).
#
# Falls through with exit 1 (silently) when:
#   - no TPM device (/dev/tpm0 / /dev/tpmrm0 absent)
#   - no seal blobs ($SEAL_DIR/seal.priv missing)
#   - tpm2-tools not installed
#
# This is by design — the service unit treats the helper as optional
# so unsealed hosts (no TPM, or operator opted out) still boot.
#
# Usage:
#   dds-tpm-unseal [SEAL_DIR]
#   dds-tpm-unseal --env-file PATH [SEAL_DIR]

set -eu

ENVFILE=""
if [ "${1:-}" = "--env-file" ]; then
    ENVFILE="$2"
    shift 2
fi
SEAL_DIR="${1:-/var/lib/dds/node}"

if [ ! -e /dev/tpm0 ] && [ ! -e /dev/tpmrm0 ]; then exit 1; fi
if ! command -v tpm2_unseal >/dev/null 2>&1; then exit 1; fi
if [ ! -f "$SEAL_DIR/seal.priv" ] || [ ! -f "$SEAL_DIR/seal.pub" ]; then exit 1; fi
if [ ! -f "$SEAL_DIR/primary.ctx" ]; then exit 1; fi

# Ephemeral object context in tmpfs.
CTX="$(mktemp -p /run dds-seal.ctx.XXXXXX 2>/dev/null || mktemp)"
trap 'rm -f "$CTX"' EXIT INT TERM

tpm2_load -Q -C "$SEAL_DIR/primary.ctx" \
    -u "$SEAL_DIR/seal.pub" -r "$SEAL_DIR/seal.priv" -c "$CTX"

PASS="$(tpm2_unseal -Q -c "$CTX" | base64 | tr -d '\n')"

if [ -n "$ENVFILE" ]; then
    install -m 0600 /dev/null "$ENVFILE"
    printf 'DDS_NODE_PASSPHRASE=%s\n' "$PASS" > "$ENVFILE"
else
    printf '%s\n' "$PASS"
fi
