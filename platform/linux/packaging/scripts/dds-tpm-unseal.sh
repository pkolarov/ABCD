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
#
# NOTE: primary.ctx saved by dds-tpm-seal is a transient TPM handle
# that becomes invalid after a power cycle — the TPM resets all loaded
# objects on reboot. We therefore re-derive the primary key fresh on
# every unseal call using the same algorithm and hierarchy so that it
# is deterministically identical to the key used at seal time.

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

# Ephemeral context files in tmpfs — cleaned up on exit.
PRIMARY_CTX="$(mktemp -p /run dds-primary.ctx.XXXXXX 2>/dev/null || mktemp)"
CTX="$(mktemp -p /run dds-seal.ctx.XXXXXX 2>/dev/null || mktemp)"
trap 'rm -f "$PRIMARY_CTX" "$CTX"' EXIT INT TERM

# Re-derive the owner-hierarchy primary key with the same algorithm
# used at seal time. TPM2 primary keys are deterministic — same
# hierarchy + same template = same key — so this produces an identical
# parent to load the sealed object against.
tpm2_createprimary -Q -C o -c "$PRIMARY_CTX" -G ecc

tpm2_load -Q -C "$PRIMARY_CTX" \
    -u "$SEAL_DIR/seal.pub" -r "$SEAL_DIR/seal.priv" -c "$CTX"

PASS="$(tpm2_unseal -Q -c "$CTX" | base64 | tr -d '\n')"

if [ -n "$ENVFILE" ]; then
    install -m 0600 /dev/null "$ENVFILE"
    printf 'DDS_NODE_PASSPHRASE=%s\n' "$PASS" > "$ENVFILE"
else
    printf '%s\n' "$PASS"
fi
