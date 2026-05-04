#!/bin/sh
# DDS Linux — seal a randomly-generated DDS_NODE_PASSPHRASE under TPM2.
#
# One-time setup. Run BEFORE `dds-node provision` so node_key.bin and
# p2p_key.bin land encrypted from the start. Outputs the plaintext
# passphrase (base64) on stdout for the caller to feed into provision.
#
#   pass="$(dds-tpm-seal)"
#   DDS_NODE_PASSPHRASE="$pass" dds-node provision <bundle> --data-dir /var/lib/dds/node
#
# After this, the OpenRC conf.d block and systemd ExecStartPre call
# dds-tpm-unseal at every service start, so the operator never re-enters
# the passphrase.
#
# Storage: $SEAL_DIR/{primary.ctx,seal.pub,seal.priv}, mode 0600 root.
# Plaintext passphrase exists only in /dev/shm during this script's
# lifetime, then is shred'd.

set -eu

SEAL_DIR="${1:-/var/lib/dds/node}"

if ! command -v tpm2_createprimary >/dev/null 2>&1; then
    echo "tpm2-tools is required (Alpine: apk add tpm2-tools)" >&2
    exit 1
fi
if [ ! -e /dev/tpm0 ] && [ ! -e /dev/tpmrm0 ]; then
    echo "no /dev/tpm{0,rm0} — TPM not available on this host" >&2
    exit 1
fi

mkdir -p "$SEAL_DIR"
chmod 0700 "$SEAL_DIR"

# Owner hierarchy, ECC primary key, default policy.
tpm2_createprimary -Q -C o -c "$SEAL_DIR/primary.ctx" -G ecc

# 32 bytes of randomness in tmpfs only.
PASS_BIN="$(mktemp -p /dev/shm dds-pass.XXXXXX 2>/dev/null || mktemp)"
trap 'shred -u "$PASS_BIN" 2>/dev/null || rm -f "$PASS_BIN"' EXIT INT TERM
dd if=/dev/urandom of="$PASS_BIN" bs=32 count=1 status=none

# Seal — produces seal.pub + seal.priv (must tpm2_load before unseal).
tpm2_create -Q -C "$SEAL_DIR/primary.ctx" -i "$PASS_BIN" \
    -u "$SEAL_DIR/seal.pub" -r "$SEAL_DIR/seal.priv"

chmod 0600 "$SEAL_DIR/primary.ctx" "$SEAL_DIR/seal.pub" "$SEAL_DIR/seal.priv"

# Emit base64 — DDS_NODE_PASSPHRASE is read as a UTF-8 string and
# random bytes can contain NUL.
base64 < "$PASS_BIN" | tr -d '\n'
echo
