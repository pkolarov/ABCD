# Linux — TPM-Sealed `DDS_NODE_PASSPHRASE`

This is the Linux side of the sealed-passphrase design (see
[`docs/sealed-passphrase-design.md`](../../../docs/sealed-passphrase-design.md)
for the cross-platform picture). It uses the on-host TPM2 to wrap the
node passphrase so node keys can be encrypted at rest **without** an
operator typing or touching anything at boot.

## When to use this

- Production servers where physical-disk theft is in scope.
- Hosts with a TPM (real hardware, or `swtpm` in UTM/QEMU).

If the host has no TPM, just don't seal — node keys at rest under
mode 0600 root are the default. The unseal hook is a no-op and the
service still boots.

## Prereqs

```sh
apk add tpm2-tools         # Alpine
# or
apt install tpm2-tools     # Debian/Ubuntu

ls /dev/tpm0 /dev/tpmrm0   # at least one must exist
```

The helper scripts (`/usr/local/sbin/dds-tpm-seal` and
`/usr/local/sbin/dds-tpm-unseal`) ship in the Linux package.

## One-time setup

```sh
# 1. Seal a fresh random passphrase. Outputs the base64 plaintext
#    passphrase on stdout — capture it, don't echo it.
pass="$(sudo /usr/local/sbin/dds-tpm-seal /var/lib/dds/node)"

# 2. Provision with that passphrase set, so node_key.bin and
#    p2p_key.bin are written encrypted from the start. (For existing
#    already-provisioned hosts use rewrap-identity instead — see below.)
sudo env DDS_NODE_PASSPHRASE="$pass" \
    /usr/local/bin/dds-node provision /path/to/provision.dds \
    --data-dir /var/lib/dds/node --no-start

# 3. Drop the plaintext passphrase from your shell.
unset pass

# 4. Enable + start the service. The OpenRC conf.d block / systemd
#    ExecStartPre= will unseal automatically at every start.
sudo rc-update add dds-node default     # Alpine / OpenRC
sudo rc-service dds-node start
# or:
sudo systemctl enable --now dds-node    # systemd
```

After this, `/var/lib/dds/node/` contains:

```
admission.cbor       # signed admission cert (plaintext, public)
domain.toml          # joined-domain info (plaintext, public)
epoch_keys.cbor      # epoch encryption keys
node_key.bin         # node identity, AES-GCM + Argon2id wrap
p2p_key.bin          # libp2p keypair, ChaCha20-Poly1305 + Argon2id wrap
primary.ctx          # TPM2 owner-hierarchy primary key context
seal.pub seal.priv   # TPM2-sealed object holding the passphrase
```

## Existing already-provisioned host

Use `dds-node rewrap-identity` to re-encrypt the existing keys under
the sealed passphrase **without** rotating the PeerId or invalidating
the admission cert.

```sh
# 1. Seal a fresh passphrase into the TPM.
pass="$(sudo /usr/local/sbin/dds-tpm-seal /var/lib/dds/node)"

# 2. Stop the service so the node isn't holding the key files open.
sudo rc-service dds-node stop     # OpenRC
# or: sudo systemctl stop dds-node

# 3. Rewrap the keys in place (PeerId unchanged).
sudo env DDS_NODE_PASSPHRASE="$pass" \
    /usr/local/bin/dds-node rewrap-identity \
    --data-dir /var/lib/dds/node
unset pass

# 4. Start the service — the TPM unseal hook supplies DDS_NODE_PASSPHRASE.
sudo rc-service dds-node start
```

Backups (`node_key.bin.bak`, `p2p_key.bin.bak`) are written
automatically before the overwrite unless `--no-backup` is passed.

If the keys are already encrypted under a **different** old passphrase
(e.g., rotating to a new TPM-bound secret after a PCR policy change),
supply the old one via `DDS_NODE_PASSPHRASE_OLD`:

```sh
export DDS_NODE_PASSPHRASE_OLD=<old_passphrase>
export DDS_NODE_PASSPHRASE=<new_passphrase>
sudo -E /usr/local/bin/dds-node rewrap-identity \
    --data-dir /var/lib/dds/node
unset DDS_NODE_PASSPHRASE_OLD DDS_NODE_PASSPHRASE
```

For brand-new hosts, do the seal step **before** `dds-node provision`
so this isn't an issue.

## Verifying the unseal works

After enabling, restart the service and inspect logs:

```sh
sudo rc-service dds-node restart
sudo tail -50 /var/log/dds/dds-node.log
```

You should see the node startup proceed and `loaded node identity` /
`loaded libp2p identity` lines without the `stored unencrypted`
informational line. The `dds-tpm-unseal --env-file` helper writes
`/run/dds/passphrase.env` (mode 0600) at every start; the systemd
`ExecStopPost=` shreds it on stop.

## Troubleshooting

**`refusing to overwrite encrypted identity at … with plaintext`** —
the seal blobs are gone or unreadable, but a prior run encrypted the
keys. Either restore the seal blobs, or for a one-shot drop-back:

```sh
sudo env DDS_ALLOW_PLAINTEXT_DOWNGRADE=1 rc-service dds-node restart
```

That re-saves the keys plaintext on the next save. Use only if you've
genuinely lost the seal blobs and don't have a backup.

**`/dev/tpm0` missing in a UTM VM** — UTM doesn't expose a TPM by
default. Edit the VM (stopped) → Devices → add a TPM 2.0 device. UTM
uses `swtpm` under the hood. After boot the device shows up.

**Backup-restore on a different host** — the TPM owner-hierarchy
primary key is host-bound. Sealed blobs from one host won't unseal on
another. For DR, keep an off-TPM backup of the *plaintext* node keys
under separate access controls (or rely on re-provisioning from the
bundle).
