# macOS — Keychain-Sealed `DDS_NODE_PASSPHRASE`

This is the macOS side of the sealed-passphrase design (see
[`docs/sealed-passphrase-design.md`](../../../docs/sealed-passphrase-design.md)
for the cross-platform picture). It uses the **System Keychain** to
wrap the node passphrase so node keys can be encrypted at rest
**without** an operator typing or touching anything at boot.

On Apple Silicon the System Keychain master key is hardware-bound (per-machine
`SystemKey` blob, with SEP involvement); on Intel Macs it's bound to the
machine via the same blob. Either way the sealed passphrase does not
unwrap on a different host.

## Boot timing

`securityd` unlocks `/Library/Keychains/System.keychain` very early in
boot using `/var/db/SystemKey` — well before any LaunchDaemon starts.
By the time the dds-node LaunchDaemon launches, the System Keychain is
already accessible. **No service-ordering work needed.**

## End-user flow (typical: joining an existing domain)

After `installer -pkg DDS-Platform-macOS-X.Y.Z-arm64.pkg -target /`:

```sh
sudo dds-node provision /path/to/provision.dds
```

That's it. On first run, `dds-node provision` detects the .pkg helpers
at `/usr/local/sbin/dds-keychain-{seal,unseal}` and:

1. Seals a fresh random passphrase into the System Keychain
   (service `"DDS Node Passphrase"`, account `<hostname-short>`).
2. Stamps `DDS_NODE_PASSPHRASE` into its own process env.
3. Continues provision — `node_key.bin` and `p2p_key.bin` land
   encrypted (CBOR `v=3`, Argon2id+ChaCha20-Poly1305).

The LaunchDaemon plist
([`com.dds.node.plist`](com.dds.node.plist)) invokes
`/usr/local/sbin/dds-launchd-wrapper`, which unseals the passphrase
from the keychain at every service start. The operator never types or
touches anything after `provision` returns.

## Re-provision behaviour

`dds-node provision` first tries to *reuse* an existing sealed
passphrase before creating a new one. So a re-provision (after a
`rm -rf "/Library/Application Support/DDS/node-data"`) keeps the same
keychain entry. To force-rotate the passphrase, delete the keychain
item first:

```sh
sudo security delete-generic-password \
    -s "DDS Node Passphrase" -a "$(hostname -s)" \
    /Library/Keychains/System.keychain
```

The next `dds-node provision` will seal a new one.

## Existing already-provisioned host

For a host that was provisioned **before** the auto-seal landed (or
manually with `DDS_NODE_PASSPHRASE=""`), use `dds-node rewrap-identity`
to re-encrypt the existing keys under the sealed passphrase **without**
rotating the PeerId or invalidating the admission cert.

```sh
# 1. Seal a fresh passphrase into the System Keychain.
pass="$(sudo /usr/local/sbin/dds-keychain-seal)"

# 2. Stop the LaunchDaemon.
sudo launchctl unload /Library/LaunchDaemons/com.dds.node.plist

# 3. Rewrap the keys in place (PeerId unchanged).
sudo env DDS_NODE_PASSPHRASE="$pass" \
    /usr/local/bin/dds-node rewrap-identity \
    --data-dir "/Library/Application Support/DDS/node-data"
unset pass

# 4. Reload — the wrapper unseals from the keychain at every start.
sudo launchctl bootstrap system /Library/LaunchDaemons/com.dds.node.plist
```

Backups (`node_key.bin.bak`, `p2p_key.bin.bak`) are written
automatically before the overwrite unless `--no-backup` is passed.

If the keys are already encrypted under a **different** old passphrase,
supply the old one via `DDS_NODE_PASSPHRASE_OLD`:

```sh
export DDS_NODE_PASSPHRASE_OLD=<old_passphrase>
export DDS_NODE_PASSPHRASE=<new_passphrase>
sudo -E /usr/local/bin/dds-node rewrap-identity \
    --data-dir "/Library/Application Support/DDS/node-data"
unset DDS_NODE_PASSPHRASE_OLD DDS_NODE_PASSPHRASE
```

## Manual install (no .pkg)

If you're working from a hand-built dds-node and not the .pkg, the
helpers don't ship to `/usr/local/sbin/`. Auto-seal silently
falls through and `provision` writes plaintext keys. To opt in:

```sh
sudo install -m 0755 platform/macos/packaging/helpers/dds-keychain-seal.sh \
    /usr/local/sbin/dds-keychain-seal
sudo install -m 0755 platform/macos/packaging/helpers/dds-keychain-unseal.sh \
    /usr/local/sbin/dds-keychain-unseal
sudo install -m 0755 platform/macos/packaging/helpers/dds-launchd-wrapper.sh \
    /usr/local/sbin/dds-launchd-wrapper
```

Then re-run `dds-node provision` (or `rewrap-identity` for an
already-provisioned node) — auto-seal kicks in.

## Verifying

After enabling, restart the daemon and look at logs:

```sh
sudo launchctl kickstart -k system/com.dds.node
tail -50 /var/log/dds/dds-node.out /var/log/dds/dds-node.err
```

You should see `loaded node identity` / `loaded libp2p identity`
without the "stored unencrypted" informational line. The wrapper
exports `DDS_NODE_PASSPHRASE` from the keychain on every start; the
passphrase only ever exists in the wrapper's process memory and the
inherited dds-node process — never on disk.

## Troubleshooting

**`security: SecKeychainSearchCopyNext: The specified item could not be
found in the keychain.`** — sealed passphrase doesn't exist for this
host. The LaunchDaemon wrapper falls through; node keys stay
plaintext. Run `dds-keychain-seal` (or re-provision) if you want to fix it.

**`Error: Crypto("decrypt: aead::Error")` at startup** — keychain item
present but its value doesn't decrypt the existing node keys. Common
cause: passphrase was rotated under the keys (e.g., `delete-generic-password`
+ `dds-keychain-seal` while keys were already encrypted). Recovery:
either restore the old passphrase from a backup, or
`dds-node rewrap-identity` with `DDS_NODE_PASSPHRASE_OLD` set to the
old passphrase, or accept loss of the encrypted keys and re-provision.

**Restoring on a different Mac.** The System Keychain master key is
host-bound. Sealed items don't move between Macs. For DR, keep an
off-keychain backup of the *plaintext* node keys under separate
controls (or rely on re-provisioning from the bundle).
