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

## Prereqs

The helper scripts ship in the macOS .pkg installer (or copy them
manually):

```sh
sudo install -m 0755 platform/macos/packaging/scripts/dds-keychain-seal.sh \
    /usr/local/sbin/dds-keychain-seal
sudo install -m 0755 platform/macos/packaging/scripts/dds-keychain-unseal.sh \
    /usr/local/sbin/dds-keychain-unseal
sudo install -m 0755 platform/macos/packaging/scripts/dds-launchd-wrapper.sh \
    /usr/local/sbin/dds-launchd-wrapper
```

The LaunchDaemon plist
([`com.dds.node.plist`](com.dds.node.plist)) already invokes the
wrapper instead of dds-node directly.

## One-time setup

```sh
# 1. Seal a fresh random passphrase. Outputs the base64 plaintext on
#    stdout — capture it, don't echo.
pass="$(sudo /usr/local/sbin/dds-keychain-seal)"

# 2. Provision (or first-time gen-node-key) with that passphrase set
#    so node_key.bin and p2p_key.bin land encrypted.
sudo env DDS_NODE_PASSPHRASE="$pass" \
    dds-node provision /path/to/provision.dds

# 3. Drop the plaintext from the shell.
unset pass

# 4. The LaunchDaemon's wrapper unseals at every start. Bring up the
#    service the usual way:
sudo launchctl bootstrap system /Library/LaunchDaemons/com.dds.node.plist
```

After this, `/Library/Application Support/DDS/node-data/` holds
encrypted `node_key.bin` / `p2p_key.bin` and the System Keychain holds
the sealed wrap key (service `"DDS Node Passphrase"`, account
`<hostname-short>`).

## Existing already-provisioned host

Same caveat as Linux: there's no `rewrap-identity` helper today, and
`rotate-identity` rotates the libp2p PeerId which invalidates the
admission cert. Two options:

1. **Re-provision** (destructive, simplest). Stop the LaunchDaemon,
   archive `/Library/Application Support/DDS/node-data`, then:
   ```sh
   sudo launchctl unload /Library/LaunchDaemons/com.dds.node.plist
   sudo rm -rf "/Library/Application Support/DDS/node-data"
   pass="$(sudo /usr/local/sbin/dds-keychain-seal)"
   sudo env DDS_NODE_PASSPHRASE="$pass" \
       dds-node provision /path/to/provision.dds
   unset pass
   sudo launchctl bootstrap system /Library/LaunchDaemons/com.dds.node.plist
   ```
   This generates a new PeerId and a fresh admission cert.

2. **Defer** until a `dds-node rewrap-identity` helper lands.

Brand-new hosts: do the seal step **before** `dds-node provision` so
this isn't an issue.

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
plaintext. Run `dds-keychain-seal` if you want to fix it.

**`Error: Crypto("decrypt: aead::Error")` at startup** — keychain item
present but its value doesn't decrypt the existing node keys. Common
cause: passphrase was rotated under the keys (e.g., `delete-generic-password`
+ `dds-keychain-seal` while keys were already encrypted). Recovery:
either restore the old passphrase from a backup, or accept loss of the
encrypted keys and re-provision.

**Restoring on a different Mac.** The System Keychain master key is
host-bound. Sealed items don't move between Macs. For DR, keep an
off-keychain backup of the *plaintext* node keys under separate
controls (or rely on re-provisioning from the bundle).

## Removing the sealed passphrase

```sh
sudo security delete-generic-password \
    -s "DDS Node Passphrase" -a "$(hostname -s)" \
    /Library/Keychains/System.keychain
```

The wrapper will fall through on next start and dds-node will load
keys plaintext (which fails if the keys were saved encrypted — see
the second troubleshooting entry).
