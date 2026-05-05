# Sealed `DDS_NODE_PASSPHRASE` — cross-platform design

## Problem

Node identity (`node_key.bin`) and libp2p keypair (`p2p_key.bin`)
sit at rest under `data_dir`. Without `DDS_NODE_PASSPHRASE`, both files
are plaintext (mode 0600 root) — see
[`identity_store.rs`](../dds-node/src/identity_store.rs) and
[`p2p_identity.rs`](../dds-node/src/p2p_identity.rs). The macOS bootstrap
deliberately leaves them plaintext
([`dds-bootstrap-domain.sh:95`](../platform/macos/packaging/dds-bootstrap-domain.sh)
sets `DDS_NODE_PASSPHRASE=""`) because the LaunchDaemon needs to start
unattended at boot — there's no admin around to type a passphrase or
touch a FIDO2 key.

The architectural intent is to bind the wrap key to OS-resident hardware
storage. The TODO at
[`service.rs:2718`](../dds-node/src/service.rs) (security review M-22)
captures this:

> bind the wrap key to OS-bound storage (DPAPI on Windows, Keychain on
> macOS, TPM on Linux)

This document describes the **sealed-passphrase** path: a thin OS-side
wrapper that hands `DDS_NODE_PASSPHRASE` to dds-node from sealed
storage at service start. No dds-node code change required (the env-var
contract is unchanged); a follow-up could replace this with a
TPM-resident `IdentityStore` backend (M-22 proper).

## Threat model

| Adversary | Defended? | How |
|---|---|---|
| Filesystem-only attacker (lost laptop disk, backup theft) | Yes | Sealed blob is unbindable off-host without the OS hardware key |
| Same-host root with a debugger | No | Same threat model as the existing FIDO2-encrypted domain key — root can attach to the running node and read keys from memory |
| Same-host non-root | Yes | Sealed blob is mode 0600 root; OS hardware key requires the SYSTEM/root context to unseal |
| Tampered boot chain (PCR-bound seal) | Yes (Linux only, optional) | If sealed under a PCR policy, an attacker who alters early boot can't unseal |

The sealed passphrase doesn't help if the attacker already runs as root
on the live host — that's a separate problem (M-22, key-resident-in-TPM).

## Per-platform mechanics

### Linux — TPM2

- **Storage**: sealed-object blobs (`primary.ctx`, `seal.pub`,
  `seal.priv`) under `data_dir`. The TPM's owner-hierarchy primary key
  is the actual hardware-bound root.
- **Tools**: `tpm2-tools` (Alpine `apk add tpm2-tools`, Debian
  `apt install tpm2-tools`).
- **Boot timing**: `/dev/tpm0` is created by the kernel TPM driver
  during early init (well before runlevel `default` / `multi-user`).
  `tpm2_unseal` talks to `/dev/tpm0` directly; `tpm2-abrmd` (the
  user-space resource manager) is **not** required for single-tenant
  unseal. So no service-dependency ordering is needed.
- **Service hook**:
  - **OpenRC**: `/etc/conf.d/dds-node` (sourced before `start_pre` and
    `start-stop-daemon`) calls `dds-tpm-unseal` and exports
    `DDS_NODE_PASSPHRASE`.
  - **systemd**: `ExecStartPre=` runs `dds-tpm-unseal --env-file
    /run/dds/passphrase.env`; `EnvironmentFile=-/run/dds/passphrase.env`
    loads it. `ExecStopPost=` shreds the env-file.

Both helpers (`/usr/local/sbin/dds-tpm-{seal,unseal}`) come from
[`platform/linux/packaging/scripts/`](../platform/linux/packaging/scripts/).
Both fail-closed-but-quiet when `/dev/tpm0` or seal blobs are absent —
hosts without a TPM still boot, just with plaintext node keys.

### macOS — System Keychain (SEP-backed transparently)

- **Storage**: a generic-password item in
  `/Library/Keychains/System.keychain`. On Apple Silicon, the
  underlying wrap key is held in the SEP; on Intel Macs, the SEP isn't
  used here but the System Keychain master key is sealed against the
  hardware via the per-machine `SystemKey` blob.
- **Tools**: `/usr/bin/security` (built-in).
- **Boot timing**: `securityd` unlocks the System Keychain very early
  in boot using `/var/db/SystemKey` — well before any LaunchDaemon
  runs. So when the dds-node LaunchDaemon starts, the System Keychain
  is already unlocked. No `Wants=`/`After=`-equivalent ordering work.
- **Service hook**: the LaunchDaemon's `ProgramArguments` invokes a
  wrapper at `/usr/local/sbin/dds-launchd-wrapper` that calls the
  unseal helper, exports `DDS_NODE_PASSPHRASE`, and `exec`s
  `dds-node run`. Falls through cleanly when no sealed passphrase
  exists.
- **Helpers** (in
  [`platform/macos/packaging/scripts/`](../platform/macos/packaging/scripts/)):
  - `dds-keychain-seal.sh` — generates random passphrase, stores in
    keychain, prints to stdout (refuses to overwrite an existing item)
  - `dds-keychain-unseal.sh` — reads from keychain, prints to stdout
  - `dds-launchd-wrapper.sh` — LaunchDaemon entrypoint; calls unseal
    then `exec`s dds-node
- **Runbook**:
  [`platform/macos/packaging/SEALED-PASSPHRASE.md`](../platform/macos/packaging/SEALED-PASSPHRASE.md).
  *Status: implemented; round-trip verified end-to-end (seal →
  encrypted gen-node-key → reload → wrong-passphrase rejection).*

### Windows — DPAPI machine scope (TPM-backed transparently)

- **Storage**: a DPAPI-protected blob at
  `%ProgramData%\DDS\node-passphrase.dpapi`. On Windows 10+ with a TPM,
  DPAPI's machine master key is automatically TPM-sealed by the OS
  (Silent-Backup / TPM-Bind). On hosts without a TPM, DPAPI degrades to
  software protection bound to the machine — still off-host-unbindable.
- **Tools**: `CryptProtectData` / `CryptUnprotectData` with
  `CRYPTPROTECT_LOCAL_MACHINE` (no user logon required), reachable from
  PowerShell via `[System.Security.Cryptography.ProtectedData]`.
- **Boot timing**: DPAPI machine scope is available as soon as
  `LSASS` is up — very early. Any service whose start type is
  `auto-start` (the dds-node service is) already starts after `RPCSS`
  which depends on `LSASS`. So DPAPI is always available by the time
  SCM launches the service.
- **Service hook**: extend
  [`win_service.rs`](../dds-node/src/win_service.rs) with a
  `--unseal-passphrase-from <path>` flag on `service-run` (small Rust
  change — call `CryptUnprotectData` via `windows-sys`, set
  `DDS_NODE_PASSPHRASE` in-process before
  `service_dispatcher::start`). MSI install passes the flag in the
  registered service args.

  *Status: not yet implemented in this repo. Sketch only.*

## Operational lifecycle

1. **One-time seal** (post-install, before `dds-node provision`):
   ```sh
   pass="$(dds-tpm-seal)"             # Linux
   # pass="$(dds-keychain-seal)"      # macOS (when implemented)
   # pass="$(.\Seal-DdsPassphrase.ps1)"  # Windows (when implemented)
   ```
2. **Provision with the passphrase set** so `node_key.bin` /
   `p2p_key.bin` land encrypted from the start:
   ```sh
   DDS_NODE_PASSPHRASE="$pass" dds-node provision <bundle.dds> \
     --data-dir /var/lib/dds/node --no-start
   unset pass
   ```
3. **Start the service.** The unit's `ExecStartPre=` (systemd) or
   conf.d block (OpenRC) unseals at every start. The operator never
   re-enters the passphrase.

For an **already-provisioned** node (keys already plaintext on disk),
seal first, then re-encrypt by setting `DDS_NODE_PASSPHRASE` and
running `dds-node rotate-identity --data-dir <dir>` — that triggers a
re-save with the new wrap. Document this in the runbook.

## Boot-ordering summary

| Platform | What must be up before unseal | How it's guaranteed |
|---|---|---|
| Linux | `/dev/tpm0` (kernel char device) | Kernel TPM driver loads in initramfs/early-boot; service starts in `default`/`multi-user` runlevel, much later. No explicit ordering needed. |
| macOS | System Keychain unlocked | `securityd` unlocks it during early boot, before LaunchDaemons start. Implicit. |
| Windows | DPAPI master key available | `LSASS` is up before SCM launches services; service depends transitively on `RPCSS` which depends on `LSASS`. Implicit. |

In all three cases the OS already orders things correctly. The unseal
hook just runs at the start of dds-node's own startup, sets the env
var, and falls through if any precondition is missing.

## Failure modes

| Symptom | Likely cause | Recovery |
|---|---|---|
| Service starts but `WARN refusing to overwrite encrypted identity at … with plaintext` | Seal blobs missing/corrupt; sealed passphrase isn't reaching dds-node, but a previous run wrote encrypted blobs | Verify `/dev/tpm0` exists and helper works (`dds-tpm-unseal /var/lib/dds/node`); restore seal blobs from backup, or set `DDS_ALLOW_PLAINTEXT_DOWNGRADE=1` for one start to drop encryption |
| `dds-tpm-unseal` exits 1 silently | TPM not present, tpm2-tools missing, or seal blobs absent | Falls through deliberately — node boots plaintext. If that's not the intent, install tpm2-tools and re-seal. |
| Re-imaged host with same `data_dir` backup | TPM owner-hierarchy primary key is host-bound — sealed blobs from the old TPM won't unseal on the new one | Restore from a `dds-node` backup that includes plaintext keys (DR procedure), then re-seal on the new host |

## Why not skip the wrapper and put it in dds-node?

Could be done — and probably should be the M-22 endpoint (TPM-resident
key, not just sealed passphrase). The wrapper approach ships today
without Rust changes, exercises each platform's native sealed-storage
API, and survives the eventual key-resident migration: when M-22 lands,
the passphrase becomes redundant and the wrapper goes away.
