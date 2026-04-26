# DDS Administrator and User Guide

This guide covers day-to-day administration and use of a DDS (Decentralized Directory Service) deployment. It assumes you have built the project (`cargo build --workspace`) and have the `dds-node` and `dds-cli` binaries available.

For background on how DDS works internally, see the [Developer Guide](DDS-Developer-Guide.md). For the formal specification, see the [Design Document](DDS-Design-Document.md).

---

## Table of Contents

1. [Concepts](#concepts)
2. [Creating a Domain](#creating-a-domain)
3. [Adding Nodes](#adding-nodes)
4. [Revoking a Node's Admission](#revoking-a-nodes-admission)
5. [Rotating a Node's Identity](#rotating-a-nodes-identity)
6. [Single-File Provisioning](#single-file-provisioning)
7. [Node Configuration Reference](#node-configuration-reference)
8. [Enrolling Users](#enrolling-users)
9. [Enrolling Devices](#enrolling-devices)
10. [Admin Bootstrap](#admin-bootstrap)
11. [Sessions and Authentication](#sessions-and-authentication)
12. [Groups and Trust](#groups-and-trust)
13. [Policy Management](#policy-management)
14. [Windows Deployment](#windows-deployment)
15. [macOS Deployment](#macos-deployment)
16. [Monitoring and Diagnostics](#monitoring-and-diagnostics)
17. [Audit Log](#audit-log)
18. [Debugging](#debugging)
19. [Air-Gapped Sync (USB Stick / Courier)](#air-gapped-sync-usb-stick--courier)
20. [Security Reference](#security-reference)
21. [Troubleshooting](#troubleshooting)

---

## Concepts

### What is DDS?

DDS is a peer-to-peer replacement for centralized directory services like Active Directory. Every node carries a full replica of the directory and can authenticate users, evaluate policy, and issue sessions **completely offline**. When nodes reconnect, they converge automatically using CRDTs (conflict-free replicated data types).

### Key Terms

| Term | Definition |
|---|---|
| **Domain** | A cryptographic realm that nodes belong to (e.g. `acme.com`). Nodes from different domains cannot communicate. |
| **Node** | A machine running `dds-node`. Each node has a libp2p `PeerId` and must hold an admission certificate for its domain. |
| **Vouchsafe ID** | A self-verifying identity URN: `urn:vouchsafe:<label>.<base32-sha256-of-public-key>`. Cannot be spoofed. |
| **Token** | A cryptographically signed record. Types: `attest` (self-declare), `vouch` (endorse another), `revoke`, `burn`. |
| **Trust Graph** | The directed graph of vouch relationships. Policy decisions walk this graph to determine access. |
| **Admission Certificate** | A domain-key-signed certificate binding a `PeerId` to a domain. Required to join the network. |
| **Domain Key** | The Ed25519 keypair created at domain genesis. Used only to sign admission certificates. |

### How Nodes Communicate

Nodes use libp2p with three discovery mechanisms:

- **mDNS** — automatic zero-config discovery on the local network (enabled by default)
- **Bootstrap peers** — explicit multiaddr for known nodes (for cross-subnet or WAN)
- **Kademlia DHT** — distributed peer discovery and routing

All communication is encrypted with the Noise protocol. Protocol strings include the domain ID, so nodes from different domains reject each other at the handshake level.

---

## Creating a Domain

A DDS domain is created once, on the first node. This is called the **genesis ceremony**.

### Basic Genesis

```bash
export DDS_DOMAIN_PASSPHRASE="strong-passphrase-here"
dds-node init-domain --name acme.com --dir ./acme
```

This creates two files:

| File | Purpose | Share? |
|---|---|---|
| `acme/domain.toml` | Public domain identity (name, ID, public key) | Yes — copy to all nodes |
| `acme/domain_key.bin` | Secret signing key (encrypted with passphrase) | No — keep on admin machine only |

### FIDO2-Protected Genesis

For higher security, protect the domain key with a hardware FIDO2 authenticator instead of a passphrase:

```bash
dds-node init-domain --name acme.com --dir ./acme --fido2
# Touch your FIDO2 key when prompted
```

With FIDO2 protection, every admission signing operation requires a physical touch of the authenticator. No passphrase is needed.

> **Requires:** `dds-node` built with `--features fido2`

### What Happens at Genesis

1. An Ed25519 keypair is generated for the domain
2. A `DomainId` is derived: `dds-dom:<base32-sha256-of-public-key>`
3. The public half is written to `domain.toml`
4. The secret half is encrypted and written to `domain_key.bin`

The domain ID is baked into all libp2p protocol strings, so every node in the domain must share this identity.

---

## Adding Nodes

Every node needs three things to join a domain:

1. **Its own libp2p keypair** (generated locally, never leaves the machine)
2. **An admission certificate** signed by the domain key
3. **A copy of `domain.toml`**

### Step 1: Generate the Node Key

On the new machine:

```bash
dds-node gen-node-key --data-dir ~/.dds
```

Output:
```
Node libp2p identity:
  data_dir: /home/admin/.dds
  p2p_key:  /home/admin/.dds/p2p_key.bin
  peer_id:  12D3KooWAbCdEf...

Send this peer id to the domain admin to obtain an admission cert.
```

Record the `peer_id`. Send it to whoever holds the domain key.

### Step 2: Issue an Admission Certificate

On the admin machine (where `domain_key.bin` lives):

```bash
export DDS_DOMAIN_PASSPHRASE="..."
dds-node admit \
    --domain-key ./acme/domain_key.bin \
    --domain ./acme/domain.toml \
    --peer-id 12D3KooWAbCdEf... \
    --out admission-newnode.cbor \
    --ttl-days 365
```

The `--ttl-days` flag is optional. Without it, the certificate never expires.

### Step 3: Deploy to the New Node

Copy to the new machine:
- `domain.toml` → `~/.dds/domain.toml`
- `admission-newnode.cbor` → `~/.dds/admission.cbor`

### Step 4: Write the Node Configuration

Create `dds.toml` on the new machine:

```toml
org_hash = "acme"
data_dir = "/home/admin/.dds"
trusted_roots = []

[network]
listen_addr = "/ip4/0.0.0.0/tcp/4001"
bootstrap_peers = []      # mDNS handles LAN; add peers for WAN
mdns_enabled = true
api_addr = "127.0.0.1:5551"

[domain]
name = "acme.com"
id = "dds-dom:XXXXX"       # from domain.toml
pubkey = "XXXXX"            # from domain.toml
admission_path = "/home/admin/.dds/admission.cbor"
```

### Step 5: Start the Node

```bash
dds-node run dds.toml
```

The node will:
1. Verify its admission certificate against the domain public key
2. Start the libp2p swarm
3. Discover peers via mDNS (and/or bootstrap peers)
4. Begin syncing directory state via gossip
5. Start the local HTTP API on port 5551

---

## Revoking a Node's Admission

Threat-model §1 / open item #4. Once an admission certificate has been
issued, the only way to disinvite that node from the domain is to issue
a domain-signed `AdmissionRevocation`. Revocations are permanent — to
re-admit the same physical machine, generate a fresh libp2p keypair on
it (`dds-node gen-node-key`) and issue a new admission cert for the new
PeerId.

### Step 1: Issue the revocation (admin machine)

```bash
dds-node revoke-admission \
  --domain-key ./acme/domain_key.bin \
  --domain ./acme/domain.toml \
  --peer-id 12D3KooW... \
  --reason "key compromise" \
  --out admission_revocation.cbor
```

### Step 2: Distribute and import (every node)

```bash
dds-node import-revocation \
  --data-dir /opt/dds/data \
  --in admission_revocation.cbor
```

The new entry takes effect at the next admission handshake — restart
the node to force-renegotiate connections.

You don't have to import the file on every node manually. Once any one
node has the revocation, the H-12 admission handshake piggy-backs the
local revocation list onto every `AdmissionResponse` (capped at 1024
entries per response). Receivers verify each entry against the domain
pubkey and persist new ones atomically, so a `revoke-admission` issued
against any one node propagates domain-wide on the order of a
handshake round-trip. The manual `import-revocation` flow remains as a
force-immediate path for emergency rollouts and for nodes that aren't
currently on the network.

### Step 3: Verify the revocation landed

```bash
dds-node list-revocations --data-dir /opt/dds/data
```

Sample output:

```
Admission revocation list:
  data_dir: /opt/dds/data
  file:     /opt/dds/data/admission_revocations.cbor
  domain:   acme (dds:domain:acme:...)
  entries:  1

  [0] peer_id:    12D3KooW...
      revoked_at: 1714086000
      reason:     key compromise
```

For scripting, pass `--json` to emit one object per entry on stdout
(suitable for `jq` / monitoring pipelines). Both modes load the store
under the same domain-pubkey verification gate as the runtime path —
entries that fail to verify (corrupt file, foreign-domain
contamination) are dropped before they appear in the output, so the
list always reflects what the running node would actually enforce.

---

## Rotating a Node's Identity

Threat-model §2 recommendation #3 / §8 open item #9. A node's
identity is its libp2p Ed25519 keypair stored at
`<data_dir>/p2p_key.bin`. Rotation is the right response to:

- A suspected compromise of the on-disk key file.
- A passphrase change for `DDS_NODE_PASSPHRASE` paired with re-wrapping.
- Routine hygiene on a published rotation cadence.

The flow is two-touch: the operator runs `rotate-identity` locally,
the admin issues a fresh admission cert (and optionally revokes the
old PeerId), the operator imports the new cert and restarts. The
admin signature is intentionally manual — a compromised node must
not be able to renew its own admission.

### Step 1: Rotate the keypair (operator, on the node)

```bash
# Stop the node first (the running process keeps the OLD keypair in
# memory; restarting after rotation will pick up the new one).
sudo systemctl stop dds-node

# Optional but recommended: set the passphrase the node uses if its
# p2p_key.bin is encrypted, so rotate-identity can read the OLD
# PeerId before overwriting.
export DDS_NODE_PASSPHRASE='…'

sudo -E dds-node rotate-identity --data-dir /opt/dds/data
```

Sample output:

```
Rotated node libp2p identity:
  data_dir:    /opt/dds/data
  p2p_key:     /opt/dds/data/p2p_key.bin
  old_peer_id: 12D3KooWOldPeer…
  new_peer_id: 12D3KooWNewPeer…
  backup:      /opt/dds/data/p2p_key.bin.rotated.1714090000

The existing admission cert is now invalid (it was bound to the old peer id).
Before restarting the node, the admin must:

  1. Issue a fresh admission cert for the new peer id and ship it to this node:
       dds-node admit --domain-key <FILE> --domain <FILE> \
         --peer-id 12D3KooWNewPeer… --out admission.cbor
     Then place admission.cbor at /opt/dds/data/admission.cbor.

  2. (Recommended) Revoke the old peer id so a stolen copy of the old keypair cannot rejoin:
       dds-node revoke-admission --domain-key <FILE> --domain <FILE> \
         --peer-id 12D3KooWOldPeer… --reason "identity rotated" --out old_revocation.cbor
     Distribute old_revocation.cbor to every peer node and import with `import-revocation`,
     or rely on H-12 piggy-back gossip once at least one peer has it.

  3. Restart the node so the new identity takes effect.
```

`rotate-identity` refuses to run if `p2p_key.bin` is missing
(redirects you to `gen-node-key`) or if the existing key is
encrypted but `DDS_NODE_PASSPHRASE` is not set. The backup file is
byte-identical to the pre-rotation key, so an operator who needs to
recover from a botched rotation can restore by renaming the
`p2p_key.bin.rotated.<timestamp>` file back over `p2p_key.bin`. Pass
`--no-backup` only when on-disk space is constrained or a separate
backup workflow is in use.

### Step 2: Issue the new admission cert (admin)

Capture both PeerIds from the rotation output and produce a fresh
admission cert plus the matching revocation:

```bash
dds-node admit \
  --domain-key ./acme/domain_key.bin \
  --domain ./acme/domain.toml \
  --peer-id 12D3KooWNewPeer… \
  --out admission.cbor

dds-node revoke-admission \
  --domain-key ./acme/domain_key.bin \
  --domain ./acme/domain.toml \
  --peer-id 12D3KooWOldPeer… \
  --reason "identity rotated" \
  --out old_revocation.cbor
```

### Step 3: Land the new cert + revocation and restart (operator)

```bash
# Drop the new admission cert in place over the old one.
sudo cp admission.cbor /opt/dds/data/admission.cbor

# Import the revocation locally so the rotated node refuses to start
# under its old identity if the backup ever gets restored by mistake.
# Other nodes will pick the revocation up via H-12 piggy-back gossip
# the next time they handshake with any node that has it.
sudo dds-node import-revocation \
  --data-dir /opt/dds/data \
  --in old_revocation.cbor

sudo systemctl start dds-node
```

The node will verify the new admission cert against the freshly-
rotated PeerId at startup and refuse to start if the cert was
issued for the wrong PeerId — which is the safety property that
makes the manual admin signature load-bearing.

---

## Single-File Provisioning

For faster rollout, create a `.dds` provisioning bundle that contains everything a new node needs.

### Create the Bundle

On the admin machine, after genesis:

```bash
dds-node create-provision-bundle --dir ./acme --org acme --out provision.dds
```

### Provision a New Node

Copy `provision.dds` to the new machine (USB stick, SCP, etc.), then:

**macOS:**
```bash
sudo dds-node provision /Volumes/USB/provision.dds
```

**Windows (admin cmd):**
```cmd
dds-node.exe provision E:\provision.dds
```

**Linux:**
```bash
dds-node provision ./provision.dds
```

This single command:
1. Extracts domain config and admission cert
2. Generates a node key
3. Writes `dds.toml`
4. Starts the node

The `--no-start` flag skips automatic startup if you want to review the config first:

```bash
dds-node provision bundle.dds --no-start --data-dir /opt/dds
```

---

## Node Configuration Reference

The `dds.toml` file controls all node behavior.

### Top-Level Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `org_hash` | string | required | Organization identifier for gossip topic partitioning |
| `data_dir` | path | `~/.dds` | Storage directory for database, keys, and certs |
| `trusted_roots` | string[] | `[]` | Vouchsafe URNs of trust anchors for policy evaluation |
| `identity_path` | path | `<data_dir>/node_key.bin` | Path to the node's Vouchsafe signing identity |
| `expiry_scan_interval_secs` | int | `60` | Seconds between expired-token sweep runs |

### `[network]` Section

| Field | Type | Default | Description |
|---|---|---|---|
| `listen_addr` | multiaddr | `/ip4/0.0.0.0/tcp/4001` | libp2p listen address |
| `bootstrap_peers` | multiaddr[] | `[]` | Explicit peer addresses for WAN or cross-subnet |
| `mdns_enabled` | bool | `true` | Enable mDNS for LAN auto-discovery |
| `heartbeat_secs` | int | `5` | Gossipsub heartbeat interval |
| `idle_timeout_secs` | int | `60` | Close idle peer connections after this duration |
| `api_addr` | string | `127.0.0.1:5551` (Linux/macOS dev), `pipe:dds-api` (Windows MSI) | Local HTTP API bind. See **HTTP API transport** below. |
| `allow_legacy_v1_tokens` | bool | `false` | Accept legacy pre-canonical-CBOR token envelopes on ingest. Turn on briefly during a domain-wide v1 → v2 cutover. |

#### HTTP API transport (H-7)

`api_addr` dispatches on scheme:

| Scheme | Transport | Peer auth |
|---|---|---|
| `127.0.0.1:<port>` | loopback TCP (legacy; still the Linux/macOS dev default) | none — caller is `Anonymous`; admission falls back to `trust_loopback_tcp_admin` |
| `unix:/path/to/dds.sock` | Unix domain socket | `getpeereid` / `SO_PEERCRED` → uid/gid/pid |
| `pipe:<name>` | Windows named pipe (resolves to `\\.\pipe\<name>`); **Windows MSI default since A-2 (2026-04-25)** | `GetNamedPipeClientProcessId` + token-user SID |

The UDS / named-pipe paths expose a concrete `CallerIdentity` to the
admin middleware and the device-binding helper, so admin endpoints can
be gated on uid / SID and `/v1/*/policies` + `/v1/*/software` bind
TOFU to the caller's principal.

**Windows MSI deployments** ship pipe-first by default since **A-2
(2026-04-25)**: `node.toml` is generated with `api_addr = 'pipe:dds-api'`
and `[network.api_auth] trust_loopback_tcp_admin = false`, the Auth
Bridge reads `HKLM\SOFTWARE\DDS\AuthBridge\ApiAddr = pipe:dds-api`, and
the Policy Agent's `appsettings.json` has `NodeBaseUrl = "pipe:dds-api"`.
A hand-installed dev/test deployment that does not provision the
registry value still falls back to TCP loopback via `DdsNodePort`
(legacy behaviour preserved).

**Linux / macOS deployments** stay on TCP by default for backward
compat — switch `api_addr` to `unix:…` and then drop
`trust_loopback_tcp_admin` once every client is on the new transport.

### `[network.api_auth]` Section (H-6 / H-7 / M-8)

| Field | Type | Default | Description |
|---|---|---|---|
| `trust_loopback_tcp_admin` | bool | `true` (Rust default), `false` in the Windows MSI's shipped `node.toml` since A-2 | Admit `Anonymous` (TCP) callers to admin endpoints. Transition-only; flip to `false` once every client is on UDS / pipe. |
| `unix_admin_uids` | uint[] | `[]` | Additional UIDs admitted on admin endpoints over UDS (`0` and the service UID are always admitted). |
| `windows_admin_sids` | string[] | `[]` | Primary user SIDs admitted on admin endpoints over the named pipe. `S-1-5-18` (LocalSystem) is always admitted. |
| `node_hmac_secret_path` | path | _unset_ | Per-install HMAC secret used to sign every HTTP response body with `X-DDS-Body-MAC`. The Windows Auth Bridge verifies this to defeat the H-6 challenge-substitution attack. See **Provisioning the response-MAC secret** below. |
| `strict_device_binding` | bool | `false` | Refuse `Anonymous` (TCP) callers on device-scoped reads. Flip on alongside `trust_loopback_tcp_admin = false`. |

##### Provisioning the response-MAC secret

The MSI installer runs a `CA_GenHmacSecret` custom action that generates
the file at install time. To provision manually (e.g. on Linux/macOS
or in a dev loop):

```bash
dds-node gen-hmac-secret --out /var/lib/dds/node-hmac.key
# then set:
#   network.api_auth.node_hmac_secret_path = "/var/lib/dds/node-hmac.key"
# and distribute the same file to the Windows Auth Bridge
# (HKLM\SOFTWARE\DDS\AuthBridge\HmacSecretPath).
```

The file is a fresh 32-byte random key with `0o600` permissions on
Unix. Pass `--force` to rotate; reinstalls skip overwriting so the
node and Auth Bridge stay in sync.

##### Windows Auth Bridge registry knobs (`HKLM\SOFTWARE\DDS\AuthBridge`)

The Auth Bridge service reads its config from the registry. The MSI
provisions all keys at install time; operators can override per-host:

| Value | Type | MSI default | Purpose |
|---|---|---|---|
| `ApiAddr` | REG_SZ | `pipe:dds-api` | Full URL forwarded to the bridge's HTTP client. Recognised schemes mirror `api_addr`: `pipe:<name>` (preferred), `http://host:port`. **A-2 (2026-04-25)**: when set, this wins over `DdsNodePort`; empty falls back to `http://127.0.0.1:<DdsNodePort>` for legacy compatibility. Must point at the same target as the node's `api_addr`. |
| `DdsNodePort` | REG_DWORD | `5551` | Legacy TCP-only fallback port; only consulted when `ApiAddr` is empty. |
| `HmacSecretPath` | REG_EXPAND_SZ | `%ProgramData%\DDS\node-hmac.key` | Path to the H-6 response-MAC secret. Empty = MAC verification disabled (transition-only); unreadable = service refuses to start. |
| `DeviceUrn` | REG_SZ | _unset_ | Optional pin for the device URN used in enrolled-user lookups. |
| `RpId` | REG_SZ | `dds.local` | FIDO2 relying-party ID. |
| `FilterBuiltInProviders` | REG_DWORD | `0` | Hide other Credential Providers when DDS is configured. |
| `AllowPasswordFallback` | REG_DWORD | `1` | Allow the password-tile fallback when the FIDO2 path fails. |

A matching client knob lives in the Policy Agent's
`appsettings.json`: `DdsPolicyAgent.NodeBaseUrl`. The MSI ships
`pipe:dds-api`; flip to TCP only when reverting the cutover.

### `[domain]` Section

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Human-readable domain name |
| `id` | string | required | `dds-dom:<base32>` domain identifier |
| `pubkey` | string | required | Hex-encoded 32-byte Ed25519 domain public key |
| `admission_path` | path | `<data_dir>/admission.cbor` | Path to the admission certificate |
| `audit_log_enabled` | bool | `false` | Enable append-only cryptographic audit log |

### Example: Minimal Config

```toml
org_hash = "acme"

[domain]
name = "acme.com"
id = "dds-dom:4z2vjf6zjk3j3xkwcu58ftwks61uyd4a"
pubkey = "a1b2c3d4e5f6..."
```

### Example: Full Config

```toml
org_hash = "acme"
data_dir = "/opt/dds/data"
trusted_roots = ["urn:vouchsafe:root-admin.4z2vjf6zjk3j3xkwcu58ftwks61uyd4a"]
expiry_scan_interval_secs = 30

[network]
listen_addr = "/ip4/0.0.0.0/tcp/4001"
bootstrap_peers = [
    "/ip4/10.0.1.10/tcp/4001/p2p/12D3KooWXyz...",
    "/ip4/10.0.1.11/tcp/4001/p2p/12D3KooWAbc..."
]
mdns_enabled = true
heartbeat_secs = 5
idle_timeout_secs = 120
api_addr = "127.0.0.1:5551"

[domain]
name = "acme.com"
id = "dds-dom:4z2vjf6zjk3j3xkwcu58ftwks61uyd4a"
pubkey = "a1b2c3d4e5f6..."
admission_path = "/opt/dds/data/admission.cbor"
audit_log_enabled = true
```

### Environment Variables

| Variable | Purpose |
|---|---|
| `DDS_DOMAIN_PASSPHRASE` | Decrypts the domain key for `init-domain` and `admit` commands |
| `DDS_NODE_PASSPHRASE` | Encrypts/decrypts the node's Vouchsafe signing identity |
| `RUST_LOG` | Controls log verbosity (e.g. `info`, `debug`, `dds_node=debug`) |

---

## Enrolling Users

Users are enrolled via FIDO2/passkey attestation. Each enrollment creates a `UserAuthAttestation` token that binds a FIDO2 credential to a Vouchsafe identity.

### Via HTTP API

```bash
curl -X POST http://127.0.0.1:5551/v1/enroll/user \
  -H "Content-Type: application/json" \
  -d '{
    "label": "alice",
    "credential_id": "<base64-credential-id>",
    "attestation_object_b64": "<base64-attestation-object>",
    "client_data_hash_b64": "<base64-client-data-hash>",
    "rp_id": "acme.com",
    "display_name": "Alice Smith",
    "authenticator_type": "cross-platform"
  }'
```

Response:
```json
{
  "urn": "urn:vouchsafe:alice.4z2vjf6zjk3j3xkwcu58ftwks61uyd4a",
  "jti": "...",
  "token_cbor_b64": "..."
}
```

### Via CLI

`dds enroll user` wraps the same endpoint. The b64 arguments come from a
WebAuthn registration ceremony — in practice the Windows Auth Bridge or
a browser-based enrollment page gathers them and the CLI is used for
scripting / testing.

```bash
dds enroll user \
    --label alice \
    --credential-id <base64-credential-id> \
    --attestation-object <base64> \
    --client-data-hash <base64> \
    --rp-id acme.com \
    --display-name "Alice Smith" \
    --authenticator-type cross-platform
```

### Enrollment Flow (Windows Credential Provider)

On Windows with the DDS Credential Provider installed:

1. User clicks the DDS tile on the logon screen
2. The Credential Provider triggers the Auth Bridge service
3. Auth Bridge calls the Windows WebAuthn API
4. User touches their FIDO2 key
5. The attestation is sent to the local `dds-node` at `/v1/enroll/user`
6. The signed `UserAuthAttestation` propagates to all peers via gossip

### Re-enrollment

A user can enroll additional FIDO2 credentials (e.g. a backup key). Each enrollment creates a separate attestation. Both credentials remain valid for authentication.

---

## Enrolling Devices

Devices are enrolled to bind a machine identity to the directory.

```bash
curl -X POST http://127.0.0.1:5551/v1/enroll/device \
  -H "Content-Type: application/json" \
  -d '{
    "label": "win11-pc",
    "device_id": "DDS-WIN-PC-001",
    "hostname": "WIN11-PC",
    "os": "Windows 11",
    "os_version": "24H2",
    "tags": ["windows", "engineering"]
  }'
```

Response:
```json
{
  "urn": "urn:vouchsafe:win11-pc.7k3mf9...",
  "jti": "...",
  "token_cbor_b64": "..."
}
```

### Via CLI

```bash
dds enroll device \
    --label win11-pc \
    --device-id DDS-WIN-PC-001 \
    --hostname WIN11-PC \
    --os "Windows 11" \
    --os-version 24H2 \
    --tag windows --tag engineering
```

Use `--tag` multiple times to attach several tags. Optional fields
`--tpm-ek-hash` and `--org-unit` are accepted for devices that report
TPM EK attestation or belong to an organizational unit.

The device URN is used to scope policy queries (e.g. "what policies apply to this device?").

---

## Admin Bootstrap

The first admin on a freshly-provisioned domain must be created by a
special bootstrap path that does not require an existing vouching admin.
After that, every further admin or user vouch is a normal signed
`vch:vouch` token.

### First admin (`dds admin setup`)

Run this **once per domain**, on the first node, with a FIDO2 authenticator
attached. The request shape is identical to `enroll user`; the only
difference is that the resulting identity is registered as a trusted
root.

```bash
dds admin setup \
    --label root-admin \
    --credential-id <base64> \
    --attestation-object <base64> \
    --client-data-hash <base64> \
    --rp-id acme.com \
    --display-name "Root Admin" \
    --authenticator-type cross-platform
```

Response includes the admin URN, the attestation JTI, and the
CBOR-encoded token. Save the URN in the `[trust_graph]` of
`dds.toml` under `trusted_roots = [...]` so surviving nodes keep the
anchor after the first node goes offline.

### Subsequent vouches (`dds admin vouch`)

Once the first admin exists, further admins and users are added with a
FIDO2 *assertion* (proof-of-possession): the admin signs a challenge
with their already-enrolled credential, and `dds-node` issues the vouch
on their behalf.

```bash
dds admin vouch \
    --subject-urn urn:vouchsafe:bob.7k3mf9... \
    --credential-id <b64> \
    --authenticator-data <b64> \
    --client-data-hash <b64> \
    --signature <b64> \
    --purpose group:admins
```

The response includes the vouch JTI, the subject URN, and the admin URN
that signed it. `admin vouch` is the right CLI for any “admin adds this
person to a group” workflow; `dds group vouch` (below) bypasses FIDO2
entirely and is intended for offline / scripted flows against a local
store.

---

## Sessions and Authentication

Sessions are short-lived tokens issued after authenticating a user. They are the DDS equivalent of Kerberos tickets.

### Issue a Session (from FIDO2 Assertion)

Session issuance requires FIDO2 proof-of-possession. The client proves possession of a FIDO2 credential, and the node verifies it against a previously enrolled `UserAuthAttestation`.

**Step 1 — fetch a server challenge (single-use, 300 s TTL):**

```bash
curl http://127.0.0.1:5551/v1/session/challenge
```

```json
{
  "challenge_id": "chall-session-17...",
  "challenge_b64url": "<43-char base64url nonce>",
  "expires_at": 1712957100
}
```

**Step 2 — build `clientDataJSON` and compute `client_data_hash`:**

```text
clientDataJSON = {"type":"webauthn.get","challenge":"<challenge_b64url>","origin":"https://<rp_id>"}
client_data_hash = SHA-256(clientDataJSON)   # base64-encode for the request
```

No spaces. Field order must be exactly: `type`, `challenge`, `origin`.

**Step 3 — call your FIDO2 authenticator** with `client_data_hash` as the clientDataHash, collect `authenticator_data` and `signature`.

**Step 4 — submit the assertion:**

```bash
curl -X POST http://127.0.0.1:5551/v1/session/assert \
  -H "Content-Type: application/json" \
  -d '{
    "credential_id": "<base64url>",
    "challenge_id": "<challenge_id from step 1>",
    "client_data_hash": "<base64(SHA-256(clientDataJSON))>",
    "authenticator_data": "<base64>",
    "signature": "<base64>"
  }'
```

Response:
```json
{
  "session_id": "sess-...",
  "token_cbor_b64": "...",
  "expires_at": 1712956800
}
```

The `challenge_id` is single-use: a second POST with the same ID is rejected with 401.

### Via CLI

```bash
dds cp --node-url http://127.0.0.1:5551 session-assert \
    --credential-id <b64> \
    --challenge-id <challenge_id> \
    --authenticator-data <b64> \
    --client-data-hash <b64> \
    --signature <b64>
```

### Session Expiry

Sessions have a short lifetime (configurable, default 5 minutes). The node runs an expiry sweep every `expiry_scan_interval_secs` (default 60s) to remove expired sessions from the trust graph.

---

## Groups and Trust

DDS uses a **vouch chain** instead of hierarchical groups. An admin vouches for a user with a stated purpose, creating a directed edge in the trust graph.

### Add a User to a Group

```bash
dds group vouch \
    --as-label admin \
    --user urn:vouchsafe:bob.7k3mf9... \
    --purpose "group:backend"
```

This creates a `vch:vouch` token signed by the admin's identity, declaring that `bob` has the purpose `group:backend`.

### Remove a User from a Group

```bash
dds group revoke \
    --as-label admin \
    --jti vouch-admin-bob-<uuid>
```

This creates a `vch:revoke` token. Because DDS uses remove-wins CRDT semantics, a concurrent add and remove resolves to **removed** (safer to deny access that should be granted than to grant access that should be denied).

### Trust Graph Structure

```
OrgRoot (vch:attest, trusted_root in config)
├── vouch → Admin-A (purpose: "admin ou:engineering")
│   ├── vouch → User-1 (purpose: "group:backend")
│   ├── vouch → User-2 (purpose: "group:backend group:oncall")
│   └── vouch → SubAdmin-B (purpose: "admin group:frontend")
│       └── vouch → User-3 (purpose: "group:frontend")
└── vouch → Admin-C (purpose: "admin ou:operations")
    └── vouch → ServiceAcct-1 (purpose: "group:monitoring")
```

Policy evaluation walks from a user's node upward through the vouch chain, collecting purposes, and checks them against policy rules.

---

## Policy Management

### Evaluate Policy Locally

```bash
# Via CLI (offline — uses an empty trust graph, good for testing rules)
dds policy check \
    --user urn:vouchsafe:bob.7k3mf9... \
    --resource repo:main \
    --action read

# Via CLI against a running node (uses the node's real trust graph)
dds policy check \
    --user urn:vouchsafe:bob.7k3mf9... \
    --resource repo:main \
    --action read \
    --remote

# Via HTTP API
curl -X POST http://127.0.0.1:5551/v1/policy/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "subject_urn": "urn:vouchsafe:bob.7k3mf9...",
    "resource": "repo:main",
    "action": "read"
  }'
```

Policy evaluation is offline and targets sub-millisecond latency. It uses only the local trust graph and policy rules — no network calls.

### Publishing policy — publisher capabilities (C-3)

Policy and software documents are **only** admitted into the trust
graph when the issuer chains back to a trusted root with the matching
publisher-capability vouch. The supported purposes are:

| Purpose | Covers |
|---|---|
| `dds:policy-publisher-windows` | `WindowsPolicyDocument` attestations |
| `dds:policy-publisher-macos` | `MacOsPolicyDocument` attestations |
| `dds:software-publisher` | `SoftwareAssignment` attestations |

Before an operator identity can publish policy or software, an admin
must vouch for that identity with the right purpose. Example:

```bash
# Assume `alice-ops` is already enrolled as a DDS user.
# Give her permission to publish Windows policy:
dds admin vouch \
    --as-label admin \
    --subject urn:vouchsafe:alice-ops.7k3mf9... \
    --purpose dds:policy-publisher-windows
```

Attestations from any other issuer are rejected at gossip ingest and
also filtered at serve time as defense in depth. Operators migrating
from a pre-C-3 deployment should vouch their existing publishers
before the first ingest restart.

### Windows Policy (GPO Equivalent)

DDS distributes Windows policy as `WindowsPolicyDocument` tokens, which are the decentralized equivalent of Group Policy Objects.

Query policies for a device:

```bash
# HTTP
curl "http://127.0.0.1:5551/v1/windows/policies?device_urn=urn:vouchsafe:win11-pc.7k3mf9..."

# CLI
dds platform windows policies --device-urn urn:vouchsafe:win11-pc.7k3mf9...
dds platform windows software --device-urn urn:vouchsafe:win11-pc.7k3mf9...
```

The Windows DDS Policy Agent service polls this endpoint for post-boot
enforcement. In the current tree, pre-logon first-account claim for
`local_accounts` entries bound with `claim_subject_urn` is handled by the
native DDS Auth Bridge, while the policy agent remains the post-boot
enforcer for the rest of Windows policy.

### Windows First Account Claim

For passwordless Windows logon, DDS can now bind a local account to a DDS
subject without ever putting a plaintext password in policy.

1. An admin publishes a `WindowsPolicyDocument` whose
   `local_accounts[]` entry has `action: Create` and
   `claim_subject_urn: "<subject URN>"`.
2. The user selects the DDS tile on the Windows logon screen and
   completes a FIDO2 assertion.
3. The native DDS Auth Bridge verifies that assertion through
   `POST /v1/session/assert`.
4. If the selected credential has no local vault entry yet, the bridge
   sends the freshly issued local DDS session token to
   `POST /v1/windows/claim-account`.
5. `dds-node` resolves the one claimable local account for that subject
   and device. The bridge then creates or resets the local Windows
   account, applies group membership / `password_never_expires`, generates
   a random password locally, wraps that password with FIDO2
   `hmac-secret`, and completes the current logon.
6. Later logons reuse the vault entry and no longer hit the claim path.

Notes:
- Passwords are never carried in `WindowsPolicyDocument`.
- Conflicting claim mappings are rejected by `dds-node`.
- The current implementation refuses first-account claim on
  domain-joined Windows machines.

### macOS Policy (MDM Equivalent)

Query macOS policies for a device:

```bash
# HTTP
curl "http://127.0.0.1:5551/v1/macos/policies?device_urn=urn:vouchsafe:mac-1.7k3mf9..."

# CLI
dds platform macos policies --device-urn urn:vouchsafe:mac-1.7k3mf9...
dds platform macos software --device-urn urn:vouchsafe:mac-1.7k3mf9...
```

The macOS DDS Policy Agent enforces:
- Managed preferences (plist-backed)
- Local accounts (`dscl`, `pwpolicy`, `dseditgroup`)
- launchd services
- Configuration profiles
- Software installation (signed `.pkg` with SHA-256 verification)

### Report Applied State

After applying policy, agents report what they applied:

```bash
# Windows (HTTP)
curl -X POST http://127.0.0.1:5551/v1/windows/applied \
  -H "Content-Type: application/json" \
  -d '{"device_urn": "...", "applied_policies": [...]}'

# macOS (HTTP)
curl -X POST http://127.0.0.1:5551/v1/macos/applied \
  -H "Content-Type: application/json" \
  -d '{"device_urn": "...", "applied_policies": [...]}'

# Either platform — submit a report from a JSON file via CLI
dds platform windows applied --from-file ./applied-report.json
dds platform macos   applied --from-file ./applied-report.json
```

For Windows first-account claim (described in the previous section), the
Auth Bridge calls `/v1/windows/claim-account` directly, but the same
endpoint is reachable for testing via:

```bash
dds platform windows claim-account \
    --device-urn urn:vouchsafe:win11-pc.7k3mf9... \
    --session-token-b64 <base64 CBOR session token>
```

### Reconciliation & Drift Detection

The Windows policy agent automatically reconciles endpoint state with the
current policy on every poll cycle (every 60 seconds). This means:

**Stale-item cleanup.** When you remove a directive from a policy (e.g., delete
a registry entry from the `registry` array, remove a user from `local_accounts`,
or unassign a software package), the agent detects that the item was previously
managed by DDS but is no longer desired. It then cleans up:

| Category | Cleanup action |
|---|---|
| Registry values | Deleted (within allowlist only) |
| Local accounts | Disabled (not deleted, to preserve profiles) |
| Group memberships | User removed from the group |
| Software packages | Silently uninstalled via `msiexec /x` |

**Drift correction.** If someone manually changes a DDS-managed registry value
or re-enables a disabled account, the agent corrects the drift on the next poll
cycle. Each enforcer reads current system state and re-applies the desired
value if it differs.

**Audit mode.** If any policy in the current cycle uses `enforcement: Audit`,
the reconciliation pass logs what *would* be cleaned up but does not actually
remove anything. Use this for dry-run validation before switching to `Enforce`.

**Safety guarantees:**
- Only items that DDS previously created/set are touched — pre-existing
  system state is never modified by reconciliation.
- Registry cleanup respects the same allowlist as forward enforcement.
- The agent tracks managed items in `%ProgramData%\DDS\applied-state.json`
  under the `managed_items` key.

**Example: removing a registry entry from policy.**

Before (policy has the entry):
```json
{
  "windows": {
    "registry": [
      {"hive":"LocalMachine","key":"SOFTWARE\\Policies\\DDS\\Feature","name":"Enabled","value":{"Dword":1},"action":"Set"}
    ]
  }
}
```

After (entry removed from policy): the agent detects `Enabled` is no longer
desired, deletes it from the registry, and updates its managed-items tracking.

---

## Windows Deployment

### Components

| Component | Type | Purpose |
|---|---|---|
| `dds-node.exe` | Rust binary (Windows Service) | P2P node + HTTP API |
| DDS Credential Provider | C++ COM DLL | Logon screen FIDO2 tile |
| DDS Auth Bridge | C++ Windows Service | Mediates between CP and dds-node |
| DDS Policy Agent | .NET Windows Service | Enforces GPO-equivalent policy |
| DDS Tray Agent | C++ desktop app (optional) | Enrollment and notification UI |

### Architecture

```
Windows Logon Screen
  └── DDS Credential Provider (COM DLL)
        └── Named pipe (TLV protocol)
              └── DDS Auth Bridge (Windows Service)
                    └── HTTP 127.0.0.1:5551
                          └── dds-node (Windows Service)
```

### Installation

**Option A — MSI installer (recommended):**

Download or build the MSI package, then run:

```powershell
msiexec /i DDS-<version>-x64.msi /qn
```

The MSI installs all components to `C:\Program Files\DDS\`, registers three
Windows Services (`DdsNode`, `DdsAuthBridge`, `DdsPolicyAgent`), registers
the Credential Provider COM DLL in System32, and creates
`C:\ProgramData\DDS\` for vault/logs/state. Configuration templates are
installed to `C:\Program Files\DDS\config\` (`node.toml` and
`appsettings.json`).

To build the MSI locally:

```powershell
cd platform\windows\installer
.\Build-Msi.ps1 -Platform x64   # or arm64
```

**Option B — Manual build:**

```cmd
cargo build --workspace --release
msbuild platform\windows\native\DdsNative.sln /p:Configuration=Release /p:Platform=x64
dotnet publish platform\windows\DdsPolicyAgent\DdsPolicyAgent.csproj -c Release --runtime win-x64 --self-contained -p:PublishSingleFile=true
```

Then register services and the Credential Provider COM DLL manually.
The MSI source (`platform/windows/installer/DdsBundle.wxs`) documents the
exact registry keys, service definitions, and COM registration needed.

### Data Paths (Windows)

| Path | Purpose |
|---|---|
| `C:\Program Files\DDS\bin\` | Binaries (dds-node, Auth Bridge, Policy Agent, Tray Agent) |
| `C:\Program Files\DDS\config\node.toml` | Node configuration |
| `C:\Program Files\DDS\config\appsettings.json` | Policy Agent configuration |
| `C:\ProgramData\DDS\` | Runtime data directory (vault, logs, applied-state). MSI install applies SDDL `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` so only `LocalSystem` and `BUILTIN\Administrators` have access — child files inherit. See `dds-node restrict-data-dir-acl` and the MSI's `CA_RestrictDataDirAcl` custom action. |
| `C:\ProgramData\DDS\node-data\` | Node database, keys, admission cert |
| `C:\ProgramData\DDS\node-data\domain.toml` | Domain public identity |
| `C:\ProgramData\DDS\node-data\admission.cbor` | Admission certificate |
| `C:\Windows\System32\DdsCredentialProvider.dll` | Credential Provider COM DLL |

### Validating

Run the full Windows E2E smoke test:

```powershell
.\platform\windows\e2e\smoke_test.ps1
```

Or test individual layers:

```powershell
# Rust FIDO2 E2E
cargo test -p dds-node --test cp_fido_e2e

# .NET policy agent tests
dotnet test
```

See [platform/windows/e2e/README.md](../platform/windows/e2e/README.md) for the full test matrix.

---

## macOS Deployment

### Components

| Component | Type | Purpose |
|---|---|---|
| `dds-node` | Rust binary (LaunchDaemon) | P2P node + HTTP API |
| DDS Policy Agent | .NET self-contained binary (LaunchDaemon) | Enforces macOS policy (preferences, accounts, launchd, profiles, software) |
| `dds-bootstrap-domain` | Shell script | Genesis ceremony + first-node setup |
| `dds-enroll-admin` | Shell script | FIDO2 admin enrollment |
| `dds-admit-node` | Shell script | Issues admission certs for sibling nodes |
| `dds-fido2-test` | Rust binary | Interactive FIDO2 enrollment + auth testing |

### Architecture

```
launchd (system domain)
  ├── com.dds.node (LaunchDaemon)
  │     └── dds-node run /Library/Application Support/DDS/dds.toml
  │           └── HTTP 127.0.0.1:5551
  └── com.dds.policyagent (LaunchDaemon)
        └── DdsPolicyAgent.MacOS
              └── polls GET /v1/macos/policies, /v1/macos/software
              └── enforces via plutil, dscl, launchctl, profiles, installer
              └── reports POST /v1/macos/applied
```

### Enterprise Account Models

DDS treats three identities separately on macOS:

- the DDS subject in the trust graph;
- the local macOS account that owns the home folder and FileVault relationship;
- the enterprise directory / IdP identity that may own the login window.

The schema now has dedicated document types for the last two relationships:
`MacAccountBindingDocument` and `SsoIdentityLinkDocument`. Dedicated CLI / HTTP
admin flows for issuing those documents are still future work, but the model is
part of the design now and should guide deployments.

#### Standalone Macs (no external directory or IdP)

Use this model for field laptops, disconnected Macs, or small fleets where DDS
is allowed to own local account lifecycle.

- DDS can manage `local_accounts` policy entries.
- Users still sign in to macOS with the local account; DDS session bootstrap
  happens after OS login.
- DDS owns trust, device policy, software assignment, and local account policy.

Recommended flow:

1. Install the DDS macOS package.
2. Bootstrap or join the DDS domain.
3. Enroll the device and the user/admin FIDO2 credentials.
4. Publish `MacOsPolicyDocument` policy, including `local_accounts` if you want
   DDS-managed local users.
5. Keep the macOS login window and FileVault tied to the local macOS account.

#### Directory-bound or Platform SSO-managed Macs

Use this model for enterprise fleets where AD, Open Directory, LDAP, or MDM +
Platform SSO already owns login and account provisioning.

- Bind or enroll the Mac into that external identity system first.
- Install DDS after the Mac already has its enterprise login path.
- Do **not** rely on DDS `local_accounts` policy for these hosts.
- Use DDS for device enrollment, policy, software, trust graph, and post-login
  session/bootstrap work.

Recommended flow:

1. Complete directory binding or Automated Device Enrollment + Platform SSO.
2. Install the DDS macOS package.
3. Enroll the device into the DDS domain.
4. Enroll the user's DDS credential.
5. Let the user keep signing in through the existing directory / IdP path.
6. Use DDS after login for policy, software, and trust-based authorization.

Current limitation:

- The macOS policy agent refuses `local_accounts` mutation on directory-bound
  hosts today.
- Platform SSO coexistence is modeled in the DDS schema, but the login-window /
  FileVault integration path is still future `DdsLoginBridge` work.

### Installation

**Option A: Install the .pkg (recommended)**

Download the latest `DDS-Platform-macOS-<version>-<arch>.pkg` from the GitHub Releases page, or build it locally:

```bash
cd platform/macos/packaging
make pkg                              # release build
# or: make pkg BUILD_MODE=debug       # faster, for testing
```

Install:

```bash
sudo installer -pkg build/DDS-Platform-macOS-0.1.0-arm64.pkg -target /
```

This installs:
- `/usr/local/bin/dds-node`, `dds`, `dds-fido2-test`
- `/usr/local/bin/dds-bootstrap-domain`, `dds-enroll-admin`, `dds-admit-node`
- `/usr/local/lib/dds/DdsPolicyAgent.MacOS` + `appsettings.json`
- `/Library/LaunchDaemons/com.dds.node.plist` (disabled)
- `/Library/LaunchDaemons/com.dds.policyagent.plist` (disabled)
- `/Library/Application Support/DDS/dds.toml.template`

Both LaunchDaemons start **disabled**. The bootstrap script enables them.

**Option B: Build from source**

```bash
cargo build --release -p dds-node --features fido2 -p dds-cli -p dds-fido2-test
dotnet publish platform/macos/DdsPolicyAgent/DdsPolicyAgent.MacOS.csproj \
  -c Release -r osx-arm64 --self-contained true -p:PublishSingleFile=true
```

### First Node Setup (Genesis)

After installing the .pkg, bootstrap the first node:

```bash
sudo dds-bootstrap-domain
```

This interactive script:
1. Prompts for domain name and org hash
2. Asks whether to protect the domain key with FIDO2 or a passphrase
3. Creates the domain (`init-domain`)
4. Creates a `provision.dds` bundle for sibling nodes
5. Generates a node key, self-admits, writes `dds.toml`
6. Starts `dds-node` via launchctl
7. Enrolls this Mac as a device
8. Starts the policy agent via launchctl
9. Saves state to `/Library/Application Support/DDS/bootstrap.env`

### Admin Enrollment (FIDO2)

After the domain is bootstrapped, enroll the first admin:

```bash
sudo dds-enroll-admin
```

This script:
1. Runs FIDO2 enrollment (two touches of your hardware key)
2. Adds the admin's URN to `trusted_roots` in `dds.toml`
3. Restarts the node to load the new trusted root

### Adding Sibling Nodes

**Option A: Single-file provisioning (recommended)**

The bootstrap script creates a `provision.dds` bundle. Copy it to the new Mac (USB, SCP, etc.):

```bash
# On the new Mac (after installing the .pkg):
sudo dds-node provision /Volumes/USB/provision.dds
```

This single command:
1. Decrypts the domain key (FIDO2 touch)
2. Generates a node key and signs an admission cert
3. Writes `dds.toml`
4. Starts both `dds-node` and the policy agent via launchctl
5. Enrolls the device
6. The domain key is zeroed in memory — never written to disk on the new machine

**Option B: Manual admission**

On the new Mac:

```bash
dds-node gen-node-key --data-dir "/Library/Application Support/DDS/node-data"
# Note the peer_id
```

On the admin Mac:

```bash
sudo dds-admit-node
# Enter the new Mac's peer_id when prompted
# Copy the resulting admission.cbor to the new Mac
```

On the new Mac, copy `domain.toml` + `admission.cbor` to `/Library/Application Support/DDS/node-data/`, edit `dds.toml`, and start via launchctl.

**Option C: Windows sibling**

A Windows machine joins the same domain using the same `provision.dds` bundle:

```cmd
REM After installing the DDS MSI:
dds-node.exe provision E:\provision.dds
```

This starts the DdsNode and DdsPolicyAgent Windows Services and enrolls the device. The Windows Credential Provider tile appears on the logon screen once enrolled users sync via gossip (~60 seconds).

### Data Paths (macOS)

| Path | Purpose |
|---|---|
| `/Library/Application Support/DDS/node-data/` | Node database, keys, admission cert |
| `/Library/Application Support/DDS/dds.toml` | Node configuration |
| `/Library/Application Support/DDS/state/` | Applied policy state, launchd bindings |
| `/Library/Application Support/DDS/packages/` | Package download cache |
| `/Library/Application Support/DDS/profiles/` | Profile payload hashes |
| `/Library/LaunchDaemons/com.dds.node.plist` | dds-node LaunchDaemon |
| `/Library/LaunchDaemons/com.dds.policyagent.plist` | Policy agent LaunchDaemon |
| `/Library/Managed Preferences/` | Managed preference plists |
| `/var/log/dds/` | dds-node logs |
| `/var/log/dds-policyagent.{out,err}` | Policy agent logs |

### Policy Agent Configuration

The policy agent reads from `/Library/Application Support/DDS/appsettings.json`:

```json
{
  "DdsPolicyAgent": {
    "DeviceUrn": "urn:vouchsafe:...",
    "NodeBaseUrl": "http://127.0.0.1:5551",
    "PollIntervalSeconds": 60,
    "StateDir": "/Library/Application Support/DDS/state",
    "ManagedPreferencesDir": "/Library/Managed Preferences",
    "LaunchDaemonPlistDir": "/Library/LaunchDaemons",
    "LaunchAgentPlistDir": "/Library/LaunchAgents",
    "RequirePackageSignature": true
  }
}
```

Settings can also be overridden via environment variables (prefix `DdsPolicyAgent__`).

### Policy Enforcement Capabilities

| Capability | Backend | Notes |
|---|---|---|
| Managed preferences | `plutil` (binary plist) | Writes to `/Library/Managed Preferences/` |
| Local accounts | `dscl`, `pwpolicy`, `sysadminctl`, `dseditgroup` | Create/delete/disable users, admin group, hidden flag. Use only on standalone Macs; refuses on directory-bound machines today. |
| launchd services | `launchctl` bootstrap/bootout/kickstart | Configure, load, unload managed LaunchDaemons/Agents |
| Configuration profiles | `profiles -I` / `profiles -R` | SHA-256 idempotency, payload stamp state |
| Software install | `/usr/sbin/installer` + `pkgutil` | HTTP download, SHA-256 verify, optional signature check. Uninstall intentionally not supported. |

### Service Management

```bash
# Check service status
sudo launchctl list | grep dds

# Restart dds-node
sudo launchctl kickstart -k system/com.dds.node

# Restart policy agent
sudo launchctl kickstart -k system/com.dds.policyagent

# Stop services
sudo launchctl bootout system/com.dds.node
sudo launchctl bootout system/com.dds.policyagent

# View logs
tail -f /var/log/dds/dds-node.err
tail -f /var/log/dds-policyagent.err
```

### Validating

Run the single-machine smoke test (no sudo required):

```bash
platform/macos/e2e/smoke-test.sh
```

This validates the full loop: domain init, node start, device enrollment, policy publish via gossip, agent enforcement (preferences, launchd state), and applied-state tracking.

For a full two-Mac mesh deployment test, see [platform/macos/e2e/README.md](../platform/macos/e2e/README.md).

Run the .NET unit tests:

```bash
dotnet test platform/macos/DdsPolicyAgent.Tests/DdsPolicyAgent.MacOS.Tests.csproj
```

---

## Monitoring and Diagnostics

### Node Status

```bash
# Via HTTP API
curl http://127.0.0.1:5551/v1/status | jq

# Via CLI — local store counters only (no node contact)
dds status

# Via CLI — live node status
dds status --remote
```

Returns:
- Connected peer count
- DAG operation count
- Trust graph depth and token counts
- Store statistics

### List Enrolled Users

```bash
curl "http://127.0.0.1:5551/v1/enrolled-users?device_urn=urn:vouchsafe:..."
```

Or via CLI:

```bash
dds cp enrolled-users [--device-urn ...]
```

### Logs

DDS uses the `tracing` framework. Control verbosity with `RUST_LOG`:

```bash
# Default (info level)
dds-node run dds.toml

# Debug logging for the node
RUST_LOG=dds_node=debug dds-node run dds.toml

# Debug all DDS crates
RUST_LOG=dds_core=debug,dds_node=debug,dds_net=debug dds-node run dds.toml

# Trace libp2p for networking issues
RUST_LOG=dds_net=trace,libp2p=debug dds-node run dds.toml
```

### Load Testing

Run the smoke test (60s, 3 nodes) to verify performance budgets:

```bash
cargo run -p dds-loadtest --release -- --smoke --output-dir /tmp/dds-smoke
```

Exits with status 2 if any KPI fails. See [dds-loadtest/README.md](../dds-loadtest/README.md) for the full soak harness.

### Key Performance Targets

| KPI | Budget |
|---|---|
| Local auth decision | ≤ 1 ms (p99) |
| Ed25519 verify throughput | ≥ 50,000 ops/s |
| CRDT merge | ≤ 0.05 ms (p99) |
| Peak heap per 1K entries | ≤ 5 MB |

---

## Audit Log

Every token accepted by the node — attestations, vouches, revocations,
burns — is appended to a local audit log (when `audit_log_enabled` is
set in `[domain]`). Each entry is the full CBOR of the original token
plus a `timestamp` and a signature from the node that recorded it, so
the log is tamper-evident even if the redb file is tampered with later.

### Query the log

```bash
# Newest entries, all actions
dds audit list

# Filter by action
dds audit list --action vouch
dds audit list --action revoke

# Cap the page size
dds audit list --limit 100

# HTTP equivalent
curl "http://127.0.0.1:5551/v1/audit/entries?action=vouch&limit=100" | jq
```

Output lists the timestamp (Unix seconds), the `action`, the node URN
that recorded it, and a truncated base64 prefix of the CBOR token. To
decode the token fully, pipe the full `token_cbor_b64` field to a CBOR
decoder (e.g. `cbor2diag`).

### Retention

Audit entries are pruned on the same tick as expired sessions. Control
retention in `dds.toml`:

```toml
[domain]
audit_log_enabled            = true
audit_log_max_entries        = 100_000   # 0 = unlimited
audit_log_retention_days     = 90        # 0 = no age limit
```

Both caps are applied every sweep; the older one wins when both are set.

---

## Debugging

### Reachability check

Confirm the CLI can talk to the node:

```bash
dds debug ping
# OK — node http://127.0.0.1:5551 reachable (peer_id=12D3Koo..., uptime=1234s)
```

### Full node statistics

`dds debug stats` is equivalent to `dds status --remote` but prints
every `NodeStatus` field (peer id, uptime, connected peers, DAG ops,
trust graph token counts, store counts, and burned/revoked totals).

```bash
dds debug stats
```

### Validate a config file

Parses a `dds-node` `config.toml` without starting the node, and surfaces
the operational-readiness fields that are easy to misspell:

```bash
dds debug config ./dds.toml
```

Prints the top-level keys plus any of:
`max_chain_depth`, `max_delegation_depth`, `audit_log_enabled`,
`audit_log_max_entries`, `audit_log_retention_days`.

Bad TOML exits non-zero with a clear message — use this in CI to smoke-
test generated configs before rolling them out.

### Node-side logs

`dds-node` does not expose logs over HTTP. Logs go to stdout via the
`tracing` framework (see the [Logs](#logs) section above) — tail them
with standard OS tooling (`journalctl -u dds-node`, Windows Event
Viewer / Service log, `Console.app` on macOS).

---

## Air-Gapped Sync (USB Stick / Courier)

Some deployments run DDS nodes on networks that can never route packets
to each other: classified enclaves, shipboard networks, off-grid sites.
The `dds export` / `dds import` commands package a node's state into a
single file so two peers can stay in sync through a courier or USB
stick.

### How it works

- **Export** reads the local `directory.redb` and `domain.toml`, and
  writes a single CBOR file (`.ddsdump`) containing:
  - every signed token (attestations, vouches, revocations)
  - every CRDT causal-DAG operation
  - the revoked-JTI and burned-URN sets
  - the source domain ID (to prevent cross-domain pollution)
- **Import** decodes the file, checks the domain ID against the
  destination's `domain.toml`, and replays the records. All writes are
  *idempotent*: re-importing the same dump changes nothing because the
  CRDT merge is deterministic and `put_token` / `put_operation` are
  keyed by JTI / operation ID.

Because the format is a plain CBOR document, a `.ddsdump` is exactly the
same size as the on-disk store contents — no extra framing overhead.

### Commands

```bash
# On node A: package the current state.
dds --data-dir /var/lib/dds export --out /mnt/usb/acme-2026-04.ddsdump
# Exported dump to /mnt/usb/acme-2026-04.ddsdump
#   Domain:     dds-dom:acme-7x4q…
#   Tokens:     142
#   Operations: 318
#   Revoked:    3
#   Burned:     0
#   Size:       412803 bytes

# On node B (different site, no network path): replay it.
dds --data-dir /var/lib/dds import --in /mnt/usb/acme-2026-04.ddsdump
# Imported:
#   Tokens:     140 new, 2 already present
#   Operations: 316 new, 2 already present
#   Revoked:    3 applied
#   Burned:     0 applied

# Preview-only (no writes). Useful when verifying a dump before applying.
dds --data-dir /var/lib/dds import --in /mnt/usb/acme-2026-04.ddsdump --dry-run
```

### Domain-id enforcement

If the dump's `domain_id` does not match the destination's
`domain.toml`, import aborts with a clear error before touching the
store. This is a safety check, not an access-control boundary: the
records themselves are cryptographically signed, so even forcing a
cross-domain merge would produce tokens that fail signature
verification at the destination.

### When to use this vs. network sync

Prefer live libp2p sync (mDNS / bootstrap peers / DHT) whenever the
nodes can reach each other. Anti-entropy catches up in under a minute
even after long disconnections. Air-gapped sync is a fallback for
deployments where that is impossible — it is not a performance
optimisation.

---

## Security Reference

### Cryptography

DDS is **quantum-resistant by default**. All identities use hybrid Ed25519 + ML-DSA-65 (FIPS 204) signatures. Both the classical and post-quantum signature must verify for a token to be valid.

FIDO2 leaf identities use classical Ed25519 or ECDSA-P256 due to hardware limitations. Quantum resistance flows through the vouch chain from hybrid trust roots.

### Domain Isolation

Nodes from different domains cannot communicate at all. The domain ID is embedded in libp2p protocol strings, causing handshakes to fail at protocol negotiation — before any application data is exchanged.

### Admission Control

A node cannot join a domain without an `AdmissionCert` signed by the domain key. The certificate binds the node's `PeerId` to the domain and is verified at startup. A compromised node key alone is not sufficient to impersonate a different node.

### Remove-Wins Semantics

When concurrent operations conflict (e.g. one admin adds a user to a group while another removes them), the **removal wins**. This is a deliberate security choice: it is safer to deny access that should have been granted than to grant access that should have been denied.

### At-Rest Encryption

- **Domain key**: Argon2id + ChaCha20-Poly1305, keyed with `DDS_DOMAIN_PASSPHRASE` (or FIDO2 hardware binding)
- **Node identity**: Argon2id + ChaCha20-Poly1305, keyed with `DDS_NODE_PASSPHRASE`
- **Database**: redb (ACID), not encrypted at rest (rely on OS-level full-disk encryption)

### Localhost-Only API

The HTTP API binds to `127.0.0.1` by default. Cross-host access should use mTLS or a tunnel. The API does not implement its own authentication — it trusts the OS network stack to restrict access to local processes.

---

## Troubleshooting

### Node won't start: "admission certificate verification failed"

The admission cert doesn't match this node's PeerId or domain config.

1. Check that `domain.toml` on this machine matches the one used during `admit`
2. Check that the admission cert was issued for this node's PeerId (not another node's)
3. Re-run `dds-node gen-node-key` and check the printed PeerId matches what was admitted

### No peers connecting

1. Check both nodes are in the same domain (same `domain.id` in their configs)
2. If on the same LAN: ensure `mdns_enabled = true` and UDP multicast is not blocked
3. If cross-subnet: add explicit `bootstrap_peers` to the config
4. Check firewall allows TCP on the listen port (default 4001)
5. Verify with `curl http://127.0.0.1:5551/v1/status` — `connected_peers` should be ≥ 1

### Users not syncing between nodes

After enrollment on one node, `UserAuthAttestation` tokens propagate via gossip. Allow up to 60 seconds for anti-entropy sync.

1. Check both nodes see each other: `connected_peers ≥ 1` on both
2. Check the enrollment succeeded: `curl http://127.0.0.1:5551/v1/enrolled-users` on the enrolling node
3. Wait 60 seconds, then check the other node

### FIDO2 assertion fails

1. Verify the credential was enrolled: check `/v1/enrolled-users` for the credential ID
2. Check the authenticator data and signature are correctly base64-encoded
3. For P-256 credentials: ensure the public key COSE encoding matches what was sent during attestation

### Policy agent not applying policy

1. Confirm the node is running: `curl http://127.0.0.1:5551/v1/status`
2. Check there are policies published for this device URN
3. Verify the agent's device URN matches what policies target
4. Check agent logs for errors (permissions, missing paths, etc.)
5. On macOS: agent must run as `root` for most operations
6. On Windows: Policy Agent service must run as `LocalSystem`
