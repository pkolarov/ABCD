# DDS Administrator and User Guide

This guide covers day-to-day administration and use of a DDS (Decentralized Directory Service) deployment. It assumes you have built the project (`cargo build --workspace`) and have the `dds-node` and `dds-cli` binaries available.

For background on how DDS works internally, see the [Developer Guide](DDS-Developer-Guide.md). For the formal specification, see the [Design Document](DDS-Design-Document.md).

---

## Table of Contents

1. [Concepts](#concepts)
2. [Creating a Domain](#creating-a-domain)
3. [Adding Nodes](#adding-nodes)
4. [Single-File Provisioning](#single-file-provisioning)
5. [Node Configuration Reference](#node-configuration-reference)
6. [Enrolling Users](#enrolling-users)
7. [Enrolling Devices](#enrolling-devices)
8. [Sessions and Authentication](#sessions-and-authentication)
9. [Groups and Trust](#groups-and-trust)
10. [Policy Management](#policy-management)
11. [Windows Deployment](#windows-deployment)
12. [macOS Deployment](#macos-deployment)
13. [Monitoring and Diagnostics](#monitoring-and-diagnostics)
14. [Security Reference](#security-reference)
15. [Troubleshooting](#troubleshooting)

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
| `api_addr` | string | `127.0.0.1:5551` | Local HTTP API bind address |

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
    "public_key_cbor": "<base64-cose-public-key>",
    "attestation_object": "<base64-attestation-object>",
    "client_data_hash": "<base64-client-data-hash>"
  }'
```

Response:
```json
{
  "urn": "urn:vouchsafe:alice.4z2vjf6zjk3j3xkwcu58ftwks61uyd4a",
  "token_b64": "..."
}
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
  "token_b64": "..."
}
```

The device URN is used to scope policy queries (e.g. "what policies apply to this device?").

---

## Sessions and Authentication

Sessions are short-lived tokens issued after authenticating a user. They are the DDS equivalent of Kerberos tickets.

### Issue a Session (by URN)

```bash
curl -X POST http://127.0.0.1:5551/v1/session \
  -H "Content-Type: application/json" \
  -d '{"subject_urn": "urn:vouchsafe:alice.4z2vjf6zjk3j3xkwcu58ftwks61uyd4a"}'
```

### Issue a Session (from FIDO2 Assertion)

This is the primary authentication flow. The client proves possession of a FIDO2 credential, and the node verifies it against a previously enrolled `UserAuthAttestation`.

```bash
curl -X POST http://127.0.0.1:5551/v1/session/assert \
  -H "Content-Type: application/json" \
  -d '{
    "credential_id": "<base64>",
    "authenticator_data": "<base64>",
    "client_data_hash": "<base64>",
    "signature": "<base64>"
  }'
```

Response:
```json
{
  "session_id": "sess-...",
  "subject_urn": "urn:vouchsafe:alice.4z2vjf6...",
  "token_b64": "...",
  "expires_at": 1712956800
}
```

### Via CLI

```bash
dds cp --node-url http://127.0.0.1:5551 session-assert \
    --credential-id <b64> \
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
# Via CLI
dds policy check \
    --user urn:vouchsafe:bob.7k3mf9... \
    --resource repo:main \
    --action read

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

### Windows Policy (GPO Equivalent)

DDS distributes Windows policy as `WindowsPolicyDocument` tokens, which are the decentralized equivalent of Group Policy Objects.

Query policies for a device:

```bash
curl "http://127.0.0.1:5551/v1/windows/policies?device_urn=urn:vouchsafe:win11-pc.7k3mf9..."
```

The Windows DDS Policy Agent service polls this endpoint and enforces the policy locally (registry settings, account management, password policy).

### macOS Policy (MDM Equivalent)

Query macOS policies for a device:

```bash
curl "http://127.0.0.1:5551/v1/macos/policies?device_urn=urn:vouchsafe:mac-1.7k3mf9..."
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
# Windows
curl -X POST http://127.0.0.1:5551/v1/windows/applied \
  -H "Content-Type: application/json" \
  -d '{"device_urn": "...", "applied_policies": [...]}'

# macOS
curl -X POST http://127.0.0.1:5551/v1/macos/applied \
  -H "Content-Type: application/json" \
  -d '{"device_urn": "...", "applied_policies": [...]}'
```

---

## Windows Deployment

### Components

| Component | Type | Purpose |
|---|---|---|
| `dds-node.exe` | Rust binary (Windows Service) | P2P node + HTTP API |
| DDS Credential Provider | C++ COM DLL | Logon screen FIDO2 tile |
| DDS Auth Bridge | C++ Windows Service | Mediates between CP and dds-node |
| DDS Policy Agent | .NET 8.0 Windows Service | Enforces GPO-equivalent policy |

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

1. **Build all components:**
   ```cmd
   cargo build --workspace
   msbuild platform\windows\native\DdsNative.sln /p:Configuration=Release /p:Platform=x64
   dotnet build ABCD.sln -c Release
   ```

2. **Install dds-node as a Windows Service**

3. **Register the Credential Provider:**
   ```
   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\
       Credential Providers\{8C0DBE9A-5E27-4DDA-9A4B-3B5C8A6E2A11}
   ```

4. **Install and start the Auth Bridge and Policy Agent services**

### Data Paths (Windows)

| Path | Purpose |
|---|---|
| `C:\ProgramData\DDS\node-data\` | Node database, keys, admission cert |
| `C:\ProgramData\DDS\dds.toml` | Node configuration |
| `C:\ProgramData\DDS\node-data\domain.toml` | Domain public identity |
| `C:\ProgramData\DDS\node-data\admission.cbor` | Admission certificate |

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
| `dds-node` | Rust binary (launchd service) | P2P node + HTTP API |
| DDS Policy Agent | .NET macOS app (runs as root) | Enforces macOS policy |

### Installation via macOS Installer

The `platform/macos/packaging/` directory contains the macOS installer, which handles:
- Domain bootstrap (genesis or join)
- Admin enrollment
- launchd service installation

### Data Paths (macOS)

| Path | Purpose |
|---|---|
| `/Library/Application Support/DDS/node-data/` | Node database, keys, admission cert |
| `/Library/Application Support/DDS/dds.toml` | Node configuration |
| `/Library/LaunchDaemons/com.dds.node.plist` | launchd service definition |

### Policy Agent Configuration

The macOS policy agent reads from `appsettings.json` or environment variables:

```bash
export DdsPolicyAgent__DeviceUrn='urn:dds:device:mac-1'
export DdsPolicyAgent__NodeBaseUrl='http://127.0.0.1:5551'
export DdsPolicyAgent__StateDir='/Library/Application Support/DDS/state'
```

The agent must run as `root` for account, profile, software, and launchd operations.

### Capabilities

| Capability | Backend | Notes |
|---|---|---|
| Managed preferences | `plutil` (plist) | Safe for production |
| Local accounts | `dscl`, `pwpolicy`, `sysadminctl` | Test on disposable host first |
| launchd services | `launchctl` | Safe with test plist paths |
| Configuration profiles | `profiles` CLI | Test on disposable host first |
| Software install | `/usr/sbin/installer` | SHA-256 verified, signed `.pkg` |

### Multi-Machine E2E

For validating a real two-Mac mesh deployment, see [platform/macos/e2e/README.md](../platform/macos/e2e/README.md).

---

## Monitoring and Diagnostics

### Node Status

```bash
# Via HTTP API
curl http://127.0.0.1:5551/v1/status | jq

# Via CLI
dds status
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
dds cp --node-url http://127.0.0.1:5551 enrolled-users [--device-urn ...]
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
