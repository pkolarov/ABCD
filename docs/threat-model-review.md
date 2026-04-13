# DDS Threat Model Review

This document reviews the security properties and known gaps in the DDS
trust architecture, focusing on admission certificates, identity storage,
key management, and platform-specific concerns.

---

## 1. Admission Certificate Flow

### Design

Each DDS node holds an `AdmissionCert` (CBOR-encoded, Ed25519-signed by the
domain key) that binds a libp2p `PeerId` to the domain. At startup, the node
loads the cert from `<data_dir>/admission.cbor`, verifies the signature
against the domain public key in `NodeConfig`, and refuses to start if
verification fails.

### Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Bearer token** — admission cert is a static file with no channel binding. Anyone who obtains a copy can impersonate the admitted peer on another machine. | High | The cert binds to a `PeerId` derived from a libp2p Ed25519 keypair stored in `p2p_key.bin`. An attacker needs both the cert AND the private key. However, if both files are copied, the node is fully cloned. |
| **No revocation** — there is no mechanism to revoke an admission cert. A compromised node stays admitted until the domain key is rotated. | High | **Gap**: Add a domain-level revocation list (signed by the domain key) that nodes exchange via gossip. Peers check the list before accepting connections. |
| **No expiry enforcement** — `AdmissionBody::expires_at` is optional and not checked at connection time by peers. | Medium | The field exists in the struct but peer-to-peer handshake does not validate it. Wire up expiry checking in the libp2p connection handler. |
| **Replay** — a captured admission cert can be replayed indefinitely since there is no nonce or timestamp-based freshness check beyond the optional `expires_at`. | Medium | Addressed by binding to `PeerId` (which requires the corresponding private key). True replay requires key theft. |

### Recommendations

1. Add `admission_cert_ttl_days` config field; nodes reject peers whose cert
   `expires_at` is in the past.
2. Implement a domain-signed revocation list gossipped on the `dds-revoke` topic.
3. Consider mutual admission cert exchange during libp2p Noise handshake so
   both peers verify domain membership before any application traffic.

---

## 2. Identity Store Encryption

### Design

Node identity keys (`node_key.bin`, `p2p_key.bin`) are stored as CBOR maps:

```
{ "v": 2, "salt": bytes(16), "nonce": bytes(12), "key": encrypted_bytes }
```

- **KDF**: Argon2id with parameters: memory = 19 MiB, iterations = 2,
  parallelism = 1, output = 32 bytes.
- **Cipher**: ChaCha20-Poly1305 (AEAD).
- **Passphrase source**: `DDS_NODE_PASSPHRASE` environment variable (node key)
  or `DDS_DOMAIN_PASSPHRASE` (domain key).

### Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Low Argon2id memory cost** — 19 MiB is below the OWASP minimum recommendation of 19 MiB (passes) but well below the preferred 64+ MiB for high-value keys. | Low | Current parameters are tuned for ARM64 embedded targets with limited RAM. Desktop deployments should increase to 64 MiB. Add a configurable `kdf_memory_kib` field. |
| **Passphrase in environment variable** — environment variables are visible in `/proc/<pid>/environ` on Linux and via process inspection on Windows. | Medium | Standard practice for containerized deployments. Document that production deployments should use secret managers (HashiCorp Vault, Azure Key Vault) to inject the passphrase and clear the env var after startup. |
| **Plaintext fallback** — if the passphrase env var is not set, keys are stored unencrypted (version = 1). | High | The code logs a warning but does not prevent startup. Consider requiring encryption in non-development modes, or at minimum logging at ERROR level. |
| **No key rotation** — there is no built-in mechanism to rotate node identity keys. Rotation requires re-provisioning the node and re-issuing its admission cert. | Medium | **Gap**: Implement `rotate-identity` CLI command that generates a new keypair, re-encrypts, and requests a new admission cert from the domain admin. |

### Recommendations

1. Default to 64 MiB Argon2id memory for desktop builds; keep 19 MiB behind
   a `--embedded` flag.
2. Add a `--require-passphrase` flag that refuses to start if the passphrase
   env var is not set.
3. Implement key rotation with automatic admission cert renewal.

---

## 3. Windows Platform Security

### ACL Gap

The Windows MSI installer places files under `C:\Program Files\DDS\` (admin-
writable only) and data under `C:\ProgramData\DDS\` (writable by SYSTEM and
Administrators). However:

| Gap | Risk | Recommendation |
|-----|------|----------------|
| `C:\ProgramData\DDS\node_key.bin` is readable by Administrators group | Medium — any admin-level process can read the node private key | Set an explicit DACL on the DDS data directory granting access only to `NT AUTHORITY\SYSTEM` and the `DDS Node Service` virtual account. |
| Policy Agent runs as `LocalSystem` | Low — standard for Windows services, but grants broad privilege | Consider running as `NT SERVICE\DdsPolicyAgent` (virtual service account) with minimal privileges. |
| Credential Provider DLL runs in `winlogon.exe` context | Low — inherent to the Windows CP architecture | Ensure the DLL is Authenticode-signed (CI scaffolding exists, signing cert pending). |

### Recommendations

1. Add a post-install custom action in the MSI that sets restrictive ACLs on
   `C:\ProgramData\DDS\`.
2. Switch the Policy Agent service to run as a virtual service account.
3. Enable Authenticode signing in CI once the signing certificate is provisioned.

---

## 4. libp2p Transport Security

### Current State

- **Noise protocol**: All peer connections use libp2p's Noise XX handshake,
  providing mutual authentication and forward secrecy.
- **Gossipsub**: Messages are broadcast in plaintext over the encrypted
  transport. Any domain member can observe all gossip traffic.

### Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **No message-level encryption** — gossip messages (tokens, sync payloads) are CBOR-encoded but not encrypted at the application layer. | Low | Transport encryption (Noise) protects against external eavesdroppers. Internal confidentiality is not a current goal — all domain members are expected to see all tokens. |
| **Peer ID spoofing** — if a node's libp2p keypair is stolen, an attacker can impersonate that peer. | Medium | Addressed by admission cert binding. Stolen keypair alone is not sufficient without the matching admission cert. |
| **No gossip message signing** — gossip messages do not carry an application-level signature. | Low | Individual tokens are signed by their issuer. The trust graph verifies signatures on ingest. Unsigned gossip is acceptable because invalid tokens are rejected. |

---

## 5. Trust Graph & Delegation

### Current Protections

- **Delegation depth cap**: Configurable via `max_delegation_depth` (default 5).
  Prevents unbounded vouch chains.
- **Revocation**: Tokens can be revoked by their issuer. Revocation is
  propagated via gossip and persisted in the revocation set.
- **Burn**: Identity URNs can be permanently burned, preventing any future
  use of that identity.
- **Self-revocation only**: A token can only be revoked by the identity that
  issued it, preventing unauthorized revocation by third parties.

### Remaining Gaps

| Gap | Risk | Recommendation |
|-----|------|----------------|
| **No trust graph partitioning** — all tokens are visible to all nodes. | Low | By design for the single-domain model. Multi-domain deployments would need topic-level isolation. |
| **Expiry sweep race** — the expiry sweeper runs on a timer; a token that just expired may be evaluated as valid until the next sweep. | Low | The window is bounded by `expiry_scan_interval_secs` (default 60s). For real-time expiry checking, add an inline expiry check in `evaluate_policy`. |

---

## 6. Summary of Open Items

| # | Item | Priority | Section |
|---|------|----------|---------|
| 1 | Admission cert revocation list | High | §1 |
| 2 | Require identity encryption in production | High | §2 |
| 3 | Windows data directory ACLs | Medium | §3 |
| 4 | Key rotation mechanism | Medium | §2 |
| 5 | Admission cert expiry enforcement | Medium | §1 |
| 6 | Increase Argon2id memory for desktop | Low | §2 |
| 7 | Virtual service account for Policy Agent | Low | §3 |
