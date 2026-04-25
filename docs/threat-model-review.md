# DDS Threat Model Review

This document reviews the security properties and known gaps in the DDS
trust architecture, focusing on admission certificates, identity storage,
key management, and platform-specific concerns.

> **Currency (2026-04-21).** This review has been superseded in scope
> by the full independent review in
> [Claude_sec_review.md](../Claude_sec_review.md) (source-validated,
> per-finding severity, remediation ledger). The sections below are
> retained for architectural context. Findings that have since been
> closed by the 2026-04-17 → 2026-04-21 remediation sweep are marked
> ~~with strikethrough~~ and a link to the fix.
>
> **2026-04-25 update.** A later independent source pass added six
> open findings to the review ledger: B-1 through B-6. The highest-risk
> architectural additions are sync persistence before trust-graph
> acceptance, purpose grants that are not tied to a live target
> attestation, and endpoint agents marking failed enforcement as
> complete. They are summarized in the relevant sections below.

---

## 1. Admission Certificate Flow

### Design

Each DDS node holds an `AdmissionCert` (CBOR-encoded, Ed25519-signed by the
domain key) that binds a libp2p `PeerId` to the domain. At startup, the node
loads the cert from `<data_dir>/admission.cbor`, verifies the signature
against the domain public key in `NodeConfig`, and refuses to start if
verification fails.

**2026-04-20 update — per-peer admission (H-12 fixed).** In addition to
self-verification at startup, nodes now run a
`request_response::cbor::Behaviour` exchange on
`/dds/admission/1.0.0/<domain>` immediately after the libp2p Noise
handshake. Each peer verifies the other's admission cert against the
domain pubkey, the domain id, and the remote `PeerId` before admitting
them. `DdsNode::admitted_peers` is the authoritative gate for
`handle_gossip_message` and `handle_sync_event` — messages from
unadmitted peers are dropped at the behaviour layer.

### Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **Bearer token** — admission cert is a static file with no channel binding. Anyone who obtains a copy can impersonate the admitted peer on another machine. | High | The cert binds to a `PeerId` derived from a libp2p Ed25519 keypair stored in `p2p_key.bin`. An attacker needs both the cert AND the private key. However, if both files are copied, the node is fully cloned. |
| **No revocation** — there is no mechanism to revoke an admission cert. A compromised node stays admitted until the domain key is rotated. | High | **Gap**: Add a domain-level revocation list (signed by the domain key) that nodes exchange via gossip. Peers check the list before accepting connections. |
| ~~**No expiry enforcement** — `AdmissionBody::expires_at` is optional and not checked at connection time by peers.~~ | ~~Medium~~ | **FIXED (M-6)**. `DdsNode::run` re-verifies the admission cert every 600 s against `(domain_pubkey, domain_id, peer_id, now)`; expiry triggers a clean shutdown. |
| **Replay** — a captured admission cert can be replayed indefinitely since there is no nonce or timestamp-based freshness check beyond the optional `expires_at`. | Medium | Addressed by binding to `PeerId` (which requires the corresponding private key). True replay requires key theft. |

### Recommendations

1. ~~Add `admission_cert_ttl_days` config field; nodes reject peers whose cert
   `expires_at` is in the past.~~ → **closed by M-6**.
2. Implement a domain-signed revocation list gossipped on the `dds-revoke` topic.
3. ~~Consider mutual admission cert exchange during libp2p Noise handshake so
   both peers verify domain membership before any application traffic.~~ →
   **closed by H-12** (via request-response behaviour that runs immediately
   after Noise; see the 2026-04-20 update above).

---

## 2. Identity Store Encryption

### Design

Node identity keys (`node_key.bin`, `p2p_key.bin`) are stored as CBOR maps.
The keyfile has been iterated twice through the remediation sweep:

```
// v=3 (current) — M-10 (2026-04-20)
{ "v": 3, "salt": bytes(16), "nonce": bytes(12), "key": encrypted_bytes,
  "m_cost": uint, "t_cost": uint, "p_cost": uint }

// v=2 (legacy) — transparently rewrapped to v=3 on first successful load
{ "v": 2, "salt": bytes(16), "nonce": bytes(12), "key": encrypted_bytes }
```

- **KDF (v=3)**: Argon2id, m=64 MiB, t=3, p=4 (OWASP tier-2; target unlock
  200–500 ms on modern hardware). v=2 used m=19 MiB, t=2, p=1.
- **Cipher**: ChaCha20-Poly1305 (AEAD).
- **Passphrase source**: `DDS_NODE_PASSPHRASE` environment variable (node key)
  or `DDS_DOMAIN_PASSPHRASE` (domain key).
- **Encrypted marker (M-14)**: a sticky `<path>.encrypted-marker` file is
  written after any successful encrypted save; subsequent plaintext saves
  are refused unless `DDS_NODE_ALLOW_PLAINTEXT_DOWNGRADE=1` is set.

### Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| ~~**Low Argon2id memory cost** — 19 MiB is below the preferred 64+ MiB for high-value keys.~~ | ~~Low~~ | **FIXED (M-10)**: v=3 defaults to m=64 MiB, t=3, p=4. Params are carried in the blob so a future bump is a schema-less config change. |
| **Passphrase in environment variable** — environment variables are visible in `/proc/<pid>/environ` on Linux and via process inspection on Windows. | Medium | Standard practice for containerized deployments. Document that production deployments should use secret managers (HashiCorp Vault, Azure Key Vault) to inject the passphrase and clear the env var after startup. |
| ~~**Plaintext fallback** — if the passphrase env var is not set, keys are stored unencrypted (version = 1).~~ | ~~High~~ | **FIXED (M-14)**: a sticky `encrypted` marker is written on first encrypted save; subsequent plaintext saves are refused by default. `DDS_NODE_ALLOW_PLAINTEXT_DOWNGRADE=1` is an explicit escape hatch (logged at WARN). Defeats the attack in the original review. |
| **No key rotation** — there is no built-in mechanism to rotate node identity keys. Rotation requires re-provisioning the node and re-issuing its admission cert. | Medium | **Gap**: Implement `rotate-identity` CLI command that generates a new keypair, re-encrypts, and requests a new admission cert from the domain admin. |

### Recommendations

1. ~~Default to 64 MiB Argon2id memory for desktop builds.~~ →
   **closed by M-10** (now the default).
2. ~~Add a `--require-passphrase` flag that refuses to start if the
   passphrase env var is not set.~~ →
   **closed by M-14** (encrypted marker refuses plaintext downgrade
   once encryption has been used).
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
| Policy Agent runs as `LocalSystem` | Low — standard for Windows services, but grants broad privilege | **Deferred (M-18).** Review-tracked as a multi-day refactor: split the HTTP-polling half of PolicyAgent and the Auth Bridge into dedicated service SIDs and impersonate up only when applying policy. |
| Credential Provider DLL runs in `winlogon.exe` context | Low — inherent to the Windows CP architecture | Ensure the DLL is Authenticode-signed (CI scaffolding exists, signing cert pending). |
| ~~Credential Provider named-pipe DACL admits `INTERACTIVE`~~ | ~~High~~ | **FIXED (H-5)**: SDDL tightened to `SY`-only; cross-user credential theft vector closed. |
| ~~Policy Agent `applied-state.json` inherits the parent directory ACL~~ | ~~Low~~ | **FIXED (L-16)**: explicit DACL applied before atomic rename so the file never observably exists with the inherited ACL. |

### Recommendations

1. Add a post-install custom action in the MSI that sets restrictive ACLs on
   `C:\ProgramData\DDS\`. (The file-mode portion of this is already done by
   M-20 / L-16; the directory-level DACL is still outstanding.)
2. Switch the Policy Agent service to run as a virtual service account
   (M-18, deferred — see above).
3. Enable Authenticode signing in CI once the signing certificate is provisioned.

---

## 4. libp2p Transport Security

### Current State

- **Noise protocol**: All peer connections use libp2p's Noise XX handshake,
  providing mutual authentication and forward secrecy.
- **Admission handshake (H-12)**: Immediately after Noise each peer runs
  the admission-cert exchange on `/dds/admission/1.0.0/<domain>` and
  must present a valid cert before any gossip or sync from them is
  ingested.
- **Gossipsub**: Messages are broadcast in plaintext over the encrypted
  transport. Any admitted domain member can observe all gossip traffic.

### Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **No message-level encryption** — gossip messages (tokens, sync payloads) are CBOR-encoded but not encrypted at the application layer. | Low | Transport encryption (Noise) protects against external eavesdroppers. Internal confidentiality is not a current goal — all domain members are expected to see all tokens. |
| **Peer ID spoofing** — if a node's libp2p keypair is stolen, an attacker can impersonate that peer. | Medium | Addressed by admission cert binding. Stolen keypair alone is not sufficient without the matching admission cert. |
| **No gossip message signing** — gossip messages do not carry an application-level signature. | Low | Individual tokens are signed by their issuer. The trust graph verifies signatures on ingest. Unsigned gossip is acceptable because invalid tokens are rejected. |
| ~~Pre-admission gossip ingest~~ | ~~High~~ | **FIXED (H-12)**: per-peer admission gating drops gossip / sync from non-admitted peers at the behaviour layer. Combined with C-3's publisher-capability filter, which remains as defense in depth. |

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
- **Publisher capability filter (C-3)**: policy / software attestations
  are only admitted into the trust graph when the issuer chains back to
  a trusted root with `dds:policy-publisher-windows`,
  `dds:policy-publisher-macos`, or `dds:software-publisher`. Enforced at
  both gossip ingest and at serve time as defense in depth.
- **Replay window (M-9)**: `revocation_within_replay_window` refuses
  revoke/burn tokens whose `iat` is outside the 7-day sliding window,
  blocking old-token rebroadcast attacks.
- **Unknown-target revocation (H-1)**: revocations whose target JTI is
  not in the graph are rejected outright rather than deferred.
- **JTI uniqueness (H-4)**: attestation JTIs are suffixed with UUIDv4 to
  prevent collision-based overwrite attacks.

### Remaining Gaps

| Gap | Risk | Recommendation |
|-----|------|----------------|
| **Sync persistence before validation (B-1)** — sync response application can write duplicate-JTI tokens and revoke/burn side effects to persistent storage even when the trust graph rejects the token. | High | Make trust-graph acceptance the first durable gate; make token storage put-if-absent or exact-byte idempotent; apply revoke/burn side effects only after graph acceptance. |
| **Purpose grants not bound to live target attestations (B-2)** — `has_purpose` / `purposes_for` can rely on revoked/expired target attestations, and inbound token validation does not enforce the vouch shape invariants used by local token creation. | High | Share one token structural validator across creation, decode/validate, and graph ingest. Require a matching unrevoked, unexpired target attestation for every vouched purpose. |
| **No deterministic active-version selection (B-4)** — multiple active policy/software attestations with the same logical ID can all be served, leaving final state to iteration order. | Medium | Add supersession semantics, require old-version revocation, or select one latest valid document per logical ID at serve time. |
| **No trust graph partitioning** — all tokens are visible to all nodes. | Low | By design for the single-domain model. Multi-domain deployments would need topic-level isolation. |
| **Challenge store cleanup is passive (B-5)** — expired session/admin challenges are not deleted on failed consume and no production sweeper calls `sweep_expired_challenges`. | Medium | Sweep on issue/consume, delete expired rows when encountered, and cap outstanding challenges per caller/kind. |
| **Expiry sweep race** — the expiry sweeper runs on a timer; a token that just expired may be evaluated as valid until the next sweep. | Low | The window is bounded by `expiry_scan_interval_secs` (default 60s). For real-time expiry checking, add an inline expiry check in `evaluate_policy`. |
| **Admin set is per-node local** — `trusted_roots` is read from local TOML; peers can disagree about who is an admin (I-11). | Medium | A future redesign should chain admins back to a domain-key-signed genesis attestation so the admin set is derived from gossip. |

---

## 6. Transport Authentication (H-6 / H-7)

### Current State

The local HTTP API now dispatches on `api_addr` scheme:

| Scheme | Transport | Peer-cred source | Use |
|---|---|---|---|
| `127.0.0.1:<port>` | loopback TCP (legacy) | none — caller is `CallerIdentity::Anonymous` | backward compat; flip off with `strict_device_binding = true` once clients move |
| `unix:/path/to/sock` | UDS (Linux/macOS) | `stream.peer_cred()` → `CallerIdentity::Uds { uid, gid, pid }` | Recommended on Linux/macOS |
| `pipe:<name>` | Windows named pipe | `GetNamedPipeClientProcessId` + `OpenProcessToken` + `GetTokenInformation(TokenUser)` → `CallerIdentity::Pipe { sid, pid }` | Recommended on Windows |

Clients that have been updated:
- `dds-cli` (hyper + `UnixStream` for `unix:` URLs).
- macOS Policy Agent (`DdsNodeHttpFactory` with `ConnectCallback` to
  `UnixDomainSocketEndPoint`).
- Windows Policy Agent (same, plus `NamedPipeClientStream`).
- C++ Auth Bridge (`SendRequestPipe` over `CreateFileW` +
  `WriteFile`/`ReadFile`; unverified on Windows pending CI).

Response-body MAC (H-6): when
`network.api_auth.node_hmac_secret_path` is set, every response carries
`X-DDS-Body-MAC: base64(HMAC-SHA256(key, method || 0 || path || 0 || body))`.
The MSI's `CA_GenHmacSecret` custom action provisions the 32-byte
per-install secret at install time; the Auth Bridge loads the same file
via `HKLM\SOFTWARE\DDS\AuthBridge\HmacSecretPath` and verifies the MAC on
every response. Mismatched / missing MAC → body cleared, status 0 →
caller fails closed.

### Recommendations

1. Finish the operational cutover on every deployment: switch
   `api_addr` to `unix:…` / `pipe:…`, then flip both
   `trust_loopback_tcp_admin = false` and `strict_device_binding = true`.
2. Run Windows CI on the C++ Auth Bridge pipe path (`SendRequestPipe`)
   and the MSI custom action (`CA_GenHmacSecret`). Macro-verified on
   macOS; Windows runtime still needed.
3. For the Windows software installer TOCTOU gap (B-6), move package
   staging out of `%TEMP%` into a SYSTEM/Admin-only cache and rehash
   immediately before launch.

---

## 7. Endpoint Agent Convergence

### Current State

Windows and macOS policy agents persist `applied-state.json` so they can
skip unchanged policy and software documents. This keeps steady-state
polls cheap, but the state machine needs to distinguish successful
application from failed application.

### Remaining Gaps

| Gap | Risk | Recommendation |
|-----|------|----------------|
| **Failed enforcement can be marked complete (B-3)** — Windows records `"ok"` even when enforcers fail; macOS records failure but `HasChanged` ignores status, so unchanged failed documents are skipped on later polls. | High | Record success only after successful outcomes. Include status in `HasChanged`, retry failed entries, and keep reporting failure until the document succeeds or is superseded. |

---

## 8. Summary of Open Items

| # | Item | Priority | Section |
|---|------|----------|---------|
| 1 | Sync persistence before trust-graph acceptance (B-1) | High | §5 |
| 2 | Live-attestation requirement for purpose grants (B-2) | High | §5 |
| 3 | Failed enforcement retry semantics (B-3) | High | §7 |
| 4 | Admission cert revocation list | High | §1 |
| 5 | Active-version selection for policies/software (B-4) | Medium | §5 |
| 6 | Challenge-store cleanup and caps (B-5) | Medium | §5 |
| 7 | Windows software staging TOCTOU hardening (B-6) | Medium | §6 |
| 8 | Windows data directory ACL (dir-level) | Medium | §3 |
| 9 | Key rotation mechanism | Medium | §2 |
| 10 | WiX virtual service account split (M-18) | Medium | §3 |
| 11 | Admin-set coherence via gossip (I-11) | Medium | §5 |
| 12 | Message-level encryption (opt-in) | Low | §4 |
| 13 | Real-time expiry in `evaluate_policy` | Low | §5 |

All Critical findings from the source-validated review are now Fixed
(pending verify). Three new High findings from the 2026-04-25 follow-up
remain open: B-1, B-2, and B-3.
