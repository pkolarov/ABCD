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
> open findings to the review ledger: B-1 through B-6. **All six
> have since landed in this branch** (latest follow-up 2026-04-25
> #5 — see Claude_sec_review.md and STATUS.md for the per-finding
> ledger). The Windows-side DACL helper for B-6 is the only piece
> still requiring Windows CI exercise; the cross-platform tamper
> defense is green on the dev host. Sections below have been
> updated to reflect closure.

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
| ~~**No revocation** — there is no mechanism to revoke an admission cert. A compromised node stays admitted until the domain key is rotated.~~ | ~~High~~ | **FIXED (2026-04-26)**: domain-signed `AdmissionRevocation` tokens (`dds-domain::AdmissionRevocation`), persisted at `<data_dir>/admission_revocations.cbor` (`dds-node::admission_revocation_store`). The H-12 handshake refuses to admit a peer whose id appears in the list, and `DdsNode::init` refuses to start if the local node's own peer id is revoked. CLI: `dds-node revoke-admission` issues a revocation, `dds-node import-revocation` adds it to a node, and `dds-node list-revocations` reports the on-disk contents (under the same domain-pubkey verification gate as the runtime path) so operators can confirm a revocation actually landed — both via manual import and via H-12 piggy-back gossip. **2026-04-26 (same day) follow-up**: `AdmissionResponse` now piggy-backs the local revocation list (capped at `MAX_REVOCATIONS_PER_RESPONSE = 1024` per response) on every H-12 handshake; receivers verify each entry against the domain pubkey via `AdmissionRevocationStore::merge` and persist any newly-learned entries atomically — revocations now propagate transitively as peers reconnect, no more manual file copy required for domain-wide rollout. |
| ~~**No expiry enforcement** — `AdmissionBody::expires_at` is optional and not checked at connection time by peers.~~ | ~~Medium~~ | **FIXED (M-6)**. `DdsNode::run` re-verifies the admission cert every 600 s against `(domain_pubkey, domain_id, peer_id, now)`; expiry triggers a clean shutdown. |
| **Replay** — a captured admission cert can be replayed indefinitely since there is no nonce or timestamp-based freshness check beyond the optional `expires_at`. | Medium | Addressed by binding to `PeerId` (which requires the corresponding private key). True replay requires key theft. |

### Recommendations

1. ~~Add `admission_cert_ttl_days` config field; nodes reject peers whose cert
   `expires_at` is in the past.~~ → **closed by M-6**.
2. ~~Implement a domain-signed revocation list gossipped on the `dds-revoke` topic.~~
   → **fully closed (2026-04-26)**: domain-signed revocation type
   (`AdmissionRevocation`) with on-disk store and H-12 enforcement
   landed in the morning pass; the same-day follow-up wired the
   list onto `AdmissionResponse` so every H-12 handshake piggy-backs
   the sender's local revocations. Receivers verify each entry
   independently against the domain pubkey before persisting, so
   the worst a hostile admitted peer can do is *omit* revocations —
   no different from today's manual-file-copy floor. The wire field
   is bounded by `MAX_REVOCATIONS_PER_RESPONSE` (1024 entries ≈ 125 KB)
   so a single handshake stays inside libp2p's request-response
   budget; lists exceeding the cap fan out across subsequent
   reconnections. A dedicated `dds-revoke` gossipsub topic is no
   longer needed for the v1 enforcement path.
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
| ~~**No key rotation** — there is no built-in mechanism to rotate node identity keys. Rotation requires re-provisioning the node and re-issuing its admission cert.~~ | ~~Medium~~ | **PARTIALLY FIXED (2026-04-26)**: `dds-node rotate-identity --data-dir <DIR> [--no-backup]` rotates the libp2p keypair in place. It reads the existing `p2p_key.bin` (refusing to proceed if the blob is encrypted but `DDS_NODE_PASSPHRASE` is not set, so the old PeerId is never silently lost), backs up the previous file as `p2p_key.bin.rotated.<unix_seconds>` unless `--no-backup`, atomically writes the new keypair under the same on-disk schema (v=3 ChaCha20-Poly1305 + Argon2id when a passphrase is configured), and prints both PeerIds plus the explicit follow-up commands the admin must run (`admit` + optional `revoke-admission`). The remaining gap (the recommendation's "automatic" cert renewal — admin signature is intentionally still a manual ceremony so the rotation cannot be initiated by a compromised node) is documented under §8 item #9. |

### Recommendations

1. ~~Default to 64 MiB Argon2id memory for desktop builds.~~ →
   **closed by M-10** (now the default).
2. ~~Add a `--require-passphrase` flag that refuses to start if the
   passphrase env var is not set.~~ →
   **closed by M-14** (encrypted marker refuses plaintext downgrade
   once encryption has been used).
3. ~~Implement key rotation with automatic admission cert renewal.~~ →
   **partially closed (2026-04-26)** by `dds-node rotate-identity`,
   which rotates the libp2p keypair in place and prints the
   admin / operator follow-up commands needed to land a fresh
   admission cert (and revoke the old one). The "automatic" half of
   the recommendation is intentionally left out — admission certs
   stay a manual admin ceremony so a compromised node cannot
   self-renew its own admission. Operators can wrap the printed
   commands in their own automation if they trust the path between
   the rotating node and the admin signer.

---

## 3. Windows Platform Security

### ACL Gap

The Windows MSI installer places files under `C:\Program Files\DDS\` (admin-
writable only) and data under `C:\ProgramData\DDS\` (writable by SYSTEM and
Administrators). However:

| Gap | Risk | Recommendation |
|-----|------|----------------|
| ~~`C:\ProgramData\DDS\node_key.bin` is readable by Administrators group~~ | ~~Medium~~ | **PARTIALLY FIXED (2026-04-26)**: the MSI's new `CA_RestrictDataDirAcl` custom action runs `dds-node restrict-data-dir-acl --data-dir [CommonAppDataFolder]DDS` immediately after `InstallFiles` (and before `CA_GenHmacSecret`), applying SDDL `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` so the directory inherits `FullControl` only for `LocalSystem` and `BUILTIN\Administrators`, with `OI`+`CI` inheritance to children. `node_key.bin`, `node-hmac.key`, `applied-state.json`, and audit logs created later all pick up the restricted DACL by inheritance. The narrow remaining gap (granting access to `Administrators` rather than to a dedicated service SID) is tracked under M-18. |
| Policy Agent runs as `LocalSystem` | Low — standard for Windows services, but grants broad privilege | **Deferred (M-18).** Review-tracked as a multi-day refactor: split the HTTP-polling half of PolicyAgent and the Auth Bridge into dedicated service SIDs and impersonate up only when applying policy. |
| Credential Provider DLL runs in `winlogon.exe` context | Low — inherent to the Windows CP architecture | Ensure the DLL is Authenticode-signed (CI scaffolding exists, signing cert pending). |
| ~~Credential Provider named-pipe DACL admits `INTERACTIVE`~~ | ~~High~~ | **FIXED (H-5)**: SDDL tightened to `SY`-only; cross-user credential theft vector closed. |
| ~~Policy Agent `applied-state.json` inherits the parent directory ACL~~ | ~~Low~~ | **FIXED (L-16)**: explicit DACL applied before atomic rename so the file never observably exists with the inherited ACL. |

### Recommendations

1. ~~Add a post-install custom action in the MSI that sets restrictive ACLs on
   `C:\ProgramData\DDS\`. (The file-mode portion of this is already done by
   M-20 / L-16; the directory-level DACL is still outstanding.)~~ →
   **closed (2026-04-26)**: `dds-node restrict-data-dir-acl` subcommand
   + `CA_RestrictDataDirAcl` MSI custom action sequenced before
   `CA_GenHmacSecret`. C++ Auth Bridge `FileLog::Init` keeps its
   self-heal call as defense in depth (covers the dev-host /
   manually-installed-binary case where the MSI did not run).
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
| **Sync persistence before validation (B-1)** ✅ closed 2026-04-25 — `apply_sync_payloads_with_graph` now feeds the trust graph before any persistent write, and `store.put_token` / `store.revoke` / `store.burn` only fire on graph acceptance; `put_token` additionally uses put-if-absent semantics so duplicate JTIs cannot overwrite. | High | (closed — see Claude_sec_review.md) |
| **Purpose grants not bound to live target attestations (B-2)** ✅ closed 2026-04-25 — `Token::create_with_version` and `Token::validate` share `Token::validate_shape` (called by `TrustGraph::add_token`), and `has_purpose` / `purposes_for` / `walk_chain` route through `active_attestation_for_iss` which skips revoked, expired, and burned-issuer attestations. | High | (closed — see Claude_sec_review.md) |
| **No deterministic active-version selection (B-4)** ✅ closed 2026-04-25 — `LocalService::list_applicable_*` now collapses duplicate `policy_id` / `package_id` at serve time (highest version → latest iat → lex-smallest jti) and emits in stable id-sorted order. | Medium | (closed — see Claude_sec_review.md) |
| **No trust graph partitioning** — all tokens are visible to all nodes. | Low | By design for the single-domain model. Multi-domain deployments would need topic-level isolation. |
| **Challenge store cleanup is passive (B-5)** ✅ closed 2026-04-25 — expired session/admin challenges were not deleted on failed consume and no production sweeper called `sweep_expired_challenges`. | Medium | The issue path (`http::issue_challenge`) now sweeps expired rows on every put, enforces a `MAX_OUTSTANDING_CHALLENGES = 4096` global cap (returning 503 when the backlog is full), and `consume_challenge` deletes expired/malformed rows in the same write transaction. A new `count_challenges` method on `ChallengeStore` backs the cap check; tests added in `dds-store` (4) and `dds-node::http` (2). |
| ~~**Expiry sweep race** — the expiry sweeper runs on a timer; a token that just expired may be evaluated as valid until the next sweep.~~ ✅ closed: the trust-graph hot paths (`has_purpose`, `purposes_for`, `walk_chain`, `active_attestation_for_iss`) already filter tokens via `is_expired()` against `SystemTime::now()` on every call, so a token whose `exp` has passed is dropped from policy evaluation immediately — independent of when the periodic `sweep_expired` next runs. The sweep exists only to reclaim store space. Three regression tests in `dds-core::trust::tests` (`realtime_expiry_drops_grant_in_has_purpose_and_purposes_for`, `realtime_expiry_in_target_attestation_drops_grant`, `realtime_expiry_breaks_chain_at_intermediate_vouch`) pin the contract — none of them call `sweep_expired`. | Low | (closed — see regression tests above) |
| **Admin set is per-node local** — `trusted_roots` is read from local TOML; peers can disagree about who is an admin (I-11). | Medium | A future redesign should chain admins back to a domain-key-signed genesis attestation so the admin set is derived from gossip. |

---

## 6. Transport Authentication (H-6 / H-7)

### Current State

The local HTTP API now dispatches on `api_addr` scheme:

| Scheme | Transport | Peer-cred source | Use |
|---|---|---|---|
| `127.0.0.1:<port>` | loopback TCP (legacy; Linux/macOS dev default) | none — caller is `CallerIdentity::Anonymous` | backward compat; flip off with `strict_device_binding = true` once clients move |
| `unix:/path/to/sock` | UDS (Linux/macOS) | `stream.peer_cred()` → `CallerIdentity::Uds { uid, gid, pid }` | Recommended on Linux/macOS |
| `pipe:<name>` | Windows named pipe (Windows MSI default since A-2) | `GetNamedPipeClientProcessId` + `OpenProcessToken` + `GetTokenInformation(TokenUser)` → `CallerIdentity::Pipe { sid, pid }` | Default on Windows |

Clients that have been updated:
- `dds-cli` (hyper + `UnixStream` for `unix:` URLs).
- macOS Policy Agent (`DdsNodeHttpFactory` with `ConnectCallback` to
  `UnixDomainSocketEndPoint`).
- Windows Policy Agent (same, plus `NamedPipeClientStream`).
- C++ Auth Bridge (`SendRequestPipe` over `CreateFileW` +
  `WriteFile`/`ReadFile`; verified on Windows x64 host 2026-04-24).
- **A-2 (2026-04-25)**: Windows Auth Bridge `CDdsConfiguration` now
  reads an `ApiAddr` REG_SZ alongside `DdsNodePort` and routes through
  `SetBaseUrl`, and the MSI provisions
  `HKLM\SOFTWARE\DDS\AuthBridge\ApiAddr = pipe:dds-api`. The shipped
  `node.toml` template defaults `api_addr = 'pipe:dds-api'` and
  `[network.api_auth] trust_loopback_tcp_admin = false`. Stock MSI
  installs reach the H-7 step-2b pipe transport without operator
  changes.

Response-body MAC (H-6): when
`network.api_auth.node_hmac_secret_path` is set, every response carries
`X-DDS-Body-MAC: base64(HMAC-SHA256(key, method || 0 || path || 0 || body))`.
The MSI's `CA_GenHmacSecret` custom action provisions the 32-byte
per-install secret at install time; the Auth Bridge loads the same file
via `HKLM\SOFTWARE\DDS\AuthBridge\HmacSecretPath` and verifies the MAC on
every response. Mismatched / missing MAC → body cleared, status 0 →
caller fails closed.

### Recommendations

1. Finish the operational cutover on every Linux/macOS deployment:
   switch `api_addr` to `unix:…`, then flip both
   `trust_loopback_tcp_admin = false` and `strict_device_binding = true`.
   Windows MSI installs already ship pipe-by-default with
   `trust_loopback_tcp_admin = false` since A-2 (2026-04-25); flip
   `strict_device_binding = true` next.
2. Verified on Windows x64 host 2026-04-24: C++ Auth Bridge pipe path
   (`SendRequestPipe`) and the MSI custom action (`CA_GenHmacSecret`).
   A-2 closes the runtime-config gap so the pipe transport is reachable
   from a stock MSI install — real-hardware login reverify pending.
3. ~~For the Windows software installer TOCTOU gap (B-6), move package
   staging out of `%TEMP%` into a SYSTEM/Admin-only cache and rehash
   immediately before launch.~~ ✅ closed 2026-04-25: staging now
   defaults to `%ProgramData%\DDS\software-cache` with a
   SYSTEM/Administrators-only DACL, and `InstallMsi` / `InstallExe`
   re-verify post-download `(size, mtime)` immediately before
   `Process.Start` (cross-platform tests in
   `DdsPolicyAgent.Tests/B6SoftwareStagingTests.cs`; Windows DACL
   helper requires Windows CI to exercise).

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
| **Failed enforcement can be marked complete (B-3)** ✅ closed 2026-04-25 — `AppliedStateStore.HasChanged` now requires a successful prior status (`"ok"` / `"skipped"`) to short-circuit; the Windows worker threads the real `EnforcementStatus` through `ApplyBundleResult` into `RecordApplied` / `ReportAsync` instead of hardcoding `"ok"` (matches macOS pattern). | High | (closed — see Claude_sec_review.md) |

---

## 8. Summary of Open Items

| # | Item | Priority | Section |
|---|------|----------|---------|
| 1 | ~~Sync persistence before trust-graph acceptance (B-1)~~ ✅ closed 2026-04-25 | High | §5 |
| 2 | ~~Live-attestation requirement for purpose grants (B-2)~~ ✅ closed 2026-04-25 | High | §5 |
| 3 | ~~Failed enforcement retry semantics (B-3)~~ ✅ closed 2026-04-25 | High | §7 |
| 4 | ~~Admission cert revocation list~~ ✅ closed 2026-04-26 (gossip-piggyback distribution on H-12 handshake landed same day — see §1 recommendation #2 and `dds-net::admission`) | High | §1 |
| 5 | ~~Active-version selection for policies/software (B-4)~~ ✅ closed 2026-04-25 | Medium | §5 |
| 6 | ~~Challenge-store cleanup and caps (B-5)~~ ✅ closed 2026-04-25 | Medium | §5 |
| 7 | ~~Windows software staging TOCTOU hardening (B-6)~~ ✅ closed 2026-04-25 (Windows-CI verification of DACL helper still pending) | Medium | §6 |
| 8 | ~~Windows data directory ACL (dir-level)~~ ✅ closed 2026-04-26 (`CA_RestrictDataDirAcl` MSI custom action + `dds-node restrict-data-dir-acl` subcommand; SDDL `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` applied before any service writes to the data dir) | Medium | §3 |
| 9 | ~~Key rotation mechanism~~ ✅ partially closed 2026-04-26 (`dds-node rotate-identity` rotates the libp2p keypair locally + prints the admin follow-up commands; admission cert renewal stays a manual admin ceremony by design) | Medium | §2 |
| 10 | WiX virtual service account split (M-18) | Medium | §3 |
| 11 | Admin-set coherence via gossip (I-11) | Medium | §5 |
| 12 | Message-level encryption (opt-in) | Low | §4 |
| 13 | ~~Real-time expiry in `evaluate_policy`~~ ✅ closed 2026-04-25 (already inline-filtered; regression tests added) | Low | §5 |

All Critical findings from the source-validated review are now Fixed
(pending verify). All six findings (B-1 through B-6) from the
2026-04-25 follow-up have landed in this branch as of 2026-04-25
follow-up #5; only the Windows-side DACL helper for B-6 still needs
Windows CI to exercise. The previously-open admission cert revocation
list (§1) closed on 2026-04-26 — local enforcement landed in the
morning pass and the gossip-based piggy-back distribution closed
the afternoon pass (`AdmissionResponse.revocations`, capped at
`MAX_REVOCATIONS_PER_RESPONSE = 1024`, per-entry domain-signature
verification on receive, atomic persistence after successful merge).
The Windows data-directory DACL (§8 item #8) closed in the
2026-04-26 install-time pass — `dds-node restrict-data-dir-acl`
subcommand wired into the MSI as `CA_RestrictDataDirAcl`, scheduled
before `CA_GenHmacSecret` so the per-install HMAC secret is created
underneath the already-restricted DACL rather than inheriting the
wide-open `%ProgramData%` parent. **No High items remain open.**
