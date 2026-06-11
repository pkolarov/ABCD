> **REMEDIATION STATUS (2026-06-11).** All findings below were acted on the same
> day — see STATUS.md "252nd pass". Both CRITICALs (C1 self-update anti-rollback,
> C2 epoch-key mandatory signature), all 9 HIGHs (#3,#4,#5,#6,#7,#8,#9,#12,#13),
> and the medium/low set were fixed with regression tests; **1166 workspace tests
> pass, clippy clean.** Deferred as documented defense-in-depth: #20, #24, #25, and
> unbounded `CausalDag` op growth. C++/C# fixes require Windows/macOS CI to compile.
> The "BLOCK" recommendation below reflects the state *at audit time*, before
> remediation.

# DDS Pre-Production Security Audit — Final Report

**Scope:** dds-core, dds-domain, dds-net, dds-node, dds-store, dds-ffi, and the Windows/macOS native platform integrations (Credential Provider, Auth Bridge, IPC, Policy Agents, CTAP2/FIDO2).
**Method:** Two-lens adversarial verification. `confirmed` = both lenses agreed the issue is real and reachable; `disputed` = lenses split on reachability/severity. Spot-checks of the two pivotal mechanisms (zero-signature epoch-key gate, self-update version-monotonicity, sync DAG insert, audit-chain key derivation) were re-run against source during this consolidation and matched the verdicts.

## Production Recommendation: **BLOCK**

Two CRITICAL issues are reachable by a **single admitted peer** (DDS's own threat model treats admission as proof of domain membership, not honesty) and defeat core security controls — patch integrity and revocation/burn delivery. They must be fixed and regression-tested before any production deployment. The HIGH cluster (privilege escalation via trust-chain, sync DAG poisoning, audit-chain corruption, pipe squatting, SYSTEM-context OOB write, sign-count bypass, plaintext credential leakage) should land in the same release.

---

## CRITICAL

### C1 — Self-update has no anti-rollback guard; one admitted peer forces a signed fleet-wide downgrade to a known-vulnerable build
`dds-domain/src/types.rs:1271-1283` · `dds-node/src/node.rs:2048-2104, 2114, 3180-3188` · `dds-node/src/self_update.rs:340-439`
*(merged: domain-types, scn-downgrade-replay, scn-compromised-peer)*

`evaluate()` never asserts `doc.version > installed_version` — confirmed by direct read; the only version use is the publisher-asserted `min_supported_from` floor (an old manifest sets it `None`) and `Pinned.allow_versions`. Self-update tokens have no `iat` replay window (revoke/burn do), and the K genuine publisher signatures stay valid forever. An admitted, **non-publisher** peer replays the K signed tokens of an older release; they pass capability, quorum-eligibility, SHA-256, and OS-vendor signature (genuine old artifact), evaluate to `ApplyNow`, and `apply_update` runs `msiexec /i` / `installer -pkg` as LocalSystem/root, reinstalling the vulnerable binary fleet-wide. The anti-entropy **sync** path fires the quorum check for any self-update payload (replay-window filter applies only to Revoke|Burn) and is the most robust trigger; the gossip variant additionally hits any fresh/restarted/lagging node whose JTI dedup never saw those tokens.
**Fix:** Hard gate `doc.version > installed_semver()` (locally observed) before `ApplyNow`; persist a durable monotonic highest-applied-version floor; add an `iat` replay window and bounded `exp` to self-update tokens. Regression-test downgrade refusal and stale-manifest replay.

### C2 — Epoch-key release accepts an all-zero Ed25519 signature and never binds publisher to sender; any admitted peer poisons any publisher's epoch key
`dds-node/src/node.rs:3633-3638` (reachable from `:1672`, `:3537`, `:3312`)
*(merged: net-pq-admission, node-ingest, scn-remote-unauth, scn-downgrade-replay)*

`install_epoch_key_release` verifies the Ed25519 publisher signature only when it is non-zero — confirmed by direct read; an all-zero 64-byte signature skips the *only* publisher-authentication, and `pq_signature` is never verified on this path. The KEM decap + AEAD unwrap is **not** a publisher authenticator: encap targets the recipient's *public* KEM key (in `AdmissionCert.pq_kem_pubkey`, served to any peer) and the binding is built from public PeerId strings. So an admitted peer wraps an attacker-chosen 32-byte key to the recipient, sets `publisher=victim, signature=[0;64]`, and it installs (persisted to `epoch_keys.cbor`). The victim then drops the real publisher's encrypted gossip as undecryptable — a targeted, restart-surviving eclipse that censors revocations, burns, and self-update **Halt** orders. In production `p2p_signing_key` is always `Some`, so the zero-sig branch is purely an attacker affordance.
**Fix:** Make the Ed25519 signature mandatory (delete the `any(|&b| b != 0)` guard; reject all-zero); gate any test shortcut behind `#[cfg(test)]`. Defense-in-depth: reject `release.publisher != sending peer`, verify ML-DSA `pq_signature` on hybrid domains, and cap `epoch_id`.

---

## HIGH

### H1 — Trust-chain walker ignores intermediate vouch purposes; low-privilege member mints high-privilege capability
`dds-core/src/trust.rs:265-353, 428-457, 466-496, 502-525` *(core-trust)*
`walk_chain` validates only connectivity to a root; `has_purpose` checks the leaf purpose then a purpose-agnostic chain. No narrowing anywhere, and the gossip ingest path applies no compensating check (vouches are unfiltered). A `group:devops` member can self-sign a Vouch granting `dds:policy-publisher-windows` / `dds:dds-self-update-publisher` to an attacker subject, and it is honored — domain-wide policy push + self-update quorum poisoning. **Fix:** thread the required purpose through `walk_chain` and enforce per-hop intersection (scope only narrows).

### H2 — Anti-entropy sync inserts attacker-chosen ops into the DAG even when the token is rejected (eclipse of revocations/burns/policy)
`dds-net/src/sync.rs:503` (and graphless `:338`) *(core-crdt; node-ingest quorum-coupling subset)*
`dag.insert(op.clone())` runs unconditionally outside the `if graph_accepted` block — confirmed by direct read, with a rationalizing comment that is itself the reasoning error (`op.id` IS the sync-dedup key). `op.id` is peer-controlled and unbound to the token. Because honest peers skip serving any op_id the requester already knows, poisoning `op-<jti>` permanently suppresses the genuine token J at the victim (per-process). **Fix:** move the insert inside `graph_accepted` and bind `op.id == op-<jti>` / `op.author == iss`.

### H3 — redb audit-log key derived from `table.len()` is corrupted by pruning; silently disables the L-12 tamper-evident chain
`dds-store/src/redb_backend.rs:462,466,488` *(store)*
`next_id = table.len()` — confirmed by direct read. After any prune, keys are non-contiguous: the typical case permanently fails every append ("missing last audit entry"); the overlap case silently overwrites a live entry. Errors are only warn!'d/swallowed. Under documented retention (`audit_log_max_entries`/`audit_log_retention_days`) the first periodic prune freezes the audit log with no attacker required; an attacker can drive the cap to trigger it, then operate unrecorded. **Fix:** allocate `next_id` and read the predecessor via `table.last()` (max key + 1), never `len()`; add a prune-then-append regression test.

### H4 — Named pipe lacks FIRST_PIPE_INSTANCE and the CP never verifies server identity; squatting captures plaintext logon passwords
`ipc_pipe_server.cpp:129` · `ipc_pipe_client.cpp:119` *(cpp-ipc)*
The bridge pipe name is squattable (no `FILE_FLAG_FIRST_PIPE_INSTANCE`, namespace not ACL'd) and the CP performs no `GetNamedPipeServerProcessId`/SID check and no `SECURITY_IDENTIFICATION`. A standard user pre-creating the pipe before the LocalSystem bridge receives the SYSTEM CP's plaintext password (enrollment) and can forge `AUTH_COMPLETE` for an arbitrary logon. **Fix:** add `FILE_FLAG_FIRST_PIPE_INSTANCE`; verify the server token SID is LocalSystem before sending secrets; open with `SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION`.

### H5 — OOB pointer write: up to 5 enrolled users enumerated into a 3-slot `_rgpCredentials` array in SYSTEM-context LogonUI
`CDdsProvider.cpp:616-617, 686-703, 768` *(cpp-credprovider)*
`_EnumerateOneCredential` writes `_rgpCredentials[idx++]` with no `idx < MAX_CREDENTIALS(3)` check while iterating up to 5 users. With ≥4 non-admin enrolled users (shared/kiosk), a member-OOB write corrupts `_dwNumCreds`, which then drives `GetCredentialAt`/destructor `Release()` over garbage pointers inside LogonUI (SYSTEM, secure desktop): reliable logon DoS, layout-dependent corruption. **Fix:** size the array ≥ `MAX_DDS_USERS`, guard every write index.

### H6 — Admission revocation not enforced against a live admitted peer; revoked peer keeps ingesting/serving until disconnect
`dds-node/src/node.rs:1471-1623` (no `admitted_peers.remove`/disconnect); gates at `:986/:3213/:3240` *(node-stores2)*
A revoked-but-connected peer is evicted from caches and triggers a rotation but is never removed from `admitted_peers` and never disconnected; no periodic reconciliation exists. It keeps publishing tokens and being served sync for the connection's life, defeating "once revoked, stays revoked." **Fix:** remove the PeerId from `admitted_peers` + `disconnect_peer_id` on revocation; add a defense-in-depth `is_revoked` check on the runtime ingest gates.

### H7 — Sign-count replay protection bypassable via credential-ID encoding mismatch (defeats cloned-authenticator detection)
`dds-node/src/service.rs:1878` (byte-normalized lookup) vs `:2053` (raw store key) *(node-service)*
The L-13 fix normalizes the credential lookup but `bump_sign_count` keys on the raw wire `credential_id`; a re-encoded (padded/unpadded) credential matches the enrolled record yet maps to a fresh 0-valued sign-count key. A cloned authenticator's lagging counter is reset, defeating clone detection and yielding a victim-bound session or admin vouch. **Fix:** canonicalize `credential_id` once and use it for both the lookup and the store key; regression-test padded-vs-unpadded replay.

### H8 — CP logs first/last char + exact length of every plaintext Windows password to world-readable C:\\Temp
`CDdsCredential.cpp:562-568` → `CDdsProvider.cpp:17-30` *(scn-secret-leak)*
The decrypted plaintext password's boundary chars and length are logged unconditionally to `C:\Temp\dds_cp.log` (Users:Read), authored by the SYSTEM CP on every logon. Collapses offline cracking space dramatically. **Fix:** delete the statement; never log credential-derived material; treat `pwdLen` as sensitive; harden the log path (see M5).

### H9 — macOS bootstrap account password passed on argv and logged, leaking to local users and off-host
`MacAccountEnforcer.cs:119` · `CommandRunner.cs:54,122-136` · `Worker.cs:405` *(scn-secret-leak)*
`dscl . -passwd … <password>` exposes the live login password in world-readable argv on every account creation; on failure the plaintext is logged and shipped to the node as `AppliedReport.Error` (persisted in node audit storage). **Fix:** pass the password via stdin; redact `-passwd`/`-newPassword` args in logs and failure messages; never put raw args in `AppliedReport.Error`.

---

## MEDIUM

- **M1 — SLSA provenance never fetched/verified; `verify_provenance` config is a no-op** — `self_update.rs:340-439`, `types.rs:1316-1320`. *(node-selfupdate-config)* Documented SLSA-L3 gate is vestigial; defense-in-depth + doc-accuracy gap behind the K-of-M + signature gates. **Fix:** implement fail-closed provenance verification gated on a real config flag, or remove the misleading docs.
- **M2 — Self-update verify→install TOCTOU; staging dir unhardened despite explicit code contract** *(disputed)* — `self_update.rs:383,98,417,425`. On non-MSI/widened-ACL deployments (and macOS/Linux without O_NOFOLLOW) a local user swaps the artifact post-verification → SYSTEM/root RCE. Inert on the standard MSI install (inherited DACL). **Fix:** explicit owner-only DACL/mode + re-hash under a held handle before launch.
- **M3 — Auth worker holds a raw recycled client-slot pointer across a 60s wait** *(disputed)* — `DdsAuthBridgeMain.cpp:1164,1336,1648`. On Terminal-Server/multi-session hosts, slot recycling delivers user-A's decrypted password to user-B's logon session. **Fix:** verify `(slotIndex, expectedClientId)` under lock before `SendResponse`.
- **M4 — CP trusts attacker-controllable IPC entry count → OOB read in winlogon** — `ipc_pipe_client.cpp:746-747`, `DdsBridgeClient.cpp:290-298`. *(cpp-credprovider, scn-panics-overflows)* SYSTEM-context OOB read + pre-logon DoS from a compromised/squatted pipe server. **Fix:** bound `count` against received bytes before the loop.
- **M5 — CP diagnostic log written to world-readable C:\\Temp with no DACL** — `CDdsProvider.cpp:17-30`. *(scn-secret-leak, cpp-ipc)* Enumerates enrolled identities, credential IDs, salt prefixes, session-token length; A-4 hardening missed this second logger. **Fix:** write under `%ProgramData%\DDS` with the FileLog SDDL.
- **M6 — DDS_AUTH_RESPONSE inner length fields trusted unchecked → OOB read exfiltrated via HTTP POST** *(disputed)* — `ipc_messages.h:276-288`, `DdsAuthBridgeMain.cpp:1384-1386,1460-1462`. Over-read of bridge memory (possibly hmac-secret) base64-encoded into the assertion POST; gated behind a SYSTEM-context CP compromise/squat. **Fix:** clamp the three lengths before use.
- **M7 — Named-pipe caller identity via OpenProcess PID-reuse TOCTOU** *(disputed)* — `http.rs:2536,2542,128-143`. On the named-pipe API transport with allowlisted SIDs, a PID-reuse race reaches the admin sub-router. **Fix:** `ImpersonateNamedPipeClient` + `OpenThreadToken`.
- **M8 — C-3 ingest gate misses DdsSelfUpdateDocument identity and LinuxPolicyDocument capability** — `node.rs:4174-4198, 4222-4247`. *(domain-types, node-selfupdate-config, scn-compromised-peer)* An admitted peer seeds unauthorized Linux policy / malformed self-update publisher metadata into every peer's trust graph. **Fix:** add the Linux arm + a self-update identity gate; make the match exhaustive/fail-closed.
- **M9 — Admin vouch requests UV=DISCOURAGED; node never enforces user_verified for admin flows** *(disputed)* — `WebAuthnHelper.cpp:390,169`, `service.rs:1931`. Privileged step-up authorized by touch alone. **Fix:** UV=REQUIRED for admin vouch/setup and node-side `user_verified` enforcement.
- **M10 — Non-loopback `api_addr` grants unauthenticated remote admin under default trust flag; Windows single-file provision emits the open TCP layout** — `http.rs:2255-2260,122`, `config.rs:394`, `provision.rs:1020-1022`. *(node-http, scn-remote-unauth, scn-local-cotenant)* **Fix:** refuse to start (or refuse trust=true) on a non-loopback bind; harden the Windows provision branch to `pipe:dds-api` + trust=false.
- **M11 — Domain root key on weakest Argon2id tier (19 MiB/t=2/p=1), distributed in provision bundles** — `domain_store.rs:748`, `provision.rs:573-586`. *(node-provision-keys)* The fleet root key is on a weaker KDF than per-node keys (M-10) and travels on USB. **Fix:** v6/v7 params-in-blob at 64 MiB/t=3/p=4 with lazy rewrap.
- **M12 — M-14 plaintext-downgrade guard covers only node_key.bin** *(disputed)* — `identity_store.rs` vs `p2p_identity.rs`/`domain_store.rs`. **Fix:** lift the sticky-marker logic into all three save paths; correct the doc claim.
- **M13 — seal-passphrase writes the DPAPI machine-scope blob with no DACL** *(disputed)* — `main.rs:1929`, `win_dpapi.rs`. LOCAL_MACHINE + NULL entropy is any-local-user-decryptable; the ACL is the sole barrier and is omitted (inert on MSI installs). **Fix:** `restrict_to_owner` + machine-static secondary entropy; correct the misleading comment.
- **M14 — Apple Secure Enclave provider never verifies SE residency** *(disputed)* — `apple_secure_enclave.rs:96-111`. A planted/misconfigured software key is trusted and falsely reported hardware-bound. **Fix:** require `kSecAttrTokenID == SecureEnclave` (fail closed); fix the docs/keychain mismatch.
- **M15 — walk_chain has no cycle guard; exponential fan-out CPU-DoS on the hot auth path and self-update ingest** — `trust.rs:265-353,466-496`. *(core-trust)* **Fix:** per-traversal visited set + root-reachability memoization.
- **M16 — Unbounded CausalDag growth and unbounded pending_self_updates accumulator from admitted peers (OOM)** — `causal_dag.rs:36-77`, `node.rs:339,2135`. *(core-crdt, scn-compromised-peer)* **Fix:** cap DAG op count/data length and the accumulator (LRU + TTL); bind ops to accepted tokens.

---

## LOW

- **L1 — Sync path re-caches/re-serves trust-graph-rejected tokens** *(disputed)* — `node.rs:3169-3177`, `sync.rs:441-510`. Availability/cache-hygiene only; admitted-peer-gated. **Fix:** re-cache only graph-accepted op_ids. *(net-sync)*
- **L2 — Revoke/burn via sync does not trigger epoch-key rotation (forward-secrecy gap)** *(disputed)* — `node.rs` gossip vs `handle_sync_response`. Bounded, self-heals at periodic rotation; one lens called it cosmetic (fan-out exclusion is a separate mechanism). **Fix:** schedule the rotation on sync-applied revoke/burn after verifying fan-out exclusion. *(net-sync)*
- **L3 — strict_device_binding inert when trust_loopback_tcp_admin left at default true** *(disputed)* — `http.rs:212-214,283-285`. Self-defeating misconfig the docs warn against; subsumed by M10. **Fix:** check Anonymous+strict before the admin early-return, or fail/warn on the true+true combo. *(node-http)*
- **L4 — EpochKeyRelease ML-DSA pq_signature never produced/verified (hybrid downgrade)** — `node.rs:3958,3633-3638`. Authenticity degrades to Ed25519-only on hybrid domains; only matters under a future CRQC and contingent on C2. **Fix:** sign/verify the ML-DSA leg on hybrid domains. *(net-pq-admission, node-ingest)*
- **L5 — Hybrid KEM never validates the X25519 recipient point; non-contributory ECDH silently zeroes the classical leg** — `kem.rs:108-131,250,312`. Self-limited PQ-hedge loss; `pq_kem_pubkey` is not signature-covered. **Fix:** reject low-order points / check `was_contributory()`. *(core-crypto)*
- **L6 — is_in_canary_cohort treats canary_pct ≥ 100 as 100% (fail-open soak bypass)** *(disputed)* — `types.rs:1248-1262`. Admin-error fail-open behind K-of-M multisig. **Fix:** reject canary_pct > 100 at ingest. *(domain-types)*
- **L7 — Hand-rolled DER length parser unbounded; latent panic if ever fed un-pre-validated cert bytes** *(disputed)* — `fido2.rs:730-747,723-724`. Shadowed today by x509-parser; defense-in-depth. **Fix:** make `der_seq_body_offset` self-bounding. *(domain-fido2, scn-malicious-authenticator)*
- **L8 — epoch_keys.cbor (KEM secret) saved without the Windows per-file DACL** — `epoch_key_store.rs:382-447`. Inert on MSI installs; bites on non-MSI/widened-ACL Windows. One read = all peers' epoch keys. **Fix:** `restrict_to_owner` on tmp + persisted path. *(scn-local-cotenant)*
- **L9 — TwoPSet::force_add is not a CRDT operation (non-convergent re-add)** *(disputed)* — `twop_set.rs:53`. Dead code today (no production caller); latent membership footgun. **Fix:** OR-Set / versioned tags before wiring to group membership. *(core-crdt)*
- **L10 — IPC receive stack buffer holding plaintext password/token not zeroized** — `DdsBridgeClient.cpp:469`. Residual plaintext in winlogon stack (defense-in-depth; requires a memory-dump capability). **Fix:** `SecureZeroMemory(buf)` on every exit path. *(scn-secret-leak)*
- **L11 — macOS keychain-seal passes the node passphrase on `security` argv** *(disputed)* — `dds-keychain-seal.sh:65`. Argv-hygiene smell; on macOS the `security` process runs as root and cross-uid argv is not readable by unprivileged users, so the stated unprivileged-read is largely not reachable. **Fix:** pipe via stdin. *(scn-secret-leak)*
- **L12 — macOS launchd Load/Kickstart label path-traversal bypasses IsManagedPath (present on Configure, missing on Load)** *(disputed)* — `LaunchdEnforcer.cs:152,305-307`. Reachable only with a signed policy + a pre-planted plist at the traversed path; root bootstrap of an unmanaged plist. **Fix:** validate the label and re-apply IsManagedPath in ResolvePlistPath. *(csharp-macos-agent)*
- **L13 — macOS file:// / bare-path package source TOCTOU (verify on original path, re-read by installer)** — `SoftwareInstaller.cs:261`. Local file swap between SHA/signature check and root `installer` run on world-writable sources → LPE; matches the fixed Windows B-6. **Fix:** copy non-https sources into the root-owned cache and verify+install from the copy. *(csharp-macos-agent)*
- **L14 — GossipEnvelopeV3 / SyncEnvelopeV3 decode bypasses the I-6 CBOR depth cap** *(disputed)* — `node.rs:1762,2971`. Uses ciborium's 256-frame default (graceful error, not a panic) instead of the 16-level cap; consistency regression, no reachable DoS on the 2 MiB worker stack. **Fix:** route both through `cbor_bounded::from_reader`. *(scn-panics-overflows)*
- **L15 — FFI `read_cstr` launders a caller-owned C string into `&'static`** *(disputed)* — `dds-ffi/src/ffi_core.rs:42`. Latent UAF footgun; all current callers consume synchronously. **Fix:** return owned `String` or tie the lifetime to the pointer. *(ffi)*
- **L16 — macOS self-update Team-ID parser looser than the hardened C# reference** *(disputed)* — `self_update.rs:260`. Consistency/robustness; exact `team_id` equality still gates. **Fix:** port the strict anchored regex. *(node-selfupdate-config)*
- **L17 — IsValidUsername accepts '.'/'..' as macOS short names (degenerate dscl paths)** *(disputed)* — `MacAccountEnforcer.cs:533`. Signed-policy-only; account-state corruption, not traversal. **Fix:** reject pure-dot names; require a leading letter/underscore. *(csharp-macos-agent)*
- **L18 — Root-thumbprint pin read from an X509Chain built with VerificationFlags=AllFlags** *(disputed)* — `WinTrustAuthenticodeVerifier.cs:74`. Optional defense-in-depth pin weakened; WinVerifyTrust + subject equality remain primary. **Fix:** derive the root from the WinVerifyTrust-validated path / require a self-signed root. *(csharp-windows-agent)*
- **L19 — CP diagnostic logs to predictable C:\\Temp from SYSTEM (symlink redirection / noisy SYSTEM writes)** — `ipc_pipe_client.cpp:90`. Benign-content redirection + logon-timing leak; production debug logging in the hot path. **Fix:** remove or gate; write under a SYSTEM-only DACL'd dir. *(cpp-ipc)* (Same C:\\Temp class as M5/H8.)
- **L20 — TwoP/CTAP2 ParseAuthData never skips attestedCredentialData when AT is set** *(disputed)* — `ctap2_protocol.cpp:233`. Parse-confusion; vault rejects len≠32; the ctap2 module is currently unwired. **Fix:** skip attestedCredentialData when `flagAT()`. *(cpp-ctap2)*

---

## DISPUTED / NEEDS-TRIAGE

The following are accurately described at the code level but the lenses split on whether the security impact is reachable today. Triage owners should decide fix-vs-document:

- **Reachability gated by a non-default/operator action** (treat as fix-then-ship hardening): M2 (TOCTOU on non-MSI), M10/L3 (non-loopback bind / coupled trust flag), M12/M13/L8 (Windows DACL/marker gaps inert on MSI installs), L13 (file:// source).
- **Reachability requires an already-SYSTEM or root attacker** (one lens called these no-privilege-gain): M3, M6 (SYSTEM-to-SYSTEM IPC over-reads), M14/L11 (root-context macOS keychain).
- **Effect contingent on another finding** (fix the parent first): L4 and the epoch-key replay-window gap depend on C2; the self-update quorum-coupling (`ops_merged>0`) info-item depends on H2.
- **Real defect, currently unreachable dead code or shadowed parser:** L7 (DER, shadowed by x509-parser), L9/L20 (TwoPSet, ctap2 module — no production callers), L14/L15 (CBOR depth, FFI lifetime — no current trigger).
- **Doc-vs-impact split:** M9 (admin-vouch UV — one lens narrowed the tray path to non-admin purpose), L6 (canary_pct behind multisig), L2 (sync-rotation possibly cosmetic).

Items verified by the lenses as `false_positive` or pure `info` (no material/reachable security impact) — e.g. the issuer-key URN scheme domain-separation gap (`identity.rs:117`), the FFI `catch_unwind`/out-pointer API-contract notes, the CBOR allocation-amplification and trailing-bytes strictness nits in the unwired ctap2 module, the COSE kty/crv validation gap (shadowed by CNG), the UP-flag-at-enrollment spec deviation, and the provision-bundle `domain_name` signature-coverage gap — are recorded but **not** ranked above; they are documentation/robustness hardening with no exploitable path under DDS's trust model.

---

## What Was Verified Clean (or Adequately Mitigated)

- **Issuer-key URN binding (`identity.rs:117`):** scheme not in the URN hash, but distinct key lengths + signature-layer scheme binding (`SchemeMismatch`) make cross-scheme confusion structurally impossible. Info-only.
- **FIDO2 assertion replay:** independently blocked by the single-use server challenge bound into clientDataHash; the captured-blob replay sub-claim in H7 does not hold (the genuine regression is clone-detection).
- **DER over-read on the attestation path (L7):** every cert is fully validated by x509-parser (`rest.is_empty()`) before the hand-rolled parser runs; the operator-gated per-AAGUID path adds further confinement.
- **Self-update apply primary gates:** K-of-M publisher quorum (each token crypto-verified), SHA-256 pin, HTTPS-only, and OS-vendor code signature are all present and enforced — the criticals are about *rollback/replay* and *channel poisoning*, not a broken primary signature gate.
- **CNG curve validation:** the COSE parser's missing kty/crv check is backstopped by `BCryptImportKeyPair(P256)` rejecting off-curve points.
- **FFI entry points:** no panic is reachable from untrusted input today (all transitive calls are `Result`-based), and current callers consume `read_cstr` borrows synchronously — the flagged items are latent regression surface, not live bugs.
- **Bridge↔node HTTP channel:** the H-6 body MAC and (where configured) replay windows on revoke/burn and PQ releases are present; the gaps found are in adjacent paths (self-update tokens, the CP↔Bridge pipe), not this channel.