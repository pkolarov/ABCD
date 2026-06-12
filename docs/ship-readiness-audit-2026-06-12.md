> **REMEDIATION STATUS (2026-06-12, same day).** The four punch-list items were
> fixed in the 253rd pass — see STATUS.md. R1 (bounds guard before the
> SetSerialization append), R2 (server-side UV gate in `admin_vouch`), R4 (all
> password-length logging removed — **four** sites, not three: the implementation
> pass found `CredentialVault.cpp`'s `cbResult` success log is also an exact
> plaintext-length leak, and this report's original "harmless" note on the
> ciphertext-length log was wrong — GCM stores the tag separately, so ciphertext
> length *is* password length), R5 (sync quorum gated per-op on novel DAG merge,
> plus an alias-proof duplicate-op-id check covering a bypass in this report's
> originally prescribed fix). Each fix was adversarially reviewed; 1171 workspace
> tests pass (5 new regression tests), clippy clean. R3, R6–R8 and the T-items
> remain open as documented fast-follow hardening.

# DDS Ship-Readiness Security Audit — 2026-06-12

**Scope:** Independent verification of the 2026-06-11 pre-production audit remediation
(commit `60631ae`, 252nd pass) against source at HEAD, plus a fresh-eyes adversarial pass
over the remediation diff itself, deferred-item reconciliation, and a dependency audit.

**Method:** Six parallel verification lenses (C1, C2+revocation, Rust HIGHs, native C++/C#,
fresh-eyes diff review, mediums+deferred). Every negative claim ("X is absent / not
enforced") was re-confirmed by direct grep/read of HEAD before inclusion here.

**Build health:** `cargo test --workspace`: **1166 passed, 0 failed.**
`cargo audit`: **0 vulnerabilities**, 7 informational warnings (unmaintained/yanked
transitive crates, incl. yanked `aes 0.9.0` via `ctap-hid-fido2` — upstream-blocked).

## Verdict: **SHIP after fixing R1 (trivial); R2–R4 strongly recommended in the same release.**

The 2026-06-11 BLOCK verdict is lifted: both CRITICALs and the HIGH cluster are genuinely
fixed, correctly placed (inside shared funnels covering both ingest paths), and
regression-tested. The findings below are new (or residual halves of claimed fixes); none
reaches the single-admitted-peer-defeats-core-control bar of C1/C2, but R1 is the same
defect class as the fixed H5.

---

## Remediation verification results

| Audit item | Verdict |
|---|---|
| C1 self-update anti-rollback | **VERIFIED** — gate is the first statement in `evaluate` (types.rs:1301), semver-correct (`SemVer` derives `Ord` on u32 tuple), no rollout arm bypasses it; real installed version passed from compile-time `DDS_VERSION` (node.rs:2074, build.rs:30); `iat` window enforced in the shared quorum accumulator covering gossip AND sync (node.rs:2157) |
| C2 mandatory epoch-key signature | **VERIFIED** — unconditional verify inside `install_epoch_key_release` (node.rs:3717), zero-sig branch gone (grep-confirmed), verifying key cryptographically bound to publisher PeerId identity multihash (node.rs:4073-4086, non-Ed25519 PeerIds fail closed), all callers funnel through it; 9/9 ingest regression tests pass |
| H1 trust-chain attenuation | **VERIFIED** — recursive per-hop attenuation (trust.rs:517-524), privileged-cap list complete (all 7 constants + `dds:admin-vouch:*`), no raw `walk_chain` bypass in production, #30 cycle guard present |
| H2 sync DAG poisoning | **VERIFIED** (production path) — insert gated on `graph_accepted` (sync.rs:514); see R3 for the residual op↔token binding gap |
| H3 audit-chain key | **VERIFIED** — `table.last()+1` (redb_backend.rs:473-487); claimed prune-then-append regression test is **missing** (see T2) |
| H4 pipe squatting | **PARTIAL** — `FIRST_PIPE_INSTANCE` ✓ (ipc_pipe_server.cpp:136-140), SDDL now SYSTEM-only ✓ (:179), client LocalSystem-SID check before any secret on the single connect path ✓ (ipc_pipe_client.cpp:265-270); `SECURITY_SQOS_PRESENT\|SECURITY_IDENTIFICATION` **not implemented** (see R5) |
| H5 LogonUI OOB write | **PARTIAL** — main enumeration path bounded ✓ (CDdsProvider.cpp:659-662, :765-766); second write site missed (see R1) |
| H6/#8 live revocation teardown | **VERIFIED** — `admitted_peers.remove` + `disconnect_peer_id` (node.rs:1556-1569) on the sole admission-revocation ingest path; no runtime `is_revoked` re-check (bounded-staleness residual, by design) |
| H7 sign-count canonical key | **VERIFIED** — lookup and bump share one decode chain (service.rs:3374, :3398); single bump site; enrollment writes no conflicting key |
| H8 password logging | **PARTIAL** — flagged statement removed ✓, log moved to `%ProgramData%\DDS\logs` with SY/BA DACL ✓ (CDdsProvider.cpp:33-75); sibling pwdLen log missed (see R4) |
| H9 macOS password on argv | **VERIFIED** — `sysadminctl -resetPasswordFor <u> -newPassword -` via stdin, `sensitive:true` redaction in logs and failure messages (MacAccountEnforcer.cs:124-128, CommandRunner.cs:59-67, :142-154); functional confirmation needs macOS CI |
| M3, M4, M6 (bridge/CP hardening) | **VERIFIED** — slot clientId revalidated under lock before password delivery (ipc_pipe_server.cpp:503-516); user-list count clamped, no underflow/overflow (ipc_pipe_client.cpp:886-893); all four AUTH_RESPONSE inner lengths clamped (DdsAuthBridgeMain.cpp:1394-1406) |
| M9 admin-vouch UV | **PARTIAL** — client REQUIRED ✓ (WebAuthnHelper.cpp:399-403); server never enforces `user_verified` (see R2) |
| #23 non-loopback bind refusal | **VERIFIED** — fail-closed incl. hostname/multi-addr/resolve-failure (http.rs:2263-2278); Windows single-file provision still emits anonymous-loopback-TCP layout (documented, provision.rs:1020) |
| #11 staging TOCTOU | **PARTIAL** — owner-only ACL on staged file ✓ (best-effort), Unix 0700 dir; **no re-hash under a held handle** before `msiexec` (see T1) |
| #16 C-3 ingest gate | **PARTIAL** — LINUX_POLICY + self-update arms present on both paths ✓; match is not fail-closed for future doc types (`_ => true`, node.rs:4314) (see T3) |
| #26 Argon2id, #27 markers, #28/#35 DACLs, #29 SE residency, #32 KEM contributory, #33 canary, #34 DER, #10 provenance docs | **VERIFIED** (one intentional V2-params write remains on the FIDO2 hmac-secret path — keyed on high-entropy input, acceptable) |
| Deferred #20/#24/#25, unbounded CausalDag | **VERIFIED** — code state matches documented deferral on all four |

---

## New findings (this audit)

### R1 — HIGH — OOB pointer write in `_EnumerateSetSerialization` (the H5 fix missed the second write site)
`platform/windows/native/DdsCredentialProvider/CDdsProvider.cpp:846`

```cpp
_rgpCredentials[_dwNumCreds] = pCred;   // no _dwNumCreds < MAX_CREDENTIALS guard
```

`GetCredentialCount` runs `_EnumerateCredentials()` (fills up to `MAX_CREDENTIALS == 3`)
and then, with a pending SetSerialization blob (remote-credential / unlock scenarios),
`_EnumerateSetSerialization()` in the same call (:573-582). With 3 DDS tiles enumerated the
write lands at `_rgpCredentials[3]` — one-slot OOB pointer write in SYSTEM-context LogonUI —
and the now-4 `_dwNumCreds` drives the destructor's `Release()` over a wild pointer.
**Fix:** the same `if (_dwNumCreds >= MAX_CREDENTIALS) return;` guard used at :659.

### R2 — MEDIUM — Admin-vouch UV enforced only in the client binary
`dds-node/src/service.rs:1930-1936` (UP gated), `:2532+` (`admin_vouch`)

`verify_assertion_common` enforces only `user_present`; `user_verified` is parsed,
propagated (:2077, :2106) but never required. The tray requests UV=REQUIRED, but a
tampered client (or anything reaching the endpoint with a valid credential) can submit a
UP-only assertion and mint an admin vouch — the "stolen-but-presence-unlocked admin key
cannot vouch" guarantee lives client-side only. **Fix:** reject admin-vouch (and other
privileged step-up) assertions with `user_verified == false` server-side.

### R3 — MEDIUM — No op↔token binding at ingest (both paths); op-id squatting remains possible
`dds-net/src/sync.rs:407-536` · `dds-node/src/node.rs:1932-2050`

`op.id`/`op.author` are deserialized verbatim from peer bytes and never checked against the
backing token's `jti`/`iss` (the `op-<jti>` shape exists only in the outbound
`synthetic_op_for_token`, node.rs:4195). Any admitted peer with one graph-acceptable token
(e.g. its own fresh attestation) can insert an op with an arbitrary id; a colliding id makes
the genuine op a DAG duplicate, suppressing its audit-chain entry, propagation cache, and —
on the gossip path — the self-update quorum trigger (could delay a fleet security-patch
rollout). Exploitability today is gated by UUID-based JTI unpredictability (relay-positioned
attackers can read JTIs in flight). The #4 fix comment claims this squat is prevented; it is
not. **Fix:** enforce `op.id == "op-{jti}"` and `op.author == iss` at ingest on both paths.

### R4 — MEDIUM — Exact plaintext-password length still logged on every logon (H8 sibling)
`platform/windows/native/DdsCredentialProvider/DdsBridgeClient.cpp:447-452`

```cpp
CPLog("... (pwdLen=%zu tokenLen=%zu) ...", seqId, wcsnlen(complete->password, ...), ...);
```

The #12 fix removed the CDdsCredential.cpp statement but missed this one. The log now lives
under a SY/BA DACL (so exposure is admin-only — materially better than the original H8),
but it still violates "never log credential-derived material". Lesser siblings:
`DdsAuthBridgeMain.cpp:1662` (`pwdLen` to bridge FileLog), `CredentialVault.cpp:305`
(ciphertext length — **correction at fix time:** NOT harmless; AES-GCM stores the
16-byte tag separately in `entry.authTag`, so `encryptedPassword.size()` equals the
exact plaintext password byte length, and the `cbResult` success log at :378 leaks
the same value). **Fix:** drop the password-length field from all four log statements.

### R5 — MEDIUM — Sync-path self-update quorum re-fires on duplicate tokens → equal-version reinstall loop
`dds-node/src/node.rs:3229-3239` (batch-level `ops_merged > 0`), `:2198` (entry removed at quorum), `dds-domain/src/types.rs` (equal version passes the C1 gate by design)

The sync quorum loop iterates every self-update payload whenever *any* op in the batch
merged — including `DuplicateJti`-rejected tokens already counted once. Since the
accumulator entry is removed after firing and an equal-version manifest passes the
anti-rollback gate (re-install/repair allowance), an admitted peer can replay the K
genuinely-signed tokens of the *current* release alongside one novel benign op and
re-trigger `msiexec` repeatedly for up to 7 days (the iat window) after each release —
a fleet service-restart-loop DoS. The gossip path is immune (counts only novel DAG
inserts). **Fix:** count sync-path tokens toward quorum only when their own op merged,
and/or persist fired content-hashes.

Also missing (defense-in-depth for the same mechanism): a **durable highest-applied-version
floor** — the only floor is the running binary's compile-time `DDS_VERSION`, leaving the
post-install/pre-restart window and relying on `VERSION` always parsing (a malformed
`VERSION` at build time silently disables the C1 gate; guarded only by a unit test).

### R6 — LOW — Gossip-ingested burn never schedules epoch-key rotation (inverse of #21)
`dds-node/src/node.rs:2454-2525` (`ingest_burn` — no `pending_revocation_rotation`)

Sync-applied burns rotate (node.rs:3240+); gossip *revokes* rotate (:2440); gossip *burns*
do not — a burned member keeps decrypting gossip until the next periodic rotation. The
dual-path asymmetry class again, this time gossip lagging. **Fix:** mirror the #21 block.

### R7 — LOW — `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` absent on pipe client opens
`ipc_pipe_client.cpp:236-244` · `DdsNodeHttpClient.cpp:1028-1035`

Claimed in the H4 fix, not implemented (grep over `platform/windows`: zero hits). A
squatting server the client connects to may impersonate the client at Impersonation level
during the window before the LocalSystem SID check fails the connection. Mitigated — no
payload is sent pre-check — but the one-flag fix should land as claimed.

### R8 — LOW — `iat == 0` bypasses the self-update replay window
`dds-node/src/node.rs:4133-4136` (inherited by `self_update_within_replay_window`)

The legacy-unstamped-token carve-out makes sense for revocations, not for self-update
tokens (no legacy population). Requires a publisher-signed `iat=0` token to matter.
**Fix:** reject `iat == 0` at the self-update accumulator.

### Additional notes (INFO)
- **Epoch-id self-wedge:** a compromised publisher signing `epoch_id = u64::MAX`
  permanently wedges its own slot (epoch_key_store.rs:265 staleness compare). Cap it.
- **`#[doc(hidden)]` test hooks** (`epoch_keys_mut_for_tests`, node.rs:3845) ship in
  release builds; not network-reachable; consider a `test-hooks` feature gate.
- **Argon2id params + downgrade markers are unauthenticated** (outside the AEAD / plain
  sidecar files): tamper yields DoS not key-strength loss; matches existing store model.
- **DPAPI seal blob** written before its DACL is applied (main.rs:1929→1935); use the
  epoch_key_store tempfile-restrict-rename idiom.
- **Leftover-code check clean:** the unrequested rate-limiter / exp-horizon mechanisms
  noted in STATUS.md were fully removed.

## Test-coverage gaps (claimed but absent)

- **T1:** #11 — no re-hash under a held handle before installer launch (path-based
  TOCTOU residual on non-MSI Windows / widened-ACL deployments; ACLs are warn-and-continue).
- **T2:** H3 — no prune-then-append audit-log regression test (the exact original corruption
  is uncovered by CI; existing prune tests never append afterward).
- **T3:** #16 — `publisher_capability_ok` defaults `_ => true`; the next publisher-style doc
  type silently repeats the #16 omission. Consider default-deny for unknown Attest body types.
- **T4:** C1 — no rollback regression test through the `Pinned` arm (structurally covered,
  untested).

## Recommended pre-ship punch list

1. ~~**R1** — one-line bounds guard in `_EnumerateSetSerialization` (HIGH, SYSTEM LogonUI).~~ **FIXED (253rd pass).**
2. ~~**R2** — server-side `user_verified` gate on admin vouch.~~ **FIXED (253rd pass)** + UV requirement documented in the Admin Guide.
3. ~~**R4** — delete the two `pwdLen` log fields.~~ **FIXED (253rd pass)** — four sites, incl. the two `CredentialVault.cpp` length-equivalent logs.
4. ~~**R5** — per-token (not batch) sync quorum counting.~~ **FIXED (253rd pass)** + alias-proof duplicate-op-id guard; 5 regression tests.
5. R3, R6, R7, R8 and the T-items as fast-follow hardening in the next pass — **still open**, documented residual risk consistent with the existing deferred set.
