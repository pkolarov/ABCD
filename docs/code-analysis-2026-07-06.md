# DDS Code Analysis — 2026-07-06

**Scope:** Fresh-eyes correctness/security pass over the tree at HEAD (`6838836`,
VERSION 1.4.1), with particular attention to the two commits landed since the
last audit (`a340615`, `6838836`) and to gossip↔sync ingest-gate parity.

**Method:** Four parallel review lenses — (1) the post-audit diff
(`a340615~1..HEAD`), (2) gossip vs anti-entropy sync gate parity, (3) the
`dds-node` local service surface, (4) Windows/macOS platform-native code. Every
finding below was re-confirmed by direct read of HEAD before inclusion; the two
highest-impact items (M-1, M-2) were additionally re-verified by hand.

**Build health:** `cargo clippy --all-targets` — **clean, 0 warnings**.

**Bottom line:** No new Critical/High in the Rust core. The prior 255 passes
hold — auth/authz/replay gates are enforced on both ingest paths, atomic writes
and zeroization are sound, and the Windows named-pipe SDDL hardening is intact.
Six residual issues found: one Medium in the macOS enrollment script that
escalates to High on a multi-user host, one Medium sync-path confidentiality
gap, and four Low/Informational items.

---

## M-1 — `dds-enroll-admin.sh` trusts a world-writable `/tmp` path → trusted-root injection / root RCE

**Severity:** Medium (High on a multi-user macOS host)
**File:** `platform/macos/packaging/dds-enroll-admin.sh:70,75,108`

The script runs as root (`sudo`) and round-trips the enrolled admin URN through a
fixed, predictable path in the sticky `/tmp`:

```sh
"${FIDO2_TEST}" 2>&1 | tee /tmp/dds-enroll-admin.log                                   # :70 (root writer)
ADMIN_URN="$(grep -o 'URN: urn:vouchsafe:[^ ]*' /tmp/dds-enroll-admin.log | ... )"     # :75
...
urn = '${ADMIN_URN}'                                                                    # :108 (into python3 -c)
```

`tee` opens the file with `O_CREAT|O_TRUNC` and **no `O_NOFOLLOW`**, and does not
use `mktemp`. On a multi-user machine an unprivileged local attacker can:

1. Pre-create `/tmp/dds-enroll-admin.log` owned by the attacker. `tee`'s truncate
   does not change ownership, so the attacker still owns the file root just wrote.
2. Between the `tee` (`:70`) and the `grep` (`:75`), rewrite the file to inject a
   chosen `URN: urn:vouchsafe:<...>` line.

That attacker-chosen value then flows to two sinks:

- **Trust escalation** — it is appended to `trusted_roots` in `dds.toml` (`:88–119`)
  and gossiped to every node in the domain, letting the attacker vouch for
  arbitrary identities (including Windows CP logon tiles).
- **Root code execution** — the `grep` capture class `[^ ]*` permits a single
  quote, so a URN such as `x'; import os; os.system("id>/tmp/pwn") #` breaks out
  of the single-quoted Python literal at `:108` and runs as root.

A symlink pre-plant (`/tmp/dds-enroll-admin.log` → a root-owned file) additionally
turns root's `tee` into an arbitrary-file overwrite primitive.

**Note:** an earlier lens read `${ADMIN_URN}` as operator-only self-injection; that
is incorrect — the value originates from a world-writable `/tmp` file, so it is
attacker-controllable whenever a second local account exists.

**Fix:** write to a private root-owned temp under `${DDS_ROOT}` (`mktemp` with
`0700`, or a fixed `${DDS_ROOT}/enroll.log`); pass `ADMIN_URN` to Python via
`os.environ`/`sys.argv` instead of string interpolation; and validate the URN
against `^urn:vouchsafe:[A-Za-z0-9._-]+$` before use.

---

## M-2 — enc-v3 plaintext downgrade guard is missing on the sync-ingest path

**Severity:** Medium (confidentiality-envelope bypass; content-layer auth gates
still apply)
**File:** `dds-node/src/node.rs:3075–3077` (vs gossip guard at `node.rs:1818–1827`)

The gossip ingest path hard-drops plaintext gossip on a domain that has the
enc-v3 capability:

```rust
// gossip — node.rs:1818
if self.domain.has_capability(dds_domain::domain::CAPABILITY_ENC_V3) {
    warn!("received plaintext gossip on enc-v3 domain — dropping");
    crate::telemetry::record_gossip_messages_dropped("enc_v3_plaintext_rejected");
    return;
}
```

`handle_sync_response` has no equivalent check — when a peer returns a response
with an empty `enc_payloads`, the plaintext `payloads` are accepted
unconditionally:

```rust
// sync — node.rs:3075
} else {
    resp.payloads          // no CAPABILITY_ENC_V3 gate
};
```

`CAPABILITY_ENC_V3` is referenced in `node.rs` only at `:1822` (gossip ingest),
`:1886` (gossip publish), and `:2719` (sync **serve**) — never on the
sync-**ingest** path. The two paths thus implement contradictory downgrade
policy: gossip rejects, sync accepts.

**Impact:** on a domain that has completed enc-v3 rollout, an admitted peer can
deliver arbitrary plaintext `payloads` via a sync response and have them enter
the full apply pipeline, silently voiding the "encrypted-only" invariant the
domain capability advertises. The `enc_v3_plaintext_rejected` telemetry never
fires, so operators cannot see the downgrade. This is a
confidentiality/policy-envelope bypass, not an auth bypass — the content-layer
gates (signature, publisher capability, admission, revocation replay window,
trust-graph authorization) all still run on the sync path (C-3/M-9 parity
confirmed) — hence Medium.

**Fix:** in the `resp.enc_payloads.is_empty()` branch of `handle_sync_response`,
drop the response (and record `enc_v3_plaintext_rejected`) when the domain has
`CAPABILITY_ENC_V3`, mirroring the gossip guard.

---

## L-1 — Sync-ingested tokens leave no audit-chain entry

**Severity:** Low/Medium (compliance/forensics gap)
**File:** `dds-node/src/node.rs` — `handle_sync_response` / `apply_sync_payloads_with_graph`

Every gossip accept/reject stamps the local signed audit chain via
`emit_audit_from_ingest` (17 call sites across `ingest_operation`,
`ingest_revocation`, `ingest_burn`). The sync-ingest chain has **zero**
`emit_audit_from_ingest` call sites — it bumps only Prometheus counters
(`record_sync_payloads_rejected`). A revocation, burn, or self-update manifest
that reaches a node purely via anti-entropy sync mutates store/graph/DAG with no
entry on the Z-3 compliance chain.

**Impact:** an attacker wanting a state change ingested *without* an audit trail
can avoid the gossip mesh and trigger/wait for a sync pull; the resulting change
is invisible to L-12 audit-chain review. Consistent with the known "sync path
historically lags" failure class.

**Fix:** emit audit entries from the sync apply path for accepted/rejected
tokens, mirroring the gossip ingest stamping.

---

## L-2 — Plaintext secrets left in un-zeroed IPC send buffers (Windows)

**Severity:** Low
**Files:** `platform/windows/native/DdsBridgeIPC/ipc_pipe_client.cpp:750–760`
(`StartEnrollUser`) and `:469–491` (`SendMessageWithSeqId`)

`StartEnrollUser` zeroes `req.password` but not the stack `sendBuffer` that
`IpcSerializeMessage` already `memcpy`'d the plaintext password into — despite a
comment claiming it wipes "the password copy that was copied into sendBuffer".
The same pattern applies to `SendMessageWithSeqId`, the helper the CP uses to
ship the `hmac_secret` (vault-unlock key) in `DDS_AUTH_RESPONSE`: the caller
wipes `response.hmac_secret` (`DdsBridgeClient.cpp:1050`) but the serialized copy
inside the helper's `sendBuffer` is not scrubbed. The plaintext lingers on the
stack, exposable via a later crash dump or uninitialized-stack reuse.

**Fix:** `SecureZeroMemory(sendBuffer, sendLen)` after `WriteRaw` on any path
carrying secrets (or unconditionally in these two helpers).

---

## L-3 — Unaligned pointer dereference in `extract_pipe_caller` (soundness/UB)

**Severity:** Low (soundness nit; not exploitable — allocator over-aligns in
practice, and the SID is validated afterward)
**File:** `dds-node/src/http.rs:2627–2631` (Windows only)

```rust
let token_user = buf.as_ptr() as *const TOKEN_USER;
unsafe { (*token_user).User.Sid }
```

`buf` is a `Vec<u8>` (alignment 1); `TOKEN_USER` requires 8-byte alignment
because `SID_AND_ATTRIBUTES` begins with a pointer. Projecting `.User.Sid`
through `*token_user` is UB when the allocation is not 8-aligned. In practice the
system allocator returns ≥16-byte-aligned blocks so it never manifests, but it is
not guaranteed by the `Vec<u8>` contract.

**Fix:** `std::ptr::addr_of!((*token_user).User.Sid).read_unaligned()`, or
over-align the receive buffer.

---

## L-4 — `merged_op_ids` novelty contract holds only in the graph-backed sync variant

**Severity:** Low (latent — the graphless variant is test-only today)
**File:** `dds-net/src/sync.rs:349–359` (graphless `apply_sync_payloads`)

`SyncResult.merged_op_ids` is documented (sync.rs:211–220) as the set callers
gate fire-once side effects on (the self-update quorum accumulator). That
guarantee only actually holds in `apply_sync_payloads_with_graph`, where an op is
merged only if its own token was graph-accepted (novel JTI). In the graphless
variant a duplicate-JTI token merely skips the store write and the op is still
inserted into the DAG unconditionally, so a replayed token paired with a fresh op
id lands in `merged_op_ids`. All production callers use `_with_graph`
(`handle_sync_response`), so this is latent, not exploitable — but the test
comment at sync.rs:684–687 ("same semantics as the graph-backed variant")
overstates the guarantee.

**Fix:** either token-gate the merge in the graphless variant too, or amend the
`merged_op_ids` doc to state the novelty guarantee is `_with_graph`-only.

---

## Informational

- **I-1 — SYSTEM-only pipe DACL vs tray-agent cooldown clear.**
  `ipc_pipe_server.cpp:179` sets `D:(A;;GA;;;SY)` (SYSTEM only), but
  `RefreshVaultFlow.cpp:159` has the interactive-session tray agent open the pipe
  to send `DDS_CLEAR_STALE` (AD-13 lockout-cooldown clear). That `Connect()` now
  fails silently — a functional regression in a security mitigation, and the
  `ipc_messages.h:168` comment ("ACL'd to SYSTEM + current user only") is stale.
  Not exploitable (fails safe), but needs a deliberate decision: remove the dead
  tray path + comment, or add a narrowly-scoped ACE.

- **I-2 — Unauthenticated challenge flood couples to the admin cap.**
  `/v1/session/challenge` is public; it shares the single `CHALLENGES` table and
  the global `MAX_OUTSTANDING_CHALLENGES = 4096` cap with the admin-gated
  challenge endpoints. A local process at the 60 req/s rate limit can fill the
  table in ~68s and 503 admin challenge issuance too. Within the accepted
  local-process threat model and rate-limited, but a per-kind sub-cap would
  decouple the public fill path from admin issuance.

- **I-3 — Implicit sync-ingest size bounds.** Served sync responses are capped
  (H-11: `SYNC_MAX_RESPONSE_ENTRIES=1000`, `SYNC_MAX_RESPONSE_BYTES=5 MB`), but
  the *ingest* side relies only on the libp2p `request_response::cbor` default
  size cap — there is no explicit entry-count check at `node.rs:3079`. Adequate
  but implicit; a hostile responder can pack many payloads into one default-cap
  response. Also `node.rs:3057` decodes decrypted `SyncPayload` with plain
  `ciborium::from_reader` rather than the `cbor_bounded` used elsewhere (I-6
  convention) — harmless for the flat struct, but inconsistent.

---

## Verified solid (checked, no issue)

- **Gossip↔sync gate parity** holds for all auth/authz/replay gates: H-12
  admitted-peer gate (both serve and ingest), live eviction of revoked peers,
  token signature/issuer-binding/expiry, legacy-v1 refusal, C-3 publisher
  capability, SC-5 publisher-identity shape, M-9 revocation/burn replay window,
  trust-graph authorization/dedup, put-if-absent on JTI, DAG-insert gating, R5
  self-update quorum + replay/novelty, and revocation-triggered epoch rotation.
  Only the two sync-side items above (M-2, L-1) diverge.
- **R5 sync-quorum fix** (`node.rs:3254–3290`) is sound — quorum counts only on
  novel DAG merge, and single-payload and cross-payload token-alias launders both
  fail closed.
- **R2 server-side UV gate** in `admin_vouch` (`service.rs:2562–2570`) derives UV
  from signature-covered `authenticator_data`, sits before the trusted-root check
  and vouch mint, and consumes the challenge + bumps sign-count even on reject.
- **Caller-supplied identity fields are ignored** — session binds to the
  credential owner, `admin_vouch` derives the URN from the asserted credential,
  `claim_windows_account` derives subject from the validated token.
- **Atomic security-state writes** — domain store, epoch-key store,
  admission/revocation store, and admin-key store all use `NamedTempFile` +
  `persist` with owner-only perms set before rename; audit append enforces the
  hash chain inside the write txn and derives the next key from `table.last()`.
- **Self-update** — HTTPS-only, streaming SHA-256 pinned to the signed manifest,
  OS-vendor signature check, verify→install TOCTOU closed, downgrade protection
  in the caller with a locally-read installed version.
- **Windows CP fixes** (`CDdsProvider.cpp`) — dense-append bounds, slot NULLing
  after Release, stale serialization-cred reset, `%zu`/DWORD vararg fix — all
  correct.
- **Named-pipe SDDL hardening** applied to *all* pipe instances;
  `FILE_FLAG_FIRST_PIPE_INSTANCE` squat protection and client-side
  `ServerIsLocalSystem()` SID check intact.
- **CommandRunner.cs / MacAccountEnforcer.cs** — `ArgumentList` with
  `UseShellExecute=false`, allowlist-validated inputs, stdin-passed secrets. No
  injection.
- **R4 log redactions** fully remove password-length disclosure across the
  bridge/CP/vault.
- **No lock-across-await hazards** in the HTTP handlers; rate-limiter mutex
  recovers from poison.
