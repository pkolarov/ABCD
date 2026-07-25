# DDS Pre-Production Review

Started 2026-07-24, completed 2026-07-25. Multi-agent review of the DDS
workspace: **18 finder agents** across security, mesh-forming, stability,
node-upgrade, and fuzzing, each finding then put through an **adversarial
verification pass** that tried to refute it against source.

---

## Remediation status — all findings closed in v1.6.0 (2026-07-25)

Every finding below (H1, M1–M6, L1–L17, I1) has been fixed. Each fix is
marked in source with its finding ID. Verification: 1267 Rust tests, 348
.NET tests (net8.0 + net9.0), `cargo clippy -D warnings` clean, `cargo
fmt` clean, credential-provider rebuild clean.

Two corrections to this document, from implementing it:

- **M6 is REFUTED — measured, not argued.** The predicted failure
  (`new X509Certificate2(msiPath)` throwing on an MSI, making every MSI
  `SoftwareAssignment` fail closed) **does not occur**. Tested against a
  validly-signed MSI on Windows 11 ARM64: .NET's file constructor routes
  through `CryptQueryObject`, which dispatches to the registered MSI
  Subject Interface Package and reads the signer correctly. **MSI
  software installs were never failing closed for this reason.** The
  verifier was still rewritten to read the signer from WinTrust's own
  provider state — it reports the chain `WinVerifyTrust` actually
  validated, avoids a second read of the file (closing a TOCTOU window),
  and drops the SYSLIB0057-obsolete constructor — with a live test
  asserting the old and new paths name the same signer. Belongs in the
  *Refuted* table below, not in "fix before GA".

- **L12 carries a breaking change.** Flipping the
  `trust_loopback_tcp_admin` default to `false` broke Windows
  single-file provisioning, which relied on the old default; fixed by
  having `run_provision` emit the flag explicitly. All shipped packaging
  (MSI / pkg / deb) already ships `pipe:` or `unix:` transport with the
  flag `false`, so **packaged installs are unaffected**. Raw-binary
  deployments serving the admin API over loopback TCP must now set
  `[network.api_auth] trust_loopback_tcp_admin = true` explicitly.

---

## Result summary

- 18/18 finder dimensions ran; **45 raw findings** → deduped below.
- Verification pass: **15 survived, 16 refuted, ~13 unverified** (a batch of
  verifier agents errored on a token-limit window; those are manually assessed
  and marked *(self-verified)* below).
- **Only one HIGH survives verification** (H1, gossip/H-12). Two items an earlier
  interim draft called blockers — the named-pipe PID race and the RegistryEnforcer
  `SYSTEM\Services` write — were **refuted** and are recorded under *Refuted* with
  the reasoning.

Legend: **CONFIRMED** = verifier could not refute it against source; **PLAUSIBLE**
= real but conditional/lower-impact; **(self-verified)** = I read the code and
confirmed it, the automated verifier did not run on it; severities shown as
`reported → verified`.

---

## HIGH

### H1 — Gossip is auto-forwarded to the whole mesh before the H-12 admission gate runs — **CONFIRMED (high)**
`dds-net/src/transport.rs:168` · `dds-node/src/node.rs:1306`

Gossipsub is built with `ValidationMode::Strict` but **without
`.validate_messages()`** and without peer scoring (verified: `validate_messages`,
`report_message_validation_result`, `with_peer_score` exist **nowhere** in the
tree). libp2p therefore auto-forwards every signature-valid, non-duplicate
message to mesh peers *before* the app runs the H-12 check at `node.rs:1306` —
which only suppresses **local** ingest, after the relay already happened.

- **Amplification-flood facet — CONFIRMED high.** An unadmitted, Noise-only peer
  (fresh keypair, reachable via the `0.0.0.0:4001` default or LAN mDNS) publishes
  signed 64 KiB messages; the entry node relays each to its mesh before dropping
  locally; dedup is defeated by varying one byte. No per-peer gossip rate limit
  exists. One unadmitted peer floods the whole domain.
- **Admission-bypass facet — PLAUSIBLE (medium).** Downstream admitted nodes
  receive the relayed message with `propagation_source` = the honest relay, so
  their H-12 gate passes and they may ingest an unadmitted peer's operation. The
  verifier rated this plausible rather than fully confirmed, but the root cause is
  the same missing control.

**Fix:** add `.validate_messages()` to the gossipsub `ConfigBuilder`; call
`report_message_validation_result(id, source, Accept)` only after the
`admitted_peers` gate + per-token validation pass, else `Ignore`; add peer
scoring and an inbound publish-rate cap. This is the single most important fix
before GA.

---

## MEDIUM

### M1 — No libp2p `ConnectionLimits` on the `0.0.0.0`-bound swarm → inbound handshake flood — **CONFIRMED (medium)**
`dds-net/src/transport.rs:259` · default `dds-node/src/config.rs:412`

No `connection_limits::Behaviour` anywhere; the swarm sets only an idle timeout.
Every inbound connection forces a Noise handshake + admission-challenge
allocation and lingers minutes (torn down only after `MAX_ADMISSION_ATTEMPTS=5`
on the ~60s tick); attacker rotates keypairs so the PeerId denylist never bites.
**Fix:** install `connection_limits::Behaviour` (max established/pending inbound,
per-peer), add an inbound handshake rate limit, disconnect un-admitted peers on a
short wall-clock timeout.

### M2 — Self-update download has no timeout and no size cap, and holds a process-global install lock for the whole download — **CONFIRMED (medium)** *(new: node-upgrade dimension)*
`dds-node/src/self_update.rs:83`

The default-on self-updater downloads the artifact with no request timeout and no
maximum size, while holding the process-global install lock. A stalled or
endless-body server (or a MITM feeding an infinite stream) exhausts disk/memory
and **permanently wedges the update channel** — the node can no longer receive a
legitimate (e.g. security-fix) update. **Fix:** bounded timeout + max-size cap on
the download, and don't hold the global lock across the network fetch.

### M3 — Hybrid-KEM secret + epoch AEAD keys written to disk in plaintext (bypasses passphrase / `DDS_REQUIRE_ENCRYPTED_KEYS`) — **(self-verified, medium)**
`dds-node/src/epoch_key_store.rs:405-434`

`save()` serializes `kem_x_sk`, `kem_mlkem_seed`, `my_epoch_key` and cached peer
epoch keys as raw `CborValue::Bytes` — no passphrase branch, not wired into
`require_encrypted_keys()`, unlike `identity_store`/`domain_store`. The file *does*
now get an owner-only DACL (lines 455/461), so live co-tenant read is blocked;
**residual risk is a stolen disk image / backup / VSS snapshot** where every other
key file is encrypted but this one is plaintext. The KEM secret decaps every
`EpochKeyRelease` and recovers all peer epoch keys. **Fix:** route through the
same passphrase encryption and honor `require_encrypted_keys()` (fail closed).

### M4 — Provision bundle (wraps the domain root key) gets no owner-only DACL on Windows — **(self-verified, medium)**
`dds-node/src/provision.rs:371-375`

`save_bundle` restricts the `.dds` bundle owner-only **only under `#[cfg(unix)]`**;
it never calls `crate::file_acl::restrict_to_owner` (which epoch_key_store *was*
fixed to use). Written to an operator-chosen out-path outside `%ProgramData%\DDS`,
the bundle inherits a DACL that may grant `Users:Read`, letting a co-tenant copy
it and brute-force a weak `DDS_DOMAIN_PASSPHRASE` offline → domain root key. **Fix:**
replace the `#[cfg(unix)]` block with `restrict_to_owner(path)`. (Same Unix-only
idiom in `dds-cli export` / `audit export --out` — check those too.)

### M5 — Swarm-task `trusted_roots` never demotes an admin whose promoting vouch *expired* — **(self-verified, medium)**
`dds-node/src/node.rs:2571`

`reconcile_roots_after_token` demotes **only** on an explicit `Revoke` token; there
is no expiry-driven demotion, while the authoritative `LocalService` side *does*
drop a root once its vouch lapses. Since every `dds:admin` vouch has a finite
1-year expiry, a delegated sub-admin (and any publisher it vouched) stays a
fully-authoritative trust root on every long-running node **until restart**, so
expiry-based de-authorization silently fails on the swarm ingest gate. **Fix:**
run a periodic expiry-aware reconcile in the swarm loop, or re-check the promoting
vouch is live in `validate_chain`/`has_purpose`, or signal the swarm task on
`LocalService` demotion.

### M6 — Authenticode gate likely rejects validly-signed MSIs → software-install path fails closed — ~~PLAUSIBLE~~ **REFUTED by live test (2026-07-25)**

> **Refuted.** The live signed-MSI test this finding asked for was run:
> `new X509Certificate2(msiPath)` does **not** throw, because .NET routes
> it through `CryptQueryObject` → the MSI SIP. MSI installs were not
> failing closed. See the Remediation section at the top. The verifier
> was rewritten anyway on independent merit (WinTrust-validated chain, no
> second file read, no obsolete API).
`platform/windows/DdsPolicyAgent/Enforcers/WinTrustAuthenticodeVerifier.cs:66`

After `WinVerifyTrust` passes, the agent extracts the signer via
`new X509Certificate2(filePath)`, which may throw on an MSI (signature lives in the
OLE `\05DigitalSignature` stream, not PE-embedded PKCS#7) → caught → `IsValid=false`
→ every MSI `SoftwareAssignment` fails while `RequirePackageSignature` defaults
true. Real-WinTrust path is untested (Windows-CI pending). Risk: operators disable
signature enforcement fleet-wide to make installs work. **Not runnable here** —
verify with a signed MSI; extract the signer via `WTHelperGetProvSignerFromChain`
instead of the file constructor. *(Distinct from installer signing, which IS done
— see Refuted list.)*

---

## LOW

- **L1 — `/v1/policy/evaluate` unauthenticated oracle** (`dds-node/src/http.rs:807`) — **CONFIRMED, medium→low.** In `public_routes` (no admin gate); any local caller can query allow/deny for arbitrary subjects. Downgraded: read-only, low-value output, rate-limited (burst 60), and the roster endpoint that would supply subject URNs *is* admin-gated. **Fix:** gate it or bind to a session token for `subject_urn`.
- **L2 — `SetSerialization` password blob never scrubbed; `_CleanupSetSerialization` is dead code** (`platform/windows/native/DdsCredentialProvider/CDdsProvider.cpp:470`) — **CONFIRMED, medium→low.** RDP/NLA Windows password lingers un-zeroed in the LogonUI (SYSTEM) heap; recoverable only with existing SYSTEM memory access. **Fix:** call the existing scrubber in `~CDdsProvider` and at the replace site.
- **L3 — Untrusted identifiers logged verbatim → log injection/forgery** (`dds-node/src/http.rs:2143`) — **CONFIRMED, medium→low.** *(new)* `device_urn`/enroll labels go unescaped into a line-oriented tracing subscriber; a crafted value can forge audit-log lines. **Fix:** escape/validate identifiers before logging.
- **L4 — HTTP listeners spawn unbounded per-connection tasks with no read/idle timeout** (`dds-node/src/http.rs:3134`) — **CONFIRMED.** *(new: stability)* A slow-loris / connection pile-up has no ceiling. **Fix:** per-connection read/idle timeout + concurrent-connection cap.
- **L5 — mDNS peer-table ceiling counts unvalidated announcements and never evicts** (`dds-node/src/node.rs:2229`) — **PLAUSIBLE, medium→low.** One LAN host advertising 256+ spoofed IDs fills `mdns_known_peers` (populated pre-Noise) and, at `MDNS_PEER_TABLE_MAX`, locks out every real peer with no eviction. Relevant to the zero-config bridged-mDNS LAN topology where mDNS is the only discovery path. **Fix:** count only validated/connected peers, or LRU-evict never-admitted entries; age out peers that never complete Noise.
- **L6 — Anti-entropy sort processes revocations before their targets → drops same-batch revocations** (`dds-net/src/sync.rs:450`) — **PLAUSIBLE, high→low.** *(new: sync)* Ordering can silently discard a revocation delivered in the same sync batch as its target. **Fix:** apply targets before revocations, or two-pass.
- **L7 — Replication-confirm probe counts a JTI as present without validating the token** (`dds-node/src/node.rs:3635`) — **(self-verified), medium→low.** *(new: sync)* An *admitted* peer can return a token bearing the target `jti` and be counted as confirming replication it doesn't hold; result drives a confirmation display, not state (payloads deliberately not applied). **Fix:** verify the token signature/identity before counting present.
- **L8 — Live `node.toml` rewritten non-atomically → crash mid-write bricks the node** (`dds-node/src/service.rs:948`) — **PLAUSIBLE, high→low.** *(new: stability; relates to the known MSI-upgrade config-reset issue)* **Fix:** write-temp-then-rename.
- **L9 — Provisioning writes `admission.cbor` before `dds.toml` → crash between them bricks/blocks re-provision** (`dds-node/src/provision.rs:1159`) — **PLAUSIBLE, medium→low.** *(new)* **Fix:** order writes so a partial state is recoverable, or stage+rename.
- **L10 — No per-response count cap on `SyncResponse` payloads → admitted-peer CPU-amplification** (`dds-node/src/node.rs:4062`) — **(self-verified), low.** *(new: sync)* **Fix:** cap payload count per response.
- **L11 — Admission challenge/response not correlated to `request_id`** (`dds-node/src/node.rs:1630`) — **PLAUSIBLE.** Concurrent TCP+QUIC dials mismatch the per-peer challenge, spuriously leaving a genuine peer un-admitted. **Fix:** key `pending_challenges` by outbound `request_id`.
- **L12 — DNS-rebinding: no `Host`/`Origin` validation; TCP default exposes admin API** (`dds-node/src/http.rs:734`) — **(self-verified).** Shipped packaging uses UDS/pipe (browsers can't reach); the binary default `127.0.0.1:5551` + `trust_loopback_tcp_admin=true` is exposed. **Fix:** loopback-Host allowlist; default `trust_loopback_tcp_admin=false`.
- **L13 — DPAPI-decrypted passphrase not zeroized before `LocalFree`** (`dds-node/src/win_dpapi.rs:88`) — **(self-verified).** `SecureZeroMemory` before free.
- **L14 — Epoch-key store secrets not zeroized on drop** (`dds-node/src/epoch_key_store.rs:141`) — **(self-verified).** Add `ZeroizeOnDrop`.
- **L15 — `ParseManagedKey` mis-parses key-level registry items → retracted keys never reverted** (`platform/windows/DdsPolicyAgent/Enforcers/RegistryEnforcer.cs:317`) — **PLAUSIBLE.** Persist an explicit key/value discriminator.
- **L16 — FFI `read_cstr` launders a caller-owned C string into `&'static str`** (`dds-ffi/src/ffi_core.rs:42`) — **(self-verified), latent unsoundness.** Return a lifetime-tied borrow.
- **L17 — PQ gossip/sync envelope decode uses plain `ciborium` not the depth-bounded reader** (`dds-node/src/node.rs:2271`, `dds-net/src/pq_envelope.rs:279`) — **defense-in-depth consistency nit.** ciborium self-caps at depth 256 (so not an unbounded-recursion DoS, per verifier), but for uniformity use `dds_core::cbor_bounded::from_reader` at untrusted boundaries.

## INFO

- **I1 — Self-update Authenticode pin degrades to a leaf-CN string match when `root_thumbprint` is omitted** (`dds-node/src/self_update.rs:208-225`) — **(self-verified).** *(new: upgrade)* With no `root_thumbprint`, the only check is signer-subject CN equality; any Authenticode cert with a matching CN from a WinTrust-trusted root would pass. **Fix:** require `root_thumbprint` to be set (fail closed if absent).
- **I2 — `sign_count==0` skips the clone/replay counter check** (`dds-node/src/service.rs:2295`) — **REFUTED as a break** (single-use challenge blocks live replay); treat 0-after-nonzero as a regression for telemetry.

---

## Refuted (checked against source and cleared — do not re-investigate)

The verification pass **refuted** these; recorded so they aren't re-raised:

| Finding | Why cleared |
|---|---|
| Named-pipe admin gate PID-reuse TOCTOU spoofs SYSTEM (`http.rs:3287`) | Not exploitable: an unprivileged attacker can't steer a SYSTEM process onto a recycled PID; window is a few synchronous µs; prior audit marks it *disputed*. Hardening nit only (switch to `ImpersonateNamedPipeClient`). |
| RegistryEnforcer `SYSTEM\Services` → SYSTEM code-exec (`RegistryEnforcer.cs:35`) | Adds no marginal capability: the attacker is a compromised node holding the pinned signing key (already a trust authority); on hosts where registry writes execute, the same signed doc already yields SYSTEM via `AccountEnforcer` (local-admin creation, no Authenticode gate); on AD hosts enforcement is forced to Audit so the write never runs. Trust boundary is the pinned key, not the allowlist. |
| Installer / CP DLL / custom-action unsigned (`Build-Msi.ps1:304`) | Production MSIs **are** signed via Azure Trusted Signing in the `msi.yml` CI release job (finder read only the local dev script); release fails unless signature is Valid, plus cosign + SLSA provenance. |
| Self-update release channel never enforced (`types.rs:1285`) | Decorative/advisory field (tracked TODO), no per-node channel config exists, and any actor able to publish already cleared the K-of-M quorum with fleet-wide push. No boundary bypassed. |
| enc-v3 CBOR decode unbounded depth (`pq_envelope.rs:279`) | ciborium self-caps at 256; the code's own I-6 doc calls 256 "generally safe." No stack exhaustion. Consistency nit (see L17). |
| Passwordless login `UV=DISCOURAGED`, stolen key logs in (`DdsBridgeClient.cpp:991`) | By-design possession factor; hmac-secret CredRandom must match enrollment. Risk-accepted. |
| EpochKeyRelease ML-DSA `pq_signature` absent (`node.rs:5268`) | Refuted at claimed severity. |
| Provision `domain_name` not signed (`provision.rs:191`) | Crypto binding via id/pubkey holds; refuted. |
| `DDS_AUTH_RESPONSE` not bound to client/seqId (`DdsAuthBridgeMain.cpp:1187`) | Refuted. |
| `credential_id_len`/`salt_len` not clamped (`DdsBridgeClient.cpp:955`) | Refuted. |
| `UninstallMsi` package_id injection (`WindowsSoftwareOperations.cs:172`) | Refuted. |
| `trust_graph` RwLock poison cascade (`node.rs:1131`) | Refuted. |
| `/metrics` shares service mutex (`telemetry.rs:2867`) | Refuted. |
| Single-file provision writes admin-open loopback TCP (`provision.rs:1235`) | Refuted. |
| Identity URN label not charset-validated (`identity.rs:86`) | Only the hash is trust-bound; refuted. |

---

## Recommended production gate

**Block on:** **H1** (gossip/H-12 — the one surviving high; the admission
guarantee is defeated for the gossip relay path).

**Fix before GA:** **M1** (connection limits), **M2** (self-update download
timeout/size cap), **M3** (epoch keys plaintext at rest), **M4** (provision-bundle
Windows DACL), **M5** (expired-admin still trusted), and **confirm M6** (don't ship
with MSI software-installs silently failing closed).

**Batch as hardening:** the LOW set — especially L4/L8/L9 (stability/brick paths),
L5 (LAN discovery DoS), L6/L7/L10 (sync integrity/DoS), and I1 (require
`root_thumbprint`).

Coverage is now complete across all five requested dimensions. The refuted table
above is itself a useful artifact — several plausible-looking issues were checked
and cleared with source-level reasoning.
