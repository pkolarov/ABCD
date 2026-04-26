# DDS Hardware-Bound Admission Plan

**Status:** ⚠ **CRITICAL — design only, no code shipped.** Tracked as
**Z-2 (High)** in
[Claude_sec_review.md](../Claude_sec_review.md) "2026-04-26 Zero-Trust
Principles Audit". Until Phases A1–A6 below land, every libp2p `PeerId`
in the fleet is a software Ed25519 keypair on disk, and the system fails
zero-trust principle #2 ("identities bound to hardware"). Promote to
top-of-queue.

**Date:** 2026-04-26
**Closes:** [docs/threat-model-review.md](threat-model-review.md) §1 "Bearer
token" risk; structural answer to node-clone resistance.

---

## 1. Problem

`AdmissionCert.body` binds `(domain_id, peer_id, issued_at, expires_at)` —
where `peer_id` is the libp2p `PeerId` derived from the node's Ed25519
keypair stored at `<data_dir>/p2p_key.bin`. An attacker who exfiltrates
`p2p_key.bin + admission.cbor` from a node can stand up a clone on
different hardware: same `PeerId`, same valid cert, accepted by every
peer in the mesh.

Encryption-at-rest (Argon2id m=64 MiB / ChaCha20-Poly1305) protects the
keyfile while the node is offline. While the node is *running*, the key
is in plaintext memory; an attacker with admin/root access reads it
directly. FIDO2 protection is already supported for the *domain* key
(via `--fido2`) but not for the per-node libp2p key.

Revocation works as a containment hammer once a clone is detected, but
detection is the hard part. The structural fix is to make the libp2p
identity **non-exportable** — bound to TPM 2.0 (Linux/Windows), Apple
Secure Enclave (macOS), or a compatible HSM — so that exfiltrating
files is no longer enough to clone the node.

---

## 2. Goals

1. An attacker who exfiltrates every file in `<data_dir>` cannot stand
   up a working clone on different hardware. The clone is rejected at
   H-12 admission, before any gossip / sync ingest.
2. All three primary platforms (Linux, Windows, macOS) get a hardware-
   backed default. Software keys remain available as a fallback for
   dev hosts and unsupported hardware (with a startup WARN log).
3. The integration does **not** require forking `libp2p_identity` or
   any other upstream crate.
4. Existing software-keyed nodes get a clean, scripted migration. No
   big-bang flag day.
5. Performance: hardware signing happens at most once per peer
   connection setup (H-12 handshake); steady-state gossip and sync
   are unaffected.

## 3. Non-goals

- Hardware binding for the **domain** signing key. Already addressed
  by `--fido2` (`dds-node init-domain --fido2`); not in scope for
  this plan.
- Defending against an attacker who has live root on the running
  node. No software design defends against this.
- Hardware binding for `dds-cli`, `dds-loadtest`, `dds-fido2-test`,
  or any non-node process.
- Any change to gossip / sync / token / trust-graph layers. The
  trust boundary is the H-12 admission handshake.

---

## 4. Architectural decision: localize hardware integration to the admission layer, not Noise

Three integration points were considered. The recommended choice is
**Option C** — the libp2p Noise handshake stays software-keyed; the
admission layer (H-12) is what becomes hardware-gated.

### Option A — Fork `libp2p_identity` to add a `Signer` variant

`libp2p_identity::Keypair` is a concrete `enum { Ed25519, Secp256k1,
Ecdsa, Rsa }` that owns raw key bytes. There is no `Signer` trait. To
plug a TPM into Noise, the keypair enum has to be extended.

- **Pro:** the libp2p `PeerId` itself becomes hardware-bound; theft
  of `p2p_key.bin` is meaningless because there are no plaintext
  bytes on disk.
- **Con:** vendoring a libp2p fork in-tree is a significant ongoing
  cost — libp2p moves quickly, and every upstream upgrade would
  require reconciling the patch.
- **Con:** TPM signing latency (~50–100 ms for ECDSA-P256) inside
  the Noise handshake adds the same delay to every peer connection.
- **Con:** upstream interest in a `Signer` trait exists in
  discussions but is not on a roadmap.

### Option B — Software session key + periodic hardware-attested re-issuance

Keep the libp2p Noise key software-resident. Have a separate hardware-
bound long-term key periodically sign an attestation that authorizes
the current software key for a bounded window (e.g. 24 h). Peers
verify the attestation chain.

- **Pro:** libp2p untouched. Bounded compromise window if software
  key is exfiltrated.
- **Con:** introduces a *new* attestation protocol with its own
  freshness and replay considerations. Complexity high relative to
  payoff.
- **Con:** does not actually prevent active attack within the
  attestation window — the attacker holding the software key can
  ride the window.

### Option C (recommended) — Hardware-bound *admission* key, software libp2p Keypair

The libp2p Keypair stays software-resident. Generate a **second** key
— `node_admission_key` — that is hardware-bound (TPM 2.0 / Secure
Enclave). The `AdmissionCert.body` binds the *public* half of this
admission key alongside the libp2p `PeerId`. The H-12 handshake adds
a challenge-response step in which the peer must produce a signature
from the admission key over a verifier-supplied nonce.

- **Pro:** libp2p completely untouched. No fork, no upstream patch.
- **Pro:** hardware signing happens **once per H-12 handshake**, not
  per Noise handshake. H-12 runs once when peers first meet (and on
  reconnect); steady-state gossip is unaffected.
- **Pro:** localizes hardware integration to a single, already-
  existing trust boundary (`dds-net::admission` + `dds-domain::
  AdmissionCert`). Code changes confined to ~3 files in two crates.
- **Pro:** clone with stolen `p2p_key.bin + admission.cbor`
  completes Noise but **fails H-12** because it cannot produce the
  admission signature → not added to `admitted_peers` → all gossip
  and sync from it is dropped at the behaviour layer.
- **Con:** AdmissionCert format must change (v1 → v2 with backward-
  compat). Existing software-keyed admissions need re-issuance to
  carry an `admission_pubkey`.
- **Con:** the libp2p `PeerId` itself remains software-derived, so a
  cloned `p2p_key.bin` can still complete Noise and consume some
  resource budget before being rejected at H-12 — limited by H-12
  handshake rate caps (already in tree as part of the H-12 design).
  This is acceptable: H-12 was designed to be the trust boundary;
  Noise was never designed to be one.

**Decision: Option C.** Rest of this plan assumes it.

---

## 5. `KeyProvider` trait

New in `dds-core::key_provider`. Sign-only — no key export. Concrete
backends live in `dds-node` (where the platform-specific deps belong);
`dds-core` stays `no_std`-compatible.

```rust
// dds-core/src/key_provider.rs
pub enum ProviderKind {
    SoftwareKeyfile,
    Tpm2,
    AppleSecureEnclave,
}

pub trait KeyProvider: Send + Sync {
    fn provider_kind(&self) -> ProviderKind;
    fn public_key(&self) -> AdmissionPublicKey;       // includes alg
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SignError>;
    /// Stable, non-secret identifier for logs/metrics. For TPM this
    /// is the persistent handle; for SE the keychain ref; for
    /// software the on-disk path's SHA-256.
    fn identity_handle(&self) -> String;
}

pub enum AdmissionPublicKey {
    Ed25519([u8; 32]),
    EcdsaP256([u8; 33]),    // SEC1 compressed
}
```

Key properties of the trait:

- **No key export.** No `to_bytes()`, no `secret_bytes()`. Backends
  that *can* export (Software) deliberately don't expose the method
  through this trait; cross-backend code can't accidentally request
  it.
- **Algorithm-agnostic public key.** Both Ed25519 (preferred when
  TPM supports `TPM_ALG_EDDSA` rev ≥ 1.59) and ECDSA-P256 (universal
  TPM 2.0 fallback; only option on Apple SE) are first-class.
- **Async-free.** TPM and SE calls block on hardware; backends spawn
  to a blocking pool internally where needed. The trait stays sync
  to keep the H-12 hot path simple.

---

## 6. AdmissionCert v2

The signed body grows by two fields. v1 stays decodable for the
duration of the migration window; v1 certs are honoured for inbound
H-12 only when `network.admission.allow_v1_certs = true` (default
**true** at first ship, default **false** one release after migration).

```rust
// v2 — wire schema v=2
pub struct AdmissionBodyV2 {
    pub v: u8,                         // 2
    pub domain_id: DomainId,
    pub peer_id: String,
    pub admission_pubkey: AdmissionPublicKey, // NEW
    pub issued_at: u64,
    pub expires_at: Option<u64>,
}
```

### H-12 handshake addition

`AdmissionRequest` and `AdmissionResponse` both gain a fresh 32-byte
random `challenge` and a `challenge_signature: Vec<u8>` over the
peer's challenge using the *admission* key. The receiver:

1. Verifies the AdmissionCert signature against the domain pubkey
   (existing behaviour).
2. Verifies that `body.peer_id` matches the libp2p `PeerId` of the
   Noise-authenticated remote (existing behaviour).
3. **NEW:** verifies `challenge_signature` against
   `body.admission_pubkey` over the locally-supplied challenge.

Step 3 is what kills the clone. A clone with the stolen libp2p
keypair + cert can complete Noise + replay an old challenge_signature
only if it captures one in transit; the local-supplied challenge is
fresh per handshake, and the signature must be over the *receiver's*
challenge, so replay is bounded by the handshake itself.

v1 certs (no `admission_pubkey`) skip step 3; that is the soft
period. Once `allow_v1_certs = false`, v1 certs are rejected outright.

---

## 7. Backends

### 7.1 SoftwareKeyfile (default fallback, dev/CI)

Wraps the existing `p2p_identity::save` / `load` path against a new
`<data_dir>/admission_key.bin` file. Same v=3 ChaCha20-Poly1305 +
Argon2id schema as `p2p_key.bin`. Logs WARN on every node start when
in use ("admission key is software-resident; hardware backend is
recommended for production").

### 7.2 TPM 2.0 (Linux + Windows)

- Crate: [`tss-esapi`](https://crates.io/crates/tss-esapi) v7+. Uses
  the TCG TSS 2.0 ESAPI; on Windows it talks to TBS via an `esys`
  shim; on Linux it talks to `/dev/tpmrm0` or `tpm2-abrmd`.
- Algorithm: **Ed25519** (`TPM_ALG_EDDSA`) when the chip reports it
  via `TPM2_GetCapability(TPM_CAP_ALGS)`, **ECDSA-P256** otherwise.
  Selection is automatic at provisioning time.
- Sealed to `PCR 0 | PCR 7` (firmware + Secure Boot). A cloned disk
  on different hardware cannot unseal the key — the policy session
  fails at first use.
- Persistence: TPM persistent handle in the user-defined range
  `0x81010000–0x8101FFFF`; canonical handle written to
  `<data_dir>/admission_key.toml` for diagnostics (handle is **not**
  a secret).
- Provisioning: new `dds-node provision-admission-key --backend tpm2
  [--algorithm eddsa|p256] [--pcrs 0,7] [--handle 0x81010001]`. The
  MSI custom action `CA_ProvisionAdmissionKey` runs after
  `CA_GenHmacSecret` and before service start.
- Non-export: TPM 2.0 keys created with `TPMA_OBJECT_FIXED_TPM |
  FIXED_PARENT | SENSITIVE_DATA_ORIGIN` + no `decrypt` attribute.
  `TPM2_Duplicate` is forbidden by the policy.

**TPM matrix** (test target):

| Chip | Vendor | Ed25519 | ECDSA-P256 |
|---|---|---|---|
| Intel PTT 2018+ | fTPM | ✗ (rev 1.38) | ✓ |
| AMD fTPM | fTPM | depends | ✓ |
| Infineon SLB 9670 | dTPM | ✓ (rev 1.59+) | ✓ |
| Nuvoton NPCT75x | dTPM | ✓ (rev 1.59+) | ✓ |

ECDSA-P256 is the safe default for the first ship.

### 7.3 Apple Secure Enclave (macOS)

- Crate: [`security-framework`](https://crates.io/crates/security-framework)
  v3+ for the `SecKey` API.
- `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` —
  ECDSA-P256 only (SE does not expose Ed25519).
- Stored in the system keychain with `kSecAttrAccessControl` +
  `kSecAccessControlPrivateKeyUsage`; no `kSecAccessControlBiometryAny`
  on a daemon.
- **Prerequisite:** the `dds-node` binary must be Developer ID
  signed and have the `com.apple.developer.kernel.secure-enclave`
  hardened-runtime entitlement. The pkg installer is not currently
  Developer ID signed; this is a hard prereq.
- Provisioning: `dds-node provision-admission-key --backend
  secure-enclave`. The macOS `.pkg` postinstall script runs it on
  first install.

### 7.4 (deferred) FIDO2 reuse

Reusing the existing `--fido2` path for the admission key is
attractive but means a touch on every H-12 handshake — operationally
unrealistic. Out of scope here; can be revisited if a use case
emerges (e.g. a high-assurance node deliberately limited to
admin-touched startup).

---

## 8. Provisioning

| Platform | Mechanism | When |
|---|---|---|
| Windows MSI | `CA_ProvisionAdmissionKey` custom action (sequenced after `CA_GenHmacSecret`, before service start) | Install + Repair (idempotent: `--keep-existing`) |
| macOS pkg | postinstall script invokes `dds-node provision-admission-key --backend secure-enclave` | Install (idempotent) |
| Linux | systemd `ExecStartPre=` invokes the same subcommand on first boot | Install (idempotent) |
| Dev host | manual: `dds-node provision-admission-key --backend software` | Operator-driven |

All platforms: the provisioning subcommand is idempotent — a key
already present at the configured handle / keychain ref / file path
is reported and reused, not regenerated. Forced rotation goes
through `dds-node rotate-admission-key` (see §9).

---

## 9. Migration from software-keyed nodes

Every existing node has an admission cert that does **not** carry an
`admission_pubkey`. The migration is per-node, scripted, and reversible
within the soft period.

Per-node flow:

1. Operator runs `dds-node provision-admission-key --backend tpm2`
   on the node. New hardware-bound key generated; public half
   printed to stdout.
2. Operator copies the public half to the admin host.
3. Admin runs `dds-node admit --domain-key … --peer-id … --admission-pubkey
   <b64>` to issue a v2 admission cert. (Old v1 cert remains on the
   node's disk for the duration of the migration window.)
4. Admin distributes the v2 cert to the node (USB, gossip, SCP —
   same mechanisms as today).
5. On node restart, the node prefers the v2 cert; v1 cert is ignored
   if a v2 is present.
6. Once every node has migrated, operator flips
   `network.admission.allow_v1_certs = false`. Any remaining v1
   admissions are rejected; revocation on the old PeerIds completes
   the cutover.

Rotation (post-migration): `dds-node rotate-admission-key
[--no-backup]` — same shape as the existing `dds-node rotate-identity`
subcommand. Generates a fresh hardware-bound key, prints the new
pubkey + the explicit admin follow-up commands needed to issue a
fresh cert and revoke the old PeerId binding.

---

## 10. Phasing

| Phase | Deliverable | Estimate | Gating |
|---|---|---|---|
| **A0** | Architectural spike: confirm `tss-esapi` API surface + Apple SE prereqs match the assumptions in §7. **No** code lands; spike output is a 1-page memo. | 3 days | None |
| **A1** | `KeyProvider` trait + `SoftwareKeyfile` backend. Refactor all `<data_dir>/p2p_key.bin` callers in `dds-node` to route through the trait. **Zero** behavioural change; all 528 tests still green. | ~1 week | A0 |
| **A2** | AdmissionCert v2 wire format + H-12 challenge-response step. v1 still accepted; v2 cert with software-keyed `admission_pubkey` works end-to-end. | ~1 week | A1 |
| **A3** | TPM 2.0 backend (Linux + Windows) with ECDSA-P256 only. Provisioning subcommand + MSI custom action + Linux systemd hook. Test matrix on Intel PTT + AMD fTPM. | ~2 weeks | A2 |
| **A4** | Apple Secure Enclave backend. Gated on Developer ID signing for the pkg. | ~1 week | A2 + pkg signing |
| **A5** | Ed25519 path on Infineon / Nuvoton dTPM. Rev 1.59 capability detection + algorithm switch. | ~3 days | A3 |
| **A6** | Migration tooling (`provision-admission-key`, `rotate-admission-key`, `admit --admission-pubkey`) + per-platform docs + `allow_v1_certs = false` default flip. | ~3 days | A3 + A4 |
| **A7** | Threat-model close-out: §1 "Bearer token" risk struck through; STATUS / Claude_sec_review updated. | ~1 day | A6 |

Total: ~6–7 weeks of focused work, dependency-bound (TPM hardware
arrival, pkg signing cert).

---

## 11. Open questions

1. **TPM Ed25519 fallback policy.** Plan defaults to ECDSA-P256
   universally for first ship. Is there appetite to ship Ed25519-on-
   capable-chips in the same release (A3 + A5 merged), or stage A5
   as a follow-up?
2. **Migration window length.** How long does `allow_v1_certs =
   true` stay the default? Recommend 1 release (~1 month) on the
   v2 ship before flipping.
3. **Apple Developer ID signing.** Track A4 is hard-blocked on this.
   Worth a separate prereq line item with its own owner.
4. **TPM Owner Authorization.** TPM 2.0 owner-hierarchy ops require
   the owner password (often empty on consumer hardware, often set
   by enterprise endpoint-management on managed hardware). Plan
   currently uses the endorsement hierarchy + null auth for the
   admission key parent; need to confirm this works on managed
   hardware where owner auth is set.
5. **Linux distribution support.** `tss-esapi` requires `tpm2-tss`
   ≥ 4.0 dev libs at build time. Pre-built packages exist for
   Ubuntu 22.04+, Debian 12+, RHEL 9+, Fedora 38+. Older distros
   need source build — is that acceptable, or do we ship a
   statically-linked variant?
6. **Software backend deprecation.** Does the software backend stay
   as a permanent dev/CI option, or is there a target release where
   it is removed entirely? Recommend: keep as dev fallback
   indefinitely, but log WARN on production-mode startup.

---

## 12. Test strategy

**Per-backend unit tests** (`dds-node/src/key_provider/tests/`):
- Generate, sign, verify roundtrip on each backend.
- Refusal to export the secret half (compile-time absence of an
  export method on the trait, runtime test that backend-specific
  export isn't reachable through `dyn KeyProvider`).
- Algorithm matrix: Ed25519 + ECDSA-P256 for software; ECDSA-P256
  for SE; both for TPM (gated on host capability).

**H-12 integration tests** (`dds-node/tests/h12_admission_v2.rs`):
- Two-node v2-cert handshake with software backend (positive).
- Replayed `challenge_signature` from a previous handshake (negative).
- Stolen cert + libp2p key, no admission key (negative — the clone
  attack the plan exists to prevent).
- v1 cert under `allow_v1_certs = true` (positive — backward-compat).
- v1 cert under `allow_v1_certs = false` (negative — post-migration).

**Cross-platform CI** (`.github/workflows/ci.yml`):
- Linux: TPM 2.0 backend tested via `swtpm` software emulator on
  every PR. Real hardware verification on the maintainer host
  pre-release.
- Windows: TBS-backed TPM tested on the existing Windows host
  runner; emulator path is `tpm2-pytss` against `swtpm` if needed.
- macOS: Secure Enclave backend gated on signed-binary CI; until
  pkg signing is in place, A4 tests run only on the maintainer
  host.

**Performance regression**:
- Add to `dds-loadtest`: H-12 handshake throughput with software
  backend (baseline) vs TPM backend. Acceptance: TPM path within
  10% of baseline gossip steady-state throughput.

**Threat-model exercise**:
- After A6 lands, repeat the existing "exfil `<data_dir>` and stand
  up a clone" scenario against a TPM-backed node. Document the
  failure mode (H-12 rejection) in `dds-fido2-test/README.md` or a
  new `dds-cloneresist-test/README.md`.

---

## 13. Out-of-scope follow-ons

- **Hardware-bound libp2p PeerId** (Option A from §4). Worth
  revisiting if upstream libp2p exposes a `Signer` trait. Not on
  any DDS-driven roadmap.
- **Clone detection at H-12** (the "lighter fix" from earlier
  brainstorming). Useful as defense-in-depth but does not address
  the bearer-token risk on its own — Track A is the structural
  fix. Can land in parallel as a separate plan if appetite emerges.
- **Multi-key admission**. Allowing multiple `admission_pubkey`s
  per cert (e.g. for high-availability rotation) is a future
  extension; v2 cert format reserves field ordering to accommodate
  it without a v3 schema bump.
