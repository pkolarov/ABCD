# FIDO2 Attestation Allow-List & Upgrade Path

## Supported Attestation Formats

DDS currently accepts two WebAuthn attestation formats during user enrollment
(`POST /v1/enroll/user`):

| Format   | Description | x5c chain | AAGUID checked |
|----------|-------------|-----------|----------------|
| `none`   | No attestation statement. The authenticator provides only the credential public key. Suitable for platform authenticators and soft tokens. | n/a (no `x5c`) | Optional, against `fido2_allowed_aaguids` |
| `packed` | Self-attestation (no `x5c`) **or** full attestation with `x5c`. The leaf-cert signature over `authData ‖ clientDataHash` is verified in both sub-modes since A-1 step-2. Self-attestation verifies the signature under the credential pubkey from `authData`; full attestation verifies it under the leaf cert's SubjectPublicKey. | Leaf signature: always when present. Chain to root: optional, opt-in per AAGUID via `[[domain.fido2_attestation_roots]]` (Phase 2 below). | Optional, against `fido2_allowed_aaguids` |

Unsupported formats (`tpm`, `android-key`, `android-safetynet`, `apple`,
`fido-u2f`) are rejected with a `Fido2Error::Format` error at enrollment time.

## Why Only `none` and `packed`

1. **Platform coverage**: Windows Hello, macOS Touch ID/Face ID, and most
   roaming FIDO2 keys (YubiKey, Crayonic C-Key, Feitian) emit either `none`
   or `packed` (self-attested or with x5c) by default when the relying
   party does not request enterprise attestation.

2. **No mandatory CA trust store**: `tpm`, `android-key`, and FIDO MDS
   integration would require maintaining a vendor-specific or MDS-rooted
   trusted root certificate store. DDS does not mandate any of those —
   identity trust flows through the vouch chain, not through hardware
   vendor PKI. Operators who want chain-rooted assurance for a specific
   authenticator model can opt in per-AAGUID via Phase 2 below; everyone
   else stays on the leaf-signature floor.

3. **Privacy**: `none` attestation reveals no information about the
   authenticator make/model. This aligns with DDS's design principle
   of minimizing metadata leakage.

## x5c Certificate Chain Handling

The `packed` attestation handler (`verify_packed` in
`dds-domain/src/fido2.rs`) treats the `x5c` array in two layers:

- **Leaf signature — always verified when `x5c` is present.** Since A-1
  step-2 (security review, 2026-04-25), the handler extracts the leaf
  cert's `SubjectPublicKeyInfo`, enforces that the SPKI algorithm OID
  matches the `attStmt.alg` field (defends against an alg-downgrade
  where an EC cert is shipped under EdDSA framing), and verifies the
  `sig` field over `authData ‖ clientDataHash` under that pubkey. Pre-A-1
  this branch returned `Ok(())` unconditionally as soon as `x5c` was
  present, which let any local process forge a packed attestation by
  attaching arbitrary cert bytes; that gap is closed regardless of
  whether a chain root is configured.

- **Chain to root — opt-in per AAGUID.** When an AAGUID has a
  `[[domain.fido2_attestation_roots]]` entry (Phase 2 below), the
  service additionally validates the leaf-first chain up to one of the
  PEM-encoded roots at `ca_pem_path`. Operators bring their own roots —
  no MDS dependency. AAGUIDs without a configured root fall through to
  the leaf-signature floor; the Phase 1 allow-list (below) is the right
  tool for "refuse this AAGUID outright."

FIDO MDS-rooted chains (which would let DDS automatically trust the set
of FIDO-Alliance-attested authenticators without per-AAGUID config) are
the deferred follow-up, tracked as M-13 in
[Claude_sec_review.md](../Claude_sec_review.md). The current opt-in
per-AAGUID model lets an operator add a vendor root in TOML today
without taking on MDS's JWT/refresh/CA-dependency surface.

## AAGUID Considerations

The Authenticator Attestation GUID (AAGUID) is extracted from the
`authData` and is now (since 2026-04-26) **optionally** validated against an
allow-list configured in `dds.toml`. By default the list is empty and any
FIDO2-compliant authenticator can be used for enrollment; enterprises that
want to restrict enrollment to approved authenticator models can populate
the allow-list (see Phase 1 below). Phase 2 layers chain validation on
top: when an AAGUID has a configured root cert, the leaf cert's
`id-fido-gen-ce-aaguid` extension must match the AAGUID in `authData`
and the chain must validate to the configured root. Phase 3 (TPM)
extends this to TPM-attested credentials.

## Upgrade Path

### Phase 1: AAGUID Allow-List ✅ Implemented (2026-04-26)

Add a `fido2_allowed_aaguids` list to the `[domain]` section of `dds.toml`:

```toml
[domain]
fido2_allowed_aaguids = [
  "2fc0579f-8113-47ea-b116-bb5a8db9202a",  # YubiKey 5 NFC
  "ee882879-721c-4913-9775-3dfcce97072a",  # Crayonic C-Key
]
```

Each entry must be a canonical UUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`)
or a 32-character bare hex string. The parser is case-insensitive. When
non-empty, enrollment (`POST /v1/enroll/user` and the bootstrap
`admin_setup` path) rejects any authenticator whose AAGUID is not in the
list with a `Fido2` error. When empty (the default), every AAGUID is
accepted — including the all-zero AAGUID that platform authenticators
emit. Unparseable entries are surfaced as a hard error at startup; the
node refuses to serve traffic rather than silently falling back to "any
AAGUID".

Implementation:

- AAGUID is parsed from `authData` bytes 37..53 in
  [`dds-domain/src/fido2.rs`](../dds-domain/src/fido2.rs) (`parse_auth_data`)
  and surfaced as `ParsedAttestation::aaguid`.
- The allow-list is configured via `DomainConfig::fido2_allowed_aaguids` in
  [`dds-node/src/config.rs`](../dds-node/src/config.rs) and enforced by
  `LocalService::enforce_fido2_aaguid_allow_list` in
  [`dds-node/src/service.rs`](../dds-node/src/service.rs), called from both
  `enroll_user` and `admin_setup`.
- Eight regression tests pin the contract: three in
  `dds-domain::fido2::tests` cover AAGUID extraction (zero, non-zero, and
  `fmt = "none"`); five in `dds-node/tests/service_tests.rs` cover the
  empty-allow-list passthrough, listed-authenticator accepted,
  unlisted-authenticator rejected (with the offending AAGUID echoed in
  the error), bare-hex / mixed-case parsing, and malformed-config
  rejection.

### Phase 2: Per-AAGUID Attestation Root ✅ Implemented (2026-04-26)

Phase 2 ships without FIDO MDS — operators bring the vendor CA root
themselves. For any AAGUID configured under
`[[domain.fido2_attestation_roots]]`, enrollment becomes strict:

1. `attStmt.x5c` must be present (self-attested `packed` is refused
   for that AAGUID).
2. The attestation signature is verified against the leaf cert's
   `SubjectPublicKeyInfo` (already covered by A-1 step-2; unchanged).
3. The leaf cert's `id-fido-gen-ce-aaguid` extension
   (OID `1.3.6.1.4.1.45724.1.1.4`) must equal the AAGUID in
   `authData` — catches a leaf cert reused under a forged AAGUID
   claim.
4. The chain `attStmt.x5c[0..]` is validated up to one of the PEM
   certs at `ca_pem_path`. Each adjacent pair is verified by
   signature; the topmost cert is signed by one of the configured
   roots. Validity windows are checked against the current time.

```toml
[[domain.fido2_attestation_roots]]
aaguid    = "2fc0579f-8113-47ea-b116-bb5a8db9202a"      # YubiKey 5 NFC
ca_pem_path = "/etc/dds/yubico-fido-root-ca.pem"

[[domain.fido2_attestation_roots]]
aaguid    = "ee882879-721c-4913-9775-3dfcce97072a"      # Crayonic C-Key
ca_pem_path = "/etc/dds/crayonic-fido-root-ca.pem"
```

Behavior is opt-in *per AAGUID*. AAGUIDs without a configured root
fall through to the existing self-attested `packed` path — the
allow-list (Phase 1) is the right tool for "just refuse this
AAGUID outright." Multiple PEM-encoded certs in one file are all
treated as alternative trust anchors (useful for vendors that
rotate roots without retiring older certs).

Failure modes that surface as explicit errors:

| Symptom | Error |
|---|---|
| AAGUID has a root configured but `attStmt.x5c` is absent | `Fido2: AAGUID … requires attStmt.x5c …` |
| Leaf cert lacks `id-fido-gen-ce-aaguid` extension | `Fido2: AAGUID … requires leaf cert id-fido-gen-ce-aaguid extension; not present` |
| Leaf cert's AAGUID extension differs from authData AAGUID | `Fido2: leaf cert AAGUID … does not match authData AAGUID …` |
| Chain does not validate to any configured root | `Fido2: attestation cert chain validation failed for AAGUID …` |
| `ca_pem_path` cannot be read or contains no `CERTIFICATE` blocks | startup-time error — node refuses to start |

Implementation:

- New `dds_domain::fido2::extract_attestation_cert_aaguid` parses the
  leaf cert's `id-fido-gen-ce-aaguid` extension into a `[u8; 16]`.
- New `dds_domain::fido2::verify_attestation_cert_chain` walks
  leaf → topmost chain cert → configured root, verifying signatures
  with ECDSA-with-SHA256 (P-256) or Ed25519. RSA chains are not
  supported in this phase; modern FIDO2 hardware (YubiKey, Crayonic,
  SoloKey, Feitian) all use ECDSA P-256.
- New config struct `Fido2AttestationRoot { aaguid, ca_pem_path }`
  in `dds-node/src/config.rs`, surfaced as
  `[[domain.fido2_attestation_roots]]`.
- New service helper `LocalService::enforce_fido2_attestation_roots`,
  called from both `enroll_user` and `admin_setup` after the Phase 1
  allow-list check.
- Six new integration tests in `dds-node/tests/service_tests.rs`
  cover: valid chain accepted, self-attested rejected for a
  configured AAGUID, chain to a *different* root rejected, leaf
  AAGUID-extension mismatch rejected, unconfigured AAGUID still uses
  the self-attested path, malformed config (bad UUID / missing PEM /
  PEM with no CERTIFICATE blocks) refused at startup.
- Eight new unit tests in `dds-domain::fido2::tests` cover AAGUID
  extension extraction (present, absent, malformed) and chain
  validation (valid, wrong root, empty chain, no roots, expired).

### Future: FIDO MDS Integration (deferred)

The current design intentionally avoids the FIDO Alliance Metadata
Service (MDS) blob: it would add a JWT verify, a ~2 MB signed
download, periodic refresh, and a CA dependency on the FIDO
Alliance. Operators can paste vendor PEMs into TOML today; an MDS
loader could be added later behind a feature flag without changing
the per-AAGUID gate.

### Phase 3: TPM Attestation

For Windows devices with TPM 2.0:

1. Parse the `tpm` attestation format per WebAuthn §8.3.
2. Validate the AIK certificate chain against the TPM vendor CA
   (e.g., Microsoft TPM Root Certificate Authority).
3. Verify the `certInfo` (TPMS_ATTEST structure) signature.

TPM attestation provides the strongest hardware binding but requires
the most complex validation. Recommended only for high-assurance
deployments.

## Current Code References

- Attestation parsing & verification: `dds-domain/src/fido2.rs` → `verify_attestation()`
- Enrollment flow: `dds-node/src/service.rs` → `enroll_user()`
- Test builders: `build_none_attestation()`, `build_packed_self_attestation()` in `fido2.rs`
