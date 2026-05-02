# DDS Supply-Chain Integrity & Self-Update Plan

**Status:** Plan — open for implementation
**Date:** 2026-04-26
**Closes (when implemented):** Z-6 / Z-7 / Z-8 from
[Claude_sec_review.md](../Claude_sec_review.md) "2026-04-26 Zero-Trust
Principles Audit (supply-chain follow-up)". Promotes the Authenticode
recommendation already noted in
[docs/threat-model-review.md](threat-model-review.md) §3 from "pending
cert" to a tracked Phase. Sets up the fleet-update story that the AD-
replacement roadmap deliberately omits today.
**Owner:** TBD.

---

## 1. Problem statement

Today an operator who installs DDS — or applies an update to it — has
no programmatic way to verify the bits are the bits we shipped. The
Windows MSI build job has Authenticode scaffolding gated behind a
`SIGN_CERT` secret that has never been provisioned
([.github/workflows/msi.yml:152-176](../.github/workflows/msi.yml));
the macOS `.pkg` job runs `pkgutil --payload-files` as a smoke test
and has no `codesign` / `notarytool` calls at all
([.github/workflows/pkg.yml:115-130](../.github/workflows/pkg.yml));
CLI / FFI binaries publish to GitHub Releases unsigned. Once installed,
the running node never re-checks itself.

For DDS-managed third-party software, the picture is asymmetric:

- The `SoftwareAssignment` document is admin-signed and gated by the
  `dds:software-publisher` capability (C-3, closed). The download URL
  and SHA-256 live inside the signed body, so a CDN swap fails the
  hash check.
- **macOS** calls `pkgutil --check-signature` —
  [SoftwareInstaller.cs:134-137](../platform/macos/DdsPolicyAgent/Enforcers/SoftwareInstaller.cs)
  — but only when `_config.RequirePackageSignature` is true. Default
  off.
- **Windows** has **no** Authenticode verification. `WinVerifyTrust`
  / `signtool` / `Authenticode` do not appear in
  [WindowsSoftwareOperations.cs](../platform/windows/DdsPolicyAgent/Enforcers/WindowsSoftwareOperations.cs)
  or [SoftwareInstaller.cs](../platform/windows/DdsPolicyAgent/Enforcers/SoftwareInstaller.cs)
  at all. SHA-256 is the only check.

And there is no fleet update mechanism for DDS itself. Operators
re-deploy the MSI / pkg by hand on every host, or via an external MDM.
A security patch to `dds-node` does not propagate by virtue of being
in the gossip mesh — the gossip mesh carries directory state, not
binaries.

## 2. Goals

1. Every DDS release artifact (Windows MSI + bundled binaries, macOS
   pkg, CLI, FFI shared library) carries an OS-vendor-rooted signature
   that operators can verify with stock tools (`signtool verify`,
   `pkgutil --check-signature`, `codesign --verify`). Closes Z-6.
2. DDS-managed third-party software installs require **two**
   independent signature checks: the DDS document signature (admin-
   issued, capability-gated — already enforced) **and** an
   OS-vendor-rooted signature on the package blob (Authenticode on
   Windows, Developer ID on macOS). Closes Z-7.
3. DDS releases publish SLSA-style provenance and an SBOM alongside
   the binary, so a downstream operator can verify what code went
   into the build. Partial Z-8.
4. DDS can update itself across the fleet, **safely** — a single
   admin key compromise does not give an attacker remote code
   execution on every node. Operational Z-8.

## 3. Non-goals (deferred)

- **Reproducible-bit-for-bit builds.** Cargo-build determinism is
  hard across hosts (timestamps, paths, `RUSTFLAGS`). SLSA Level 3
  provenance + a hermetic build pipeline + `cargo-vet` is the v1
  bar; bit-reproducibility is a v2 follow-up.
- **Anti-rollback for managed software.** Out of scope here; lives
  with the existing version-supersede logic (B-4, closed).
- **Distribution beyond GitHub Releases.** No first-class APT /
  Homebrew / winget channels in v1; operators bring their own MDM
  or air-gap workflow for the fleet.
- **Code-signing-key rotation.** v1 ships with a single Windows
  code-signing cert + a single macOS Developer ID. Rotation lives
  with the broader key-rotation conversation (threat-model §8 item
  9, partially closed 2026-04-26).

## 4. Phases

### Phase A — Sign every release artifact (closes Z-6)

**A.1 — Provision the Windows code-signing cert.** EV or OV cert from
a CA Microsoft accepts (DigiCert / Sectigo / GlobalSign). Stored as
`SIGN_CERT_BASE64` + `SIGN_CERT_PASSWORD` repository secrets. The
existing scaffolding at [msi.yml:152-176](../.github/workflows/msi.yml)
becomes unconditional — drop the `if: env.SIGN_CERT != ''` guard so
unsigned builds *fail* rather than silently proceed.

Artifacts to sign with `signtool`:

- `dds-node.exe`, `dds-cli.exe`, `dds_ffi.dll`
- `DdsAuthBridge.exe`, `DdsCredentialProvider.dll`,
  `DdsPolicyAgent.exe`, `DdsTrayAgent.exe`
- The MSI itself (after binary signing and after WiX has linked it)

Timestamp every signature against
`http://timestamp.digicert.com` (or equivalent) so the signature
remains valid after the cert expires.

**A.2 — Provision the macOS Developer ID + notarization.** Apple
Developer ID Application certificate (for the binaries) + Developer
ID Installer certificate (for the `.pkg`). Stored as
`MACOS_DEVELOPER_ID_APPLICATION_P12` /
`MACOS_DEVELOPER_ID_INSTALLER_P12` + their passwords +
`APPLE_NOTARY_API_KEY` / `APPLE_NOTARY_ISSUER_ID` /
`APPLE_NOTARY_KEY_ID` repository secrets.

Add to [.github/workflows/pkg.yml](../.github/workflows/pkg.yml):

```yaml
- name: Sign macOS binaries
  run: |
    codesign --sign "$DEVELOPER_ID_APPLICATION" \
             --options runtime \
             --timestamp \
             --entitlements platform/macos/dds-node.entitlements \
             platform/macos/packaging/build/pkg-root/usr/local/bin/dds-node \
             platform/macos/packaging/build/pkg-root/usr/local/bin/dds-cli \
             platform/macos/packaging/build/pkg-root/usr/local/lib/dds/libdds_ffi.dylib

- name: Sign macOS pkg
  run: productsign --sign "$DEVELOPER_ID_INSTALLER" unsigned.pkg signed.pkg

- name: Notarize and staple
  run: |
    xcrun notarytool submit signed.pkg \
        --key "$NOTARY_KEY" --key-id "$NOTARY_KEY_ID" --issuer "$NOTARY_ISSUER" \
        --wait
    xcrun stapler staple signed.pkg
```

**A.3 — CLI / FFI binaries.** Sign them with the same cert as the
node. Publish to GitHub Releases. Attach a detached signature
(`.sig`) and SHA-256SUMS file for environments that can't run
`signtool` / `codesign`.

**A.4 — Operator verification doc.** New section in
[DDS-Admin-Guide.md](DDS-Admin-Guide.md) "Verifying a DDS release"
with the exact commands:

```powershell
signtool verify /pa /v dds-installer.msi
```

```bash
spctl --assess --verbose=4 --type install dds-installer.pkg
pkgutil --check-signature dds-installer.pkg
```

**Acceptance:** every release tarball / MSI / pkg on GitHub Releases
verifies cleanly with the stock OS tooling, including post-cert-expiry
(timestamp anchor).

### Phase B — Two-signature gate on managed software (closes Z-7)

**B.1 — Schema change. ✅ Landed 2026-04-28 follow-up #61.**
[`SoftwareAssignment`](../dds-domain/src/types.rs) gained an optional
`publisher_identity: Option<PublisherIdentity>` field with
`#[serde(default, skip_serializing_if = "Option::is_none")]` so a
pre-Phase-B publisher's CBOR wire bytes round-trip byte-identical and a
v1 agent decoding a v2 document deserialises the field as `None`. The
companion enum has two variants:

```rust
pub enum PublisherIdentity {
    Authenticode {
        subject: String,
        root_thumbprint: Option<String>, // 40 lowercase hex chars
    },
    AppleDeveloperId {
        team_id: String, // 10 uppercase alphanumerics
    },
}
```

`PublisherIdentity::validate()` enforces the field-level invariants
documented on each variant — empty / wrong-shape values would silently
match nothing on the agent and be observationally indistinguishable
from "no publisher pinning", so the schema layer fails closed instead.
The matching error type `PublisherIdentityError` is
`std::error::Error` so the Phase B.2 / B.3 trust-graph admission path
can surface a typed reason at ingest. 6 new regression tests in
[`dds-domain/tests/domain_tests.rs`](../dds-domain/tests/domain_tests.rs):
`test_software_assignment_with_authenticode_publisher_roundtrip`
(CBOR round-trip with both `subject` and `root_thumbprint` populated),
`test_software_assignment_with_apple_publisher_roundtrip`
(CBOR round-trip with a 10-char Team ID),
`test_software_assignment_legacy_cbor_decodes_as_none` (v1 wire
backward-compat), `test_publisher_identity_validate_authenticode`
(empty subject + thumbprint length / case rejected), and
`test_publisher_identity_validate_apple_team_id` (length / case /
non-alphanumeric rejected). Backward-compatible — older agents
deserialize with `publisher_identity = None` and behave as today; new
publishers opt in immediately. **Phase B.2 (Windows agent), Phase B.3
(macOS agent), and Phase B.4 (cross-platform regression tests) all
landed 2026-04-29 — see the dedicated subsections below. Phase B.5
(publisher migration cutover) remains open and is gated on Phase A
(provisioning DDS's own release-artifact code-signing certs)
shipping first.**

**B.1 follow-on — node-side fail-closed at agent read path. Landed
2026-04-29.** [`LocalService::list_applicable_software`](../dds-node/src/service.rs)
now calls `PublisherIdentity::validate()` on every decoded
`SoftwareAssignment` and *skips* (warn-log + `continue`) any
assignment whose publisher metadata fails the schema-layer invariants
(empty Authenticode subject, wrong-shape SHA-1 root thumbprint,
malformed Apple Team ID). Without this gate a malformed
`publisher_identity` would ride all the way to the C# agent, the
signer-subject string compare would fail to match anything real, and
the agent would fall through to hash-only — observationally identical
to "no publisher pinning". One new regression test
(`b1_software_with_invalid_publisher_identity_is_skipped`) seeds two
attestations (one with empty Authenticode subject, one with a valid
Apple Team ID) and asserts only the valid one reaches the read path.

**B.1 follow-on — ingest-time fail-closed at gossip + sync. Landed
2026-04-29.** The read-path filter (above) still admitted the rogue
token into the trust graph and let it propagate to peers whose
serve-time filters might be older or patched differently — the same
defence-in-depth gap C-3 plugged for `publisher_capability`. The new
private helper
[`software_publisher_identity_ok`](../dds-node/src/node.rs) runs
`PublisherIdentity::validate()` at both ingest call sites:

- **Gossip ingest** —
  [`DdsNode::ingest_operation`](../dds-node/src/node.rs) calls the
  helper immediately after the existing C-3
  `publisher_capability_ok` gate; a malformed publisher_identity
  emits a `*.rejected` audit entry with reason
  `publisher-identity-invalid` and the token is dropped before the
  trust graph is consulted.
- **Sync apply** —
  [`DdsNode::handle_sync_response`](../dds-node/src/node.rs) calls
  the helper from the pre-apply `filter` closure; rejections bump
  the new `dds_sync_payloads_rejected_total{reason="publisher_identity"}`
  bucket alongside the existing `legacy_v1` /
  `publisher_capability` / `replay_window` pre-apply reasons.

The helper short-circuits on non-Attest tokens (revoke / burn /
vouch), on Attest tokens that don't carry a `SoftwareAssignment`
body (e.g. `WindowsPolicyDocument`, `MacOsPolicyDocument`), on tokens
with no body at all, and on CBOR decode failures (those surface
separately through `SyncResult::errors` and the existing per-token
validation guard at the top of `ingest_operation`). 10 new unit
tests in
[`dds-node/src/node.rs`](../dds-node/src/node.rs)
`publisher_identity_gate_tests` cover the helper surface: valid
Authenticode + thumbprint accepted, valid Apple Team ID accepted, no
publisher_identity accepted (legacy v1 publishers), empty
Authenticode subject rejected, malformed (uppercase) root_thumbprint
rejected, malformed (lowercase) Apple Team ID rejected, non-Attest
tokens admitted unconditionally, Attest tokens with no body
admitted, Attest tokens carrying a non-software body admitted, and
torn-CBOR `SoftwareAssignment` bodies admitted. The telemetry
catalog in [`dds-node/src/telemetry.rs`](../dds-node/src/telemetry.rs)
and the `# HELP` text on the renderer were extended to document the
new `publisher_identity` reason bucket alongside the existing
pre-apply reasons.

**B.2 — Windows agent. ✅ Landed 2026-04-29.**
The signature gate now lives in
[`SoftwareInstaller.ApplyInstallAsync`](../platform/windows/DdsPolicyAgent/Enforcers/SoftwareInstaller.cs)
between the SHA-256 verify and the `InstallMsi`/`InstallExe` launch
(within the B-6 size+mtime re-check window). It runs whenever
**either** `AgentConfig.RequirePackageSignature` is `true` **or**
the directive carries `publisher_identity` — flipping
`RequirePackageSignature` off cannot silently downgrade a
pinned-publisher assignment to hash-only, mirroring the macOS
Phase B.3 behaviour.

Three new helpers compose the gate:

- [`PublisherIdentitySpec`](../platform/windows/DdsPolicyAgent/Enforcers/PublisherIdentity.cs)
  parses the directive's externally-tagged enum
  (`{"Authenticode": {...}}` / `{"AppleDeveloperId": {...}}`) and
  fail-closes on malformed shape (unknown variant, empty subject,
  wrong-shape root thumbprint, wrong-shape Team ID, multiple variant
  tags). Mirrors the Rust `PublisherIdentity::validate` invariants
  exactly: 40 lowercase hex chars for the SHA-1 thumbprint and
  10 uppercase alphanumerics for the Apple Team ID.
- [`IAuthenticodeVerifier`](../platform/windows/DdsPolicyAgent/Enforcers/IAuthenticodeVerifier.cs) —
  thin abstraction over `WinVerifyTrust` so the gate can be
  unit-tested on non-Windows hosts. Returns
  `AuthenticodeVerifyResult { IsValid, SignerSubject,
  RootThumbprintSha1Hex, Reason }`.
- [`WinTrustAuthenticodeVerifier`](../platform/windows/DdsPolicyAgent/Enforcers/WinTrustAuthenticodeVerifier.cs) —
  Windows production implementation. Calls
  `WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` for chain
  trust (revocation + system root) plus `X509Certificate2` +
  `X509Chain` for signer-subject and chain-root SHA-1 thumbprint
  extraction. The two calls share the same on-disk staged file
  inside the SYSTEM-only DACL (B-6) so a TOCTOU swap can't inject
  between verify and launch.
  [`StubAuthenticodeVerifier`](../platform/windows/DdsPolicyAgent/Enforcers/StubAuthenticodeVerifier.cs)
  registered on non-Windows builds fail-closes any directive that
  requires a signature so dev/test hosts cannot accidentally
  short-circuit the gate.

The gate enforces three pinning levels in order:

1. `RequirePackageSignature` only → `WinVerifyTrust` must succeed.
2. `Authenticode { subject }` set → also exact-match
   `CertGetNameString(CERT_NAME_SIMPLE_DISPLAY_TYPE)` against
   `subject` (case-sensitive ordinal, mirroring the macOS Team-ID
   match).
3. `Authenticode { subject, root_thumbprint }` set → also exact-match
   the chain-root SHA-1 thumbprint against the 40-lowercase-hex
   value in the directive.

An `AppleDeveloperId` `publisher_identity` on a Windows scope is
rejected as a configuration error (the policy author scoped a
macOS-only signer expectation onto a Windows device) before the
verifier is ever called. A malformed `publisher_identity` fails
*before* the download so a directive that can never satisfy the
gate does not burn bandwidth.

[`AgentConfig`](../platform/windows/DdsPolicyAgent/Config/AgentConfig.cs)
gained `RequirePackageSignature: bool` (default `true`) — the
`Program.cs` DI wiring registers `WinTrustAuthenticodeVerifier` on
Windows and `StubAuthenticodeVerifier` on other hosts. The
`SoftwareInstaller` constructor was extended to accept
`IAuthenticodeVerifier` + `IOptions<AgentConfig>`; a back-compat
overload kept the legacy `(ops, log)` constructor working with
`RequirePackageSignature = false` + the stub verifier, so existing
tests that pre-date Phase B.2 still compile unchanged.

29 new regression tests in
[`platform/windows/DdsPolicyAgent.Tests/SoftwareInstallerSignatureGateTests.cs`](../platform/windows/DdsPolicyAgent.Tests/SoftwareInstallerSignatureGateTests.cs)
cover the parser surface (PublisherIdentitySpec — absent / null /
empty-object / two-variants / unknown-variant / malformed-thumbprint /
malformed-team-id / round-trip both variants), the stub verifier
contract, and the integration paths: matching subject proceeds,
mismatched subject fails closed, unsigned-when-required fails closed,
unsigned-when-publisher_identity-set-even-if-require-off still gates,
neither-required-nor-pinned skips the gate (verifier MUST NOT be
called), AppleDeveloperId-on-Windows fails closed without calling
the verifier, missing / mismatched / matching root-thumbprint paths,
and the malformed-publisher_identity-fails-before-download path.
174 / 174 Windows .NET tests passing (was 145).

**B.3 — macOS agent. ✅ Landed 2026-04-29.**
[`SoftwareInstaller`](../platform/macos/DdsPolicyAgent/Enforcers/SoftwareInstaller.cs)
now routes the `pkgutil --check-signature` call through a private
`EnforcePackageSignature` helper that captures stdout, refuses on a
non-zero exit, and — when the directive carries
`publisher_identity = AppleDeveloperId { team_id }` — pins the leaf-cert
Team ID against the expected value via the new
[`PkgutilSignatureParser`](../platform/macos/DdsPolicyAgent/Enforcers/PkgutilSignatureParser.cs)
(regex on the indented `N. <subject-with-colon> (XXXXXXXXXX)` leaf-cert
shape). The directive's `publisher_identity` field is parsed by the new
[`PublisherIdentitySpec`](../platform/macos/DdsPolicyAgent/Enforcers/PublisherIdentity.cs)
helper that mirrors the Rust externally-tagged enum (`{"AppleDeveloperId":
{"team_id": "..."}}` / `{"Authenticode": {"subject": "..."}}`) and
fail-closes on malformed shape (unknown variant, wrong-shape Team ID, etc.).
The signature gate now runs whenever **either** `RequirePackageSignature`
is true **or** `publisher_identity` is set on the directive — so an
operator who explicitly turned `RequirePackageSignature` off can still
not silently downgrade a Team-ID-pinned assignment to hash-only. An
`Authenticode` `publisher_identity` on a macOS scope is rejected as a
configuration error (the policy author scoped a Windows-only signer
expectation onto a macOS device). 14 new regression tests in
[`platform/macos/DdsPolicyAgent.Tests/EnforcerTests.cs`](../platform/macos/DdsPolicyAgent.Tests/EnforcerTests.cs)
cover the parser (PublisherIdentitySpec, PkgutilSignatureParser) and the
six integration paths: matching Team ID proceeds past the gate, Team ID
mismatch fails closed, unsigned pkg fails closed, signed-but-not-Developer-ID
pkg fails closed, Authenticode-on-macOS fails closed, and the
`RequirePackageSignature=false`-but-`publisher_identity`-set
backward-compat angle. 91 / 91 macOS .NET tests passing (was 77).

**B.4 — Tests. ✅ Landed 2026-04-29.** The cross-platform regression
matrix is now mirrored bilaterally on Windows
[`SoftwareInstallerSignatureGateTests`](../platform/windows/DdsPolicyAgent.Tests/SoftwareInstallerSignatureGateTests.cs)
and macOS
[`EnforcerTests`](../platform/macos/DdsPolicyAgent.Tests/EnforcerTests.cs):

| Spec test | Windows (`phase_b2_*`) | macOS (`phase_b3_*`) |
|---|---|---|
| `…rejects_unsigned_blob_when_required` | `rejects_unsigned_when_required` | `rejects_unsigned_pkg_when_publisher_identity_set` |
| `…rejects_wrong_signer_subject` | `rejects_mismatched_subject` | `rejects_mismatched_team_id` |
| `…accepts_signed_blob_with_no_publisher_identity_directive` | `accepts_signed_blob_with_no_publisher_identity_directive` (new 2026-04-29) | `accepts_signed_blob_with_no_publisher_identity_directive` (new 2026-04-29) |
| `…rejects_unsigned_blob_when_publisher_identity_set_even_if_require_off` | `rejects_unsigned_when_publisher_identity_set_even_if_require_off` | `signature_check_runs_when_publisher_identity_set_even_if_require_off` |

The 2026-04-29 follow-on closes the **legacy hash + sig backward-compat
path**, which was previously uncovered: the existing "matching subject"
/ "matching team_id" tests both pinned a publisher, and the existing
"neither require nor pin" test had `RequirePackageSignature=false`. A
future regression that always required `publisher_identity` alongside
`RequirePackageSignature` would silently break pre-Phase-B publishers
during the migration window without these assertions. Result counts:
30 / 30 Phase B.2 Windows signature-gate tests passing (was 29 / 29) +
175 total Windows .NET tests passing on the macOS dev host (was 174;
the 39 skipped tests are Windows-host-only); 92 / 92 macOS .NET tests
passing (was 91 / 91).

**B.5 — Migration plan.** v2 cutover date: 30 days after Phase A
ships. Past that date, publishers shipping `SoftwareAssignment`
without `publisher_identity` get a warn-log on every endpoint apply;
60 days, hard-fail. The grace window stays for one release cycle so
nobody is surprised.

**Acceptance:** Windows endpoint refuses an unsigned-but-correctly-
hashed `.msi` when `publisher_identity` is set on the document; macOS
behaves the same with `pkgutil --check-signature`. Two-signature gate
is enforced: an attacker who compromises a publisher's pipeline AND
has the publisher's admin DDS key still cannot install on an endpoint
unless they also hold an OS-vendor-trusted code-signing cert.

### Phase C — Provenance & SBOM (partial Z-8)

**C.1 — SLSA Level 3 provenance. ✅ Landed 2026-05-02.** Added
`provenance` jobs calling
`slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`
to [`.github/workflows/msi.yml`](../.github/workflows/msi.yml) and
[`.github/workflows/pkg.yml`](../.github/workflows/pkg.yml), and
created a new [`.github/workflows/cli.yml`](../.github/workflows/cli.yml)
that builds the standalone `dds` CLI for Linux (x86_64), macOS (arm64 +
x86_64), and Windows (x86_64) with matching SLSA provenance. For the matrix
`pkg.yml` build a `collect-hashes` job downloads all platform `.pkg`
artifacts after both matrix legs complete and emits a single combined
`base64-subjects` string. On tag pushes the `.intoto.jsonl` attestation
files are uploaded as release assets alongside the binaries.
Operators can verify with:
```
slsa-verifier verify-artifact dds-linux-x86_64 \
  --provenance-path dds-linux-x86_64.intoto.jsonl \
  --source-uri github.com/<org>/<repo>
```
Closes Z-7/Z-8 supply-chain Phase C.1 acceptance criteria ("every released
artifact has a verifiable in-toto provenance attestation").

**C.2 — SBOM. ✅ Landed 2026-05-02.** A new `sbom` job in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) installs
`cargo-cyclonedx` via `taiki-e/install-action@v2` and runs
`cargo cyclonedx --format json --all` on every PR and push to `main`.
The resulting `*.cdx.json` files are uploaded as the `sbom-cyclonedx`
workflow artifact via `actions/upload-artifact@v4`. The release workflow
can attach these alongside the MSI / pkg binaries by downloading the
artifact and including them in the GitHub Release body. Generates
one CycloneDX JSON SBOM per crate in the workspace, capturing all
transitive Cargo dependencies with their versions and source hashes.

**C.3 — `cargo-vet` baseline.** Adopt
[`cargo-vet`](https://github.com/mozilla/cargo-vet); commit the
initial audit set. CI fails if a new dependency or upgraded version
lacks an audit. Mozilla's public audit set covers most common crates;
DDS-specific audits commit under `supply-chain/audits.toml`.

**C.4 — `cargo audit` in CI. ✅ Landed 2026-04-29.**
The new `audit` job in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) installs
[`cargo-audit`](https://github.com/rustsec/rustsec) via
`taiki-e/install-action@v2` and runs `cargo audit` on every PR and
every push to `main`. Default behaviour: exit non-zero on any RUSTSEC
*vulnerability* advisory; informational warnings (unmaintained /
unsound / yanked) surface in the build log but do not block. The
eight currently-tracked warnings are upstream-blocked transitive
dependencies documented in [`security-gaps.md`](../security-gaps.md)
"Dependency Audit Gap" — once those clear, graduate the step to
`cargo audit -D warnings` so a fresh advisory immediately surfaces a
PR. Closes the dependency-audit gap originally flagged in the
2026-04-12 security-gaps doc and confirms in CI what the
2026-04-28 manual `cargo audit` run validated locally
(0 vulnerabilities post-`rustls-webpki` 0.103.10 → 0.103.13 bump).

**C.5 — Sigstore signing.** Optional sweetener: `cosign sign-blob`
the release artifacts with a Sigstore Fulcio identity (workflow OIDC).
Operators can verify with `cosign verify-blob` and a transparency-log
proof. Lower priority than A.1/A.2 but a strict superset on the
audit-trail side.

**Acceptance:** every released artifact has a verifiable in-toto
provenance attestation; CI rejects builds with un-audited dependency
versions; SBOMs are linkable from the release page.

### Phase D — Fleet self-update (operational Z-8)

This is the largest piece. Two design tensions:

- **A signed update from a single admin should not be enough to
  ship code to every node.** A self-update document is the
  most-privileged document in the system — code execution at
  `LocalSystem` / `root` on every host. Single-key signing repeats
  the AD "domain admin compromise" failure mode the rest of DDS is
  built to avoid.
- **Operators need a usable update flow.** Multi-sig with high N
  becomes operationally toxic.

The proposed envelope:

**D.1 — New document type:** `DdsSelfUpdateDocument` (separate from
`SoftwareAssignment` deliberately — the capability gate, the staging
behaviour, and the trust model are different).

```rust
pub struct DdsSelfUpdateDocument {
    pub channel: ReleaseChannel,         // Stable | Beta | Canary
    pub version: SemVer,
    pub artifacts: Vec<UpdateArtifact>,  // per-platform: msi, pkg, …
    pub min_supported_from: SemVer,      // refuse to update from < this
    pub rollout: RolloutPolicy,          // see D.3
    pub provenance: ProvenanceRef,       // SLSA attestation URL + sha256
}

pub struct UpdateArtifact {
    pub platform: Platform,              // win-x64, win-arm64, macos-x64, macos-arm64
    pub url: String,
    pub sha256: [u8; 32],
    pub publisher_identity: PublisherIdentity,  // OS-vendor signer (Phase B)
}
```

**D.2 — Multi-sig admission.** A `DdsSelfUpdateDocument` is admitted
into the trust graph **only** when it carries `K` distinct admin
signatures, where:

- `K = max(2, ceil(M / 2))` and `M` is the count of admins in the
  graph at the time of admission.
- Signatures must come from admins holding a new dedicated capability
  `dds:dds-self-update-publisher` (NOT the regular
  `dds:software-publisher` — those are separated by design so a
  publisher key for third-party apps cannot be repurposed to ship
  code to every node).
- Admins ideally hold their key on hardware (Z-2 plan) — in v1 we
  enforce multi-sig as the compensating control until Z-2 lands.

The verification logic lives in `dds-core::trust::add_token` next
to the existing publisher-capability filter.

**D.3 — Staged rollout.** `RolloutPolicy`:

```rust
pub enum RolloutPolicy {
    Pinned { allow_versions: Vec<SemVer> },   // strictly opt-in per node
    Staged {
        canary_pct: u8,    // 0..100, e.g. 5
        canary_min_age_hours: u32,   // soak before promoting
        promote_to_full_after: Duration,
        halt_on_health_regression: bool,
    },
    Halt,                                     // emergency lever
}
```

Each node decides whether *it* is in the canary cohort by hashing its
own `PeerId` + the document JTI mod 100 against `canary_pct`. No
central coordinator. The cohort therefore re-randomizes on every
update — a node is not permanently in the canary.

**D.4 — Self-update apply path.** On a node that decides to apply:

1. Fetch the artifact at `UpdateArtifact.url`.
2. Verify SHA-256 in streaming fashion (mirror Phase B / B-6).
3. Verify the OS-vendor signature on the blob (Phase B's
   `WinVerifyTrust` / `pkgutil`).
4. Stage to the SYSTEM-only DACL cache.
5. Run the platform-native installer with `/quiet` (Windows) or
   `installer -pkg` (macOS).
6. The installer writes the new binaries; the existing service
   manager (Windows SCM / launchd) restarts them.
7. After restart, the new node emits an `audit.action = self.update`
   entry (Phase A in
   [observability-plan.md](observability-plan.md)) with the prior
   and new versions and the document JTI.

**D.5 — Halt & rollback.** A `Halt` rollout published with the same
multi-sig requirement supersedes any pending update. Rollback is a
`DdsSelfUpdateDocument` with a lower `version` field — admins
explicitly approve the downgrade with the same multi-sig.

**D.6 — Non-self-update path.** For air-gapped / regulated deployments
that must keep their own change-control pipeline, the document
*type* can be deserialized but the apply step is gated by a node
config flag `self_update_apply = false` (default `true`). Such nodes
log "self-update available, apply disabled by config" and continue
running the installed version.

**Acceptance:** a single admin key compromise produces no installable
self-update document on any node, because the trust graph rejects the
document for missing the K-th signature. A multi-sig-approved canary
update reaches ~5% of the fleet within the canary window, and the
remainder only after the soak elapses without health regressions.

## 5. Tradeoffs

- **Phase A introduces hard dependencies on commercial code-signing
  certs.** Buying and rotating an EV cert plus an Apple Developer ID
  is real operational cost. Worth it for any pilot beyond a single
  team. For pre-pilot demos we ship signed-by-self-cert with a
  documented "verify with this fingerprint" workaround — not for
  customer use.
- **Phase B gracefully degrades for legacy publishers** (the
  `Option<PublisherIdentity>` field). The grace window risk is that
  a slow publisher migration leaves Windows endpoints with the
  hash-only check past the cutover date; the warn-then-fail timeline
  in B.5 puts pressure on this.
- **Phase D's multi-sig requires K admins to coordinate.** That's
  a feature, not a bug — exactly the class of compromise we're
  defending against. The runbook needs a documented "rotate one of
  the K admins offline" procedure so the K-of-M floor doesn't
  become an availability risk.
- **Z-2 (HW-bound identity) is a force multiplier here, not a
  prerequisite.** Phase D works with software-resident admin keys —
  but the per-key compromise probability drops sharply once Z-2
  binds those keys to hardware. The plans should land in either
  order.

## 6. Out of scope (explicit follow-ups)

- Bit-reproducible builds (covered in non-goals).
- Sigstore as the primary signing root (Phase C.5 ships it as a
  defense-in-depth layer, not a replacement for OS-vendor signing).
- DDS-as-deb / DDS-as-Homebrew distribution channels.
- Multi-domain self-update fanout. Each domain has its own admins;
  a shared self-update across domains is not a v1 concept.
- Cryptographic transparency log of releases (Sigstore Rekor gives
  this for free in Phase C.5; an in-domain version is a v2 idea).

## 7. Definition of done

- Fresh release passes `signtool verify /pa /v` on Windows and
  `spctl --assess --type install` on macOS.
- Endpoint refuses to install a `SoftwareAssignment` whose declared
  `publisher_identity` does not match the package signer subject.
- A node running `dds-cli stats` (from
  [observability-plan.md](observability-plan.md)) reports its
  installed version and the most-recently-applied
  `DdsSelfUpdateDocument` JTI.
- A canary `DdsSelfUpdateDocument` published with K-of-M signatures
  reaches the configured canary percentage within one polling cycle
  and the remainder of the fleet within the soak window.
- A single-admin-signed self-update document is rejected at trust-
  graph ingest with a regression test pinning the rejection.
- An expired code-signing cert with a valid timestamp still
  verifies — pinned by an integration test running against an
  artifact built with a now-expired test cert.

## 8. Cross-references

- [Claude_sec_review.md](../Claude_sec_review.md) Z-6 / Z-7 / Z-8 —
  closed by Phases A / B / (C+D).
- [docs/threat-model-review.md](threat-model-review.md) §3 (Windows
  ACL gap, "Authenticode signing in CI once cert is provisioned")
  — promoted from "pending" to a tracked Phase A.
- [docs/AD-drop-in-replacement-roadmap.md](AD-drop-in-replacement-roadmap.md)
  — the fleet-update story this plan supplies is the operational
  half of "DDS as a usable AD replacement"; pairs with the
  observability plan's monitoring coverage.
- [docs/hardware-bound-admission-plan.md](hardware-bound-admission-plan.md)
  Z-2 — Phase D's multi-sig is the v1 compensating control until
  hardware binding lands; with Z-2 in place the per-key
  compromise probability drops and the multi-sig K could
  reasonably relax.
- [docs/observability-plan.md](observability-plan.md) — Phase D's
  `audit.action = self.update` event is registered in the audit
  vocabulary defined there.
