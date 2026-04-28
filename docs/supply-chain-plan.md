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
publishers opt in immediately. **Phase B.2 / B.3 (the C# agent
verifiers) and B.4 / B.5 (cross-platform regression tests + migration
plan) remain open.**

**B.2 — Windows agent.** Add `WinVerifyTrust` invocation in
`WindowsSoftwareOperations.DownloadAndVerifyAsync` after the
SHA-256 check and before `Process.Start` (the same window B-6
hardened with size+mtime re-check):

```csharp
// New, after existing hash check:
if (config.RequirePackageSignature || directive.PublisherIdentity is not null)
{
    var result = WinTrust.VerifyAuthenticode(packagePath);
    if (!result.IsValid) throw new InvalidOperationException(
        $"Authenticode verify failed for '{packageId}': {result.Reason}");
    if (directive.PublisherIdentity is { } expected
        && !SubjectMatches(result.SignerSubject, expected))
        throw new InvalidOperationException(
            $"Authenticode signer mismatch for '{packageId}': " +
            $"expected '{expected.Subject}', got '{result.SignerSubject}'");
}
```

`WinTrust.VerifyAuthenticode` is a thin C# wrapper over
`WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)` plus
`CertGetNameString` to extract the signer subject. The check happens
on the staged file inside the SYSTEM-only DACL (B-6) so a TOCTOU
swap can't inject between verify and launch.

**B.3 — macOS agent.** `_config.RequirePackageSignature` defaults to
**true** (was false). The existing
[SoftwareInstaller.cs:134-137](../platform/macos/DdsPolicyAgent/Enforcers/SoftwareInstaller.cs)
call becomes mandatory. Add Team ID extraction + match against
`PublisherIdentity::AppleDeveloperId` when the document specifies it.

**B.4 — Tests.** Cross-platform regression tests:

- `software_install_rejects_unsigned_blob_when_required`
- `software_install_rejects_wrong_signer_subject`
- `software_install_accepts_signed_blob_with_no_publisher_identity_directive`
  (legacy hash-only backward compat)
- `software_install_rejects_unsigned_blob_when_publisher_identity_set_even_if_require_off`

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

**C.1 — SLSA Level 3 provenance.** Use the
[slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator)
to attach an in-toto provenance attestation to every artifact in
`msi.yml`, `pkg.yml`, and a new `cli.yml` (currently the CLI is
built inside `msi.yml` only). The provenance records the source
commit, build environment, builder identity, and material hashes.

**C.2 — SBOM.** Generate a CycloneDX SBOM with
[cargo-cyclonedx](https://github.com/CycloneDX/cyclonedx-rust-cargo)
during the build job. Publish alongside the binary on the GitHub
Release page.

**C.3 — `cargo-vet` baseline.** Adopt
[`cargo-vet`](https://github.com/mozilla/cargo-vet); commit the
initial audit set. CI fails if a new dependency or upgraded version
lacks an audit. Mozilla's public audit set covers most common crates;
DDS-specific audits commit under `supply-chain/audits.toml`.

**C.4 — `cargo audit` in CI.** Run
[`cargo-audit`](https://github.com/rustsec/rustsec) on every PR and
every release; fail the build on any RUSTSEC advisory above a
configured severity threshold. (The 2026-04-12 security-gaps doc
already flagged the dependency-audit gap as an open operational item;
this closes it.)

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
