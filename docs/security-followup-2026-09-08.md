# Follow-up security review of the 2026-09-07 remediation — implementation record (2026-09-08)

The follow-up review below was received on 2026-09-08 against `4ed0f4a` (the docs commit
that closed out the first review's F1-F4 remediation). It found all four original findings
genuinely fixed, plus four residual/newly-introduced issues (S1-S4) and one interoperability
defect (R1) in the fix code itself. Every finding was verified against the source, then
implemented, then independently adversarially verified by a second agent, before being
integrated here.

| ID | Follow-up severity | Verified | Fix |
|---|---|---|---|
| S1 | Medium | Confirmed, both Linux and Windows | `fix(policy): ... require Enforce for account claims (S1)` |
| S2 | Medium (root cause of S1) | Confirmed, all three platforms | `fix(policy): run supersession before Disabled/scope filtering (S2)` |
| S3 | Medium | Confirmed; hardened further during integration | `fix(auth): a vouched attestation wins credential lookup over an earlier-sorting duplicate (S3)` |
| S4 | Medium | Confirmed | `fix(device-binding): quarantine pre-S4 device bindings until an admin re-provisions them (S4)` |
| R1 | Medium (availability) | Confirmed | `fix(pam): unwrap the CBOR byte-string header fido2-assert wraps authenticatorData in (R1)` |

**S1/S2 were fixed together** (S2 is S1's root cause) in one commit, since both are the
same restructuring of `list_applicable_{windows,macos,linux}_policies`: publisher-capability
and revoked/burned checks still run early, but `Enforcement::Disabled` and `scope_matches`
filtering now run *after* `supersede_*_policies` picks the true current revision per
`policy_id`, not before. `linux_account_subjects` and `resolve_windows_account_claim` (the
latter found independently while fixing S1, not named in the review's own evidence — its
result is handed straight to `NetUserAdd` with no other enforcement gate) both now require
`Enforcement::Enforce` before a login/claim mapping is honored. Audit-mode documents
correctly remain visible from the `list_applicable_*` functions themselves (an existing,
still-passing test, `windows_policy_audit_documents_are_returned`, pins that on purpose —
the agent decides to log, not enforce; only the account-claim/login resolvers gained the
Enforce requirement). New regression tests cover Disabled-v2-retires-Enforce-v1 and
narrowed-scope-v2-retires-v1 on all three platforms (Windows, macOS, Linux), plus the
Audit-mapping-denied/Enforce-mapping-allowed pair for both the Linux login and Windows
claim paths.

**S3 was hardened beyond the review's own fix guidance during integration.** The first
implementation (independently verified as CONFIRMED_FIXED against the letter of the
finding) collected every self-issued attestation matching a requested `credential_id` and
selected the vouched one — closing the shadow/DoS lockout the finding described — but did
so by re-parsing every candidate's attestation object (a real CBOR decode + signature
verification) *before* selection ran. Since any admitted peer can self-issue an unlimited
number of user-auth attestations for an arbitrary `credential_id` (no publisher-capability
gate applies to this body type), that traded S3's hard lockout for an attacker-sized
CPU-amplification cost per assertion attempt, and a single malformed decoy could hard-fail
the whole lookup via `?` even when a legitimate vouched candidate also matched. An
adversarial verify pass flagged exactly this. The integrated fix defers the one real
`verify_attestation` call to only the already-selected winner; a new test
(`malformed_unvouched_decoy_credential_cannot_deny_service_to_the_vouched_owner`) proves a
malformed decoy can no longer deny service to the vouched owner.

**Method.** Four fixes were implemented in parallel, each in its own isolated git worktree
branched from `4ed0f4a`, then each independently reviewed by a second, adversarial agent
instructed to try to refute the fix rather than confirm it. All four implementations were
confirmed correct against their findings; the S3 hardening above and two macOS-parity
regression tests for S2 (flagged as a non-blocking coverage gap by both the implementer and
the verifier — `list_applicable_macos_policies` received the identical restructuring but
initially lacked the Windows/Linux pair's direct supersession-ordering tests) were added
during integration before these fixes were committed to `main`.

**Two non-blocking notes from the adversarial verify pass, not acted on:**
- S3's "more than one vouched candidate" tie-break (smallest jti) has no dedicated test —
  the finding itself calls this an edge case that "should not normally happen" and only
  requires determinism, which the code provides; a reviewer wanting full line coverage on
  that specific branch would need to add a two-admin-double-vouch fixture.
- S4's admin endpoint (`POST /v1/admin/device-binding`) still returns `Established` rather
  than a distinct outcome for "replaced a legacy pre-S4 entry" vs. "bound a fresh URN" — an
  operator reading the HTTP response alone cannot tell those apart, though the `tracing::warn!`
  log line does. `verification` reasoning judged this cosmetic, not blocking.

Verification: see this branch's own commit messages for the exact `cargo test`/`clippy`/
`fmt` output each fix was checked against, and STATUS.md for the final combined-suite
numbers this record was published alongside.

---

# ABCD security follow-up — 8 September 2026

The five commits since the original review address all four reported issues, but remediation is incomplete for upgrades and Linux login. F1’s identity impersonation and F3’s use of sessions after loss of authorization are fixed in the reviewed source. F2 prevents new unauthorized device bindings but retains bindings created before the fix. F4 adds account-specific authorization, with policy-selection and authenticator-format problems remaining.

**The fixes have not reached the latest published release.** GitHub’s latest release is [v1.6.3](https://github.com/pkolarov/ABCD/releases/tag/v1.6.3), published on 7 September at 06:33 UTC. Its annotated tag resolves to the original reviewed commit, `ecd8a977a20b11ae9cd8701d22b255d99853fb6c`. The fixes landed later that day. Installing that release does not install these fixes.

**Scope and verification**

Compared baseline `ecd8a977a20b11ae9cd8701d22b255d99853fb6c` with current main `4ed0f4a9aef1faba472c5bb14051e0619acd1ff0`: five commits, 34 changed files. Reviewed the changed authentication, trust, device-binding, HTTP, and PAM paths, including their policy-selection dependencies and regression tests. [Complete comparison](https://github.com/pkolarov/ABCD/compare/ecd8a977a20b11ae9cd8701d22b255d99853fb6c...4ed0f4a9aef1faba472c5bb14051e0619acd1ff0).

GitHub reported 43 successful and 13 skipped checks for this head, with no failed checks. I inspected the actual [cargo test log](https://github.com/pkolarov/ABCD/actions/runs/34144799514/job/101814377846): the new forged-attestation, pinned-enrollment, unbound-device, revoked/burned-session, and mapped-Linux-account regressions passed. The node unit suite reported 470 passed. Cargo audit, cargo vet, and the Linux .NET policy-agent check also succeeded.

Rust/Cargo and .NET are unavailable in this review environment, so I did not independently rerun those suites. The findings below are based on source inspection; they are not demonstrations against a running deployment. A small independent cryptographic format probe supports the PAM interoperability finding. No hardware-backed PAM or Windows logon test was performed. This is a focused follow-up, not an exhaustive new audit of the entire repository.

**Status of the original findings**

| Finding | Commit | Assessment on current main |
|---|---|---|
| F1: forged user-auth attestation impersonates another identity | [2909fae](https://github.com/pkolarov/ABCD/commit/2909faeae5af6132fb31e1cd5aee332f0abeab42) | Fixed for the reported impersonation path. Ingest and lookup require self-issued user-auth attestations; session issuance requires an effective vouch that pins the exact enrollment. A separate credential-shadowing availability issue remains below. |
| F2: first local caller claims an arbitrary device URN | [aedac3f](https://github.com/pkolarov/ABCD/commit/aedac3f0c3969aaa86df082c6f34e519d0035e77) | Fixed for new bindings. Non-admin callers receive 403 for unbound devices; administrators provision bindings explicitly. Existing unauthorized bindings survive an upgrade. |
| F3: revoked/burned identity uses an unexpired session for account claims | [bf145cb](https://github.com/pkolarov/ABCD/commit/bf145cb9213eb5d930fdd639725927b9f4e285a7) | Fixed for the reported scenario. Account claims recheck live authorization and reject burned identities or subjects without active grants. |
| F4: PAM accepts a session without binding it to the requested Unix account | [f457945](https://github.com/pkolarov/ABCD/commit/f457945f63c13c3bd1cbf1ecfe5c4ffde83313e7) | Original missing-account check is fixed. The node now requires an explicit subject/account mapping, and the helper/module check the returned username. Remaining policy and collection problems prevent treating the Linux flow as complete. |

**S1 — Audit-only policy can grant real Linux login access**

Severity: **Medium**, potentially higher when a privileged existing account is mapped. Newly introduced in the F4 authorization path. High confidence in the code path; runtime exploitability depends on a working PAM integration and the surrounding PAM stack.

`linux_account_subjects` accepts Create, Modify, and Enable mappings from every applicable Linux policy without checking its enforcement mode. The upstream policy query excludes Disabled documents but retains Audit documents. Audit means “log violations but don't enforce” in the domain model, and the Linux agent treats it as a dry run. Consequently an Audit directive mapping a vouched identity to an existing account can satisfy real account authorization. The user needs a valid session, and an authorized publisher must have authored the audit mapping; this is not arbitrary account access without a mapping.

Evidence: [mapping and authorization](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/service.rs#L2133-L2253), [policy filtering](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/service.rs#L1915-L1965), [enforcement semantics](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-domain/src/types.rs#L143-L152).

Fix: require Enforce when deriving login grants. Audit may report that a login would be allowed, but must not authorize it. Add a regression using an existing account, a valid vouched subject, and only an Audit mapping: authorization must fail, then succeed when switched to Enforce.

**S2 — A Disabled revision can leave an older policy effective**

Severity: **Medium**. Pre-existing policy-selection issue, newly relevant to the added Linux login authorization.

The policy query removes Disabled documents before selecting the highest version for a policy ID. If version 1 is Enforce and version 2 is Disabled, version 2 is discarded and version 1 remains the winner, provided the older token has not separately been revoked or expired. A login mapping from version 1 therefore remains available to the new authorization path. The Windows and macOS policy queries use the same filtering order. Scope filtering before version selection creates a related stale-policy risk when a newer revision narrows scope.

Evidence: [Linux filtering before supersession](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/service.rs#L1927-L1965), [version selection](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/service.rs#L4084-L4122), [corresponding platform queries](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/service.rs#L1798-L1910).

Fix: after validating publisher authority and token validity, select the authoritative current revision, then evaluate its enforcement and scope. Preserve a Disabled revision’s ability to supersede an older active revision. Test Enforce-v1 followed by Disabled-v2 with both tokens present, including denial of a formerly mapped Linux login. The existing standalone Disabled test does not exercise this sequence.

**S3 — An unvouched duplicate credential can block legitimate authentication**

Severity: **Medium**. Newly identified residual availability issue in the F1 area; the first-match behavior predates these commits.

Credential lookup walks attestations in JTI order and stops at the first matching credential ID. It skips non-self-issued tokens, but does not check the selected enrollment’s vouch until after signature verification. An admitted malicious peer able to publish its own self-issued user-auth token can copy a victim’s visible credential/attestation data under its own identity and choose an earlier-sorting JTI. The duplicate can then be selected instead of the legitimate enrollment. Even with the victim’s correct assertion, session creation fails because the selected enrollment has no effective vouch. The legitimate matching entry is never tried.

This requires access to the replicated credential record and an accepted publication path. It does not restore the original victim impersonation vulnerability: the new pin check prevents the unauthorized session, but permits denial of service against the legitimate credential.

Evidence: [first-match lookup and break](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/service.rs#L2363-L2432), [later vouch check](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/service.rs#L2630-L2655), [JTI-keyed storage](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-core/src/trust.rs#L29-L34).

Fix: resolve session credentials from currently authorized, exactly pinned enrollments before committing to a matching entry. Handle ambiguity among authorized entries explicitly. Merely rejecting every duplicate lets an unvouched token retain the same denial-of-service power. Add a test where an earlier unvouched duplicate cannot suppress a legitimate pinned enrollment.

**S4 — F2 upgrade does not invalidate previously captured device bindings**

Severity: **Medium**, conditional on exploitation before upgrade. Remediation gap, not a new way to create an unauthorized binding on a clean installation.

The store loads the existing device-to-UID/SID map without recording whether its entries were administrator-provisioned or obtained through the old first-caller behavior. Revised read/write checks trust that map. An attacker who captured a device URN before upgrade retains access afterward. Provisioning the intended principal through the new admin endpoint returns a conflict instead of replacing the attacker’s entry.

Evidence: [unchanged loading and binding semantics](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/device_binding.rs#L72-L152), [stored-binding authorization](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/http.rs#L355-L385), [admin conflict response](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/http.rs#L2296-L2304).

Fix: provide an explicit upgrade reconciliation procedure and privileged revoke/rebind operation. Consider a schema/provenance change that requires administrators to confirm legacy entries. Test loading a pre-fix attacker binding and replacing or quarantining it without authorizing the attacker. Deployments using the legacy Anonymous TCP allowance also need strict device binding enabled for principal-based enforcement.

**R1 — Rewritten PAM helper forwards CBOR-wrapped authenticator data as raw bytes**

Impact: **Medium availability/interoperability concern** for deployments relying on this helper. Introduced in the rewritten collection path; the previous default collection path was already incomplete.

Yubico’s [official fido2-assert output specification](https://developers.yubico.com/libfido2/Manuals/fido2-assert.html) identifies the third output line as CBOR-encoded authenticator data, then base64-encoded. The helper only transcodes standard base64 into base64url. It does not unwrap the CBOR byte string. The node expects raw authenticator data, extracts its RP hash and flags at raw offsets, and verifies the signature over those raw bytes plus the client-data hash.

Evidence: [helper conversion](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/platform/linux/pam_dds/src/bin/dds_pam_helper.rs#L488-L505), [node’s raw-data verifier](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-domain/src/fido2.rs#L800-L837).

A local independent Ed25519 probe signed a 37-byte raw authenticator-data value plus a client-data hash. Verification succeeded on the raw value. Applying the helper’s conversion to the CBOR-wrapped value forwarded 39 bytes, changed the interpreted RP hash, and caused signature verification to fail. This validates the format mismatch, not an end-to-end hardware test.

Fix: bounded-decode the CBOR byte string before constructing the API request. Test with realistic fido2-assert output and a real signature, then perform a hardware-backed PAM login. The failure is fail-closed; it is not an authentication bypass.

**Other carryover and recommended order**

The new `require_user_verification_for_account_claim` setting provides a server-side PIN/biometric requirement but defaults to false. Universal user verification is therefore still a deployment choice. The dependency lockfile and existing cargo-audit exceptions were not changed by these commits; a passing audit job does not demonstrate that previously accepted dependency risks were removed. [UV configuration](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/dds-node/src/config.rs#L145-L153), [audit exceptions](https://github.com/pkolarov/ABCD/blob/4ed0f4a9aef1faba472c5bb14051e0619acd1ff0/.cargo/audit.toml).

Prioritize the Linux enforcement/version-selection checks and the legacy-binding reconciliation, then close credential shadowing and fix the helper framing. Add focused regression tests for these cases and validate real PAM/Windows login behavior before shipping a release containing the remediation.
