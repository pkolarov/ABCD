# External security review of v1.6.3 — remediation record (2026-09-07)

The review below was received on 2026-09-07 against `ecd8a97` (v1.6.3). Every
finding was verified against the source before anything was changed; the
verdicts and the fixing commits are recorded here, followed by the review as
received.

| ID | Review severity | Verified | Notes | Fix |
|---|---|---|---|---|
| F1 | High | **Confirmed, worse than written** | Ingest never inspected the attestation body and the lookup re-parsed with unattested credentials allowed, so no approved hardware was needed; on Windows the logon screen itself provides the session endpoint and the account claim resets an existing account's password, so the chain closes to an interactive logon as the victim. | `fix(auth): a replicated user-auth attestation must be self-issued and vouch-pinned before it can authenticate (F1)` |
| F2 | Medium | Confirmed in code, **narrower on packaged installs** | The Unix socket is root-owned 0660 and the node runs as root, so agents are admin callers there; on Windows the node pipe has no explicit DACL, which is why the fix is at the API layer. | `fix(api): device bindings are provisioned by an administrator, never by the first caller (F2)` |
| F3 | Medium | Confirmed as described | No session revocation mechanism exists; the claim endpoint is device-scoped, so the practical caller is the Auth Bridge. | `fix(auth): re-check live authorization and optional user verification before a Windows account claim (F3)` |
| F4 | High, conditional | Confirmed, **not shipped** | Missing account binding and the fido2-assert protocol errors are both real; no installer or workflow packages `pam_dds`. | `fix(pam): bind PAM authentication to the requested Unix account via a node-side authorization (F4)` |
| UV | Additional risk | Confirmed | UV requested as *discouraged*; server enforced UV only for admin vouch/revoke. | `[domain] require_user_verification_for_account_claim` (default off), in the F3 commit |
| hickory-proto | Additional risk | Confirmed | Documented upstream block in `.cargo/audit.toml`; unchanged. | none |

Still open after this remediation:

- The Windows node pipe is created without an explicit security descriptor
  (`dds-node/src/http.rs`, named-pipe listener). The Auth Bridge's own IPC
  pipe sets a SYSTEM-only SDDL; the node pipe should do the same.
- `pam_dds` remains unpackaged. Its fido2-assert path is now written against
  the libfido2 manual with unit-tested parsers, but has not been run against
  a hardware authenticator.
- The F1 and F3 changes touch the Windows logon path (session issuance and
  account claim). A normal logon, a fresh claim on a second PC, and a revoked
  user were unit-tested only; exercise them on the Windows box before release.

---

# ABCD security review

Reviewed: 7 September 2026  
Repository: [pkolarov/ABCD](https://github.com/pkolarov/ABCD)  
Revision: [`ecd8a977a20b11ae9cd8701d22b255d99853fb6c`](https://github.com/pkolarov/ABCD/commit/ecd8a977a20b11ae9cd8701d22b255d99853fb6c), `main`, release `v1.6.3`

**Prioritize the replicated credential identity-binding flaw before production deployment.** The review identified three source-confirmed security defects and one conditional Linux PAM defect. These are static findings, not demonstrated attacks against a running deployment.

| ID | Severity | Finding | Evidence status |
|---|---|---|---|
| F1 | High | Replicated credential can authenticate as a different DDS subject | Source-confirmed; end-to-end reproduction pending |
| F2 | Medium | Unprivileged API caller can claim an unbound device identity | Source-confirmed; requires transport access |
| F3 | Medium | Revoked users retain account-claim authorization through existing sessions | Source-confirmed; requires a live session and remaining account policy |
| F4 | High, conditional | PAM success is not bound to the requested Unix account | Missing check confirmed; current assertion collection also has functional defects |

## F1 — Replicated credential can authenticate as a different subject

**Impact:** An attacker controlling an admitted peer can introduce an attacker-controlled credential associated with a victim's subject URN. If the attacker can reach the receiving node's session API, a valid assertion from that credential is used to mint a session with the victim's existing grants. No victim signing key or authenticator is required.

**Evidence and data flow:**

1. [`publisher_capability_ok`, node.rs:6158](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/node.rs#L6158) restricts policy/software/update documents, but returns `true` for `dds:user-auth-attestation`. The gossip ingest path validates the token and then inserts it into the trust graph at [node.rs:3237](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/node.rs#L3237).
2. [`Token::verify_issuer_binding`, token.rs:312](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-core/src/token.rs#L312) binds the signature key to `iss`. It does not bind `sub` to that key. The shape check at [token.rs:424](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-core/src/token.rs#L424) adds no user-credential ownership rule.
3. [`verify_assertion_common`, service.rs:2182](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/service.rs#L2182) searches every non-revoked credential attestation, verifies the embedded credential, and returns **`token.payload.sub`** at line 2211. It does not require `iss == sub`, or prove the selected credential attestation is the one approved by a trusted vouch.
4. [Session issuance, service.rs:2425](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/service.rs#L2425) uses that subject. [`issue_session_inner`, service.rs:1349](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/service.rs#L1349) obtains the subject's existing purposes, independently of which credential attestation authenticated it.

The distinction matters: rejecting an attacker-supplied `subject_urn` in the HTTP request does not protect the subject read from a replicated token. Existing signature, challenge, RP-ID, and counter checks do not prevent the attacker from signing correctly with their own credential.

**Prerequisites:** Ability to publish through an admitted peer; knowledge of a victim URN with live grants; access to the target's local session endpoint. This is not an unauthenticated Internet attack. An admin-vouch escalation additionally requires access to admin-gated endpoints and an available persisted admin key; that broader consequence was not established end to end.

**Fix:** For the current self-issued enrollment format, enforce `iss == sub` on user-auth attestations at ingestion, rehydration, and authentication. Require an active, authorized enrollment binding to the exact selected credential attestation, including its hash, subject and credential ID. Reuse the same validation across gossip, sync, import and local enrollment. Reject expired and ambiguous credential mappings. If delegated enrollment is needed, represent and verify that delegation explicitly.

**Regression case:** Give victim V a legitimate vouched credential. Introduce a separately valid token signed by A with `iss=A`, `sub=V` and A's credential. A valid fresh assertion by A must be rejected and must never mint a V session. Repeat through both gossip and sync paths.

## F2 — Device binding is established by an unauthorized first caller

**Impact:** A local non-admin caller with API transport access can submit an applied report naming another device, thereby obtain its device-scoped policy/software reads and submit false compliance reports under that device's name.

[`tofu_device_binding`, http.rs:321](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/http.rs#L321) binds the first concrete UID/SID to a caller-supplied `device_urn`. It requires neither device proof nor enrollment authorization. [`DeviceBindingStore::tofu_bind`, device_binding.rs:126](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/device_binding.rs#L126) persists that association. `/applied` then accepts the report; subsequent reads accept the matching stored principal.

There is a further interaction: admin/service callers return early at [http.rs:327](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/http.rs#L327), so normal privileged agent reports do not establish a protective binding. An unbound device can remain claimable after normal operation has begun. The existing [test at http.rs:6542](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/http.rs#L6542) explicitly expects arbitrary UID 1000 to bind an unbound URN and read it; this test was inspected, not executed.

**Prerequisites:** Access to the UDS/named pipe and knowledge of an unbound device URN. A Unix deployment whose socket and parent directory exclude all non-admin users limits this attack. An already established binding to another principal blocks it. This does not itself authorize policy publication or grant OS administrator rights.

**Fix:** Provision device-to-agent bindings through an administrator-authenticated enrollment flow. Require the configured agent identity or a device-key proof on reports; never create authorization bindings from unauthenticated report content. Validate the named device exists and belongs to this agent. Establish bindings for privileged agents too.

**Regression case:** A non-admin caller's report for an unbound device must return 403 and leave the binding store unchanged. A legitimate root/SYSTEM report must not leave a device open to a later non-admin claim.

## F3 — Existing session bypasses subsequent user revocation at account claim

**Impact:** After a user's grants or identity are revoked, an unexpired session can still authorize a Windows account claim if the corresponding account-creation directive remains. The exposure can last up to the 24-hour session cap.

[`validate_local_session_token`, service.rs:3621](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/service.rs#L3621) checks signature, expiry, local issuer, session purpose and matching body subject. It does not consult current subject revocation, identity burn, active grants or a session revocation mechanism. [`resolve_windows_account_claim`, service.rs:2013](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/dds-node/src/service.rs#L2013) then matches that subject against a current account directive. The policy publisher's authority is checked, but the user's current authorization is not.

**Prerequisites:** A previously issued session, device-scoped endpoint access, and a remaining matching account policy. Removing the account directive can independently stop the claim. This finding establishes continued claim authorization; it does not establish a direct unprivileged HTTP-to-SYSTEM execution path, since account creation is performed separately by the Auth Bridge.

**Fix:** At this privileged operation, re-evaluate the subject's live login/claim grant and reject burned/revoked identities and invalidated sessions. Bind sessions to the intended device where applicable. Specify the maximum revocation delay explicitly if offline session survival is intentional.

**Regression case:** Issue a session, revoke the user's qualifying grant or burn the user identity, retain the account directive, and retry the claim. Expect rejection before account information is returned or any OS mutation occurs.

## F4 — PAM does not bind authentication to PAM_USER

**Impact if the assertion collection path is operational:** A valid DDS user's assertion can satisfy authentication for a different Unix account, including a privileged account where the surrounding PAM stack permits it.

The PAM module passes the requested username to its helper and returns success on `outcome.ok` at [linux.rs:109](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/platform/linux/pam_dds/src/linux.rs#L109). The helper puts the username only into an optional subject hint at [dds_pam_helper.rs:451](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/platform/linux/pam_dds/src/bin/dds_pam_helper.rs#L451), then returns success after parsing a session response at line 469. It never validates the session subject against an authorized DDS-to-Unix account mapping. The node deliberately ignores the request's subject hint.

**Qualification:** This is a confirmed missing authorization check, but not a verified working PAM bypass on stock v1.6.3. The default helper also appears incompatible with the real `fido2-assert` CLI: it passes `-G -h <rp_id>`, sends only a challenge, and interprets output fields differently from the documented protocol. Yubico documents `-h` as enabling hmac-secret, a device positional argument, and multi-line input beginning with the client-data hash and RP ID. These functional problems may make the current default path fail closed. They must not be repaired without also fixing account binding. See [Yubico's fido2-assert manual](https://developers.yubico.com/libfido2/Manuals/fido2-assert.html).

**Fix:** Have the trusted node authorize a tuple of DDS subject, device, Unix UID/account and PAM service. Verify that result before returning `PAM_SUCCESS`. Supply a defined server-side account mapping; the client hint must remain non-authoritative. Use a fixed trusted authenticator-tool path and bounded execution.

**Regression case:** With Alice's valid credential and a working collection adapter, request authentication for Bob and root. Both must fail; Alice must pass only for the account explicitly mapped to her identity. Exercise the complete PAM stack.

## Additional security risks

**Windows passwordless login does not enforce MFA universally.** The Credential Provider requests `WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED` at [DdsBridgeClient.cpp:991](https://github.com/pkolarov/ABCD/blob/ecd8a977a20b11ae9cd8701d22b255d99853fb6c/platform/windows/native/DdsCredentialProvider/DdsBridgeClient.cpp#L991). Session issuance records UV as `mfa_verified`, but the Windows claim path does not require it. Touch-only credentials can therefore participate in that flow. This may be intentional, but deployments requiring PIN/biometric verification need an enforced server-side UV policy. The admin-vouch endpoint already has a separate UV requirement. Changing UV can also affect the hmac-secret vault compatibility assumptions noted in the code, so migration needs hardware testing.

**Known dependency exception remains.** `Cargo.lock` pins `hickory-proto` to `0.25.0-alpha.5`, and `.cargo/audit.toml` ignores RUSTSEC-2026-0119. The current [RustSec advisory](https://rustsec.org/advisories/RUSTSEC-2026-0119.html) describes quadratic CPU consumption during DNS message encoding and lists `>=0.26.1` as patched. The affected dependency and audit suppression are confirmed; exploitability through DDS's specific mDNS use was not demonstrated. Upgrade the dependency graph or backport the fix, and document reachability while the exception remains. This was a targeted advisory check, not a fresh complete dependency audit.

## Scope and validation limits

The repository was located using the connected GitHub integration and cloned at the stated revision. Review covered security-sensitive portions of token validation, trust evaluation, replicated token ingestion, FIDO2 enrollment/assertion verification, local API authorization, device binding, session/account claims, self-update handling, selected platform agents, and CI/dependency configuration. The existing security reviews were treated as historical claims and checked against current source where relevant.

Several earlier findings do have corresponding fixes: explicit gossip validation and reporting, connection limits, bounded update downloads, default-off loopback TCP admin trust, and admin-vouch UV enforcement. This is not a blanket verification that every earlier finding is resolved.

No source changes, commits, issues or PR comments were made. No running production service was tested. Rust/.NET toolchains and Windows/FIDO2 hardware were unavailable in the review environment; no application tests, new regression cases or exploit demonstrations were executed. Git history, every native-code path, deployment ACLs, branch protection and all current dependency advisories were not exhaustively audited. The regression cases above are proposed acceptance criteria.

Recommended order: fix F1; close F2 and F3; keep PAM out of production until F4 and the collection adapter are validated; then resolve the MFA policy and dependency exception against the intended deployment requirements.
