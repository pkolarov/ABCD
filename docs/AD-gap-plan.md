# DDS Windows AD Coexistence Gap Plan

> **⚠️ Superseded by [windows-ad-coexistence-spec.md](windows-ad-coexistence-spec.md) on 2026-04-25.**
> Kept for historical reference as the originating gap analysis. The locked v1
> behavior, decisions, and per-task implementation plan now live in the spec.

**Status:** Superseded
**Date:** 2026-04-13
**Owner:** Windows platform / auth / policy-agent workstream

---

## 1. Goal

Define the first safe coexistence mode between DDS and Microsoft directory-managed
Windows machines:

- **AD-joined Windows machines** must coexist with AD without breaking the host.
- DDS may participate on the **authentication front** by brokering FIDO2 into an
  already-existing Windows domain account.
- DDS policy enforcement on AD-joined hosts must be **audit-only**.
- **Entra-only joined Windows machines** are explicitly **unsupported** in v1 and
  must fail fast with a clear error.

This plan is intentionally narrower than "full AD/Entra integration". It is a
pragmatic first step that lets DDS live on the logon path without trying to
replace AD, GPO, Intune, or Entra device identity.

---

## 2. Scope Decisions

### 2.1 Support Matrix

| Host State | v1 Behavior | Notes |
| --- | --- | --- |
| Workgroup / local-only | Existing DDS behavior | No change beyond refactoring to a richer join-state model |
| AD joined | **Supported in coexistence mode** | DDS auth allowed only for already-enrolled Windows accounts; policy application forced to audit-only |
| AD joined + Entra registered / hybrid indicators | **Treat same as AD joined** | If the machine is still domain-joined, do not reject it just because extra Entra signals exist |
| Entra-only joined | **Unsupported** | Fail fast with explicit unsupported message |
| Unknown / probe failed | Fail closed for mutating operations | Prefer audit / unsupported over accidental enforcement |

### 2.2 Non-Goals For v1

- No first-account bootstrap or local account claim on AD-joined machines.
- No DDS ownership of GPO-like settings on AD-joined machines.
- No Intune / Graph / MSAL / OIDC / SAML / SCIM implementation in this phase.
- No Entra sign-in support.
- No attempt to replace Windows domain logon semantics or AD credential
  validation. DDS still ends by handing Windows a normal credential blob.

---

## 3. Current Repo State

The existing code is already close to the desired AD coexistence behavior on the
Windows authentication path:

1. The enrollment flow captures the **current Windows SID and password**, binds a
   FIDO2 credential, and stores the password in the local vault encrypted under
   `hmac-secret`.
   Files:
   - `platform/windows/native/DdsTrayAgent/EnrollmentFlow.cpp`

2. The DDS logon path resolves `domain` and `username` from the stored SID, then
   packs `KERB_INTERACTIVE_UNLOCK_LOGON` for Windows.
   Files:
   - `platform/windows/native/DdsAuthBridge/DdsAuthBridgeMain.cpp`
   - `platform/windows/native/DdsCredentialProvider/CDdsCredential.cpp`

3. First-account claim is already blocked on domain-joined Windows machines.
   Files:
   - `platform/windows/native/DdsAuthBridge/DdsAuthBridgeMain.cpp`

4. The policy agent only blocks **local account mutation** on domain-joined
   machines today. Registry, password policy, and software paths are still
   eligible to run, which is not acceptable for AD coexistence.
   Files:
   - `platform/windows/DdsPolicyAgent/Worker.cs`
   - `platform/windows/DdsPolicyAgent/Enforcers/AccountEnforcer.cs`
   - `platform/windows/DdsPolicyAgent/Enforcers/RegistryEnforcer.cs`
   - `platform/windows/DdsPolicyAgent/Enforcers/PasswordPolicyEnforcer.cs`
   - `platform/windows/DdsPolicyAgent/Enforcers/SoftwareInstaller.cs`

5. The credential provider currently enumerates DDS-enrolled users from
   `dds-node`, even on hosts where first-claim is disabled. That means the logon
   screen can show users who are not actually logon-capable on an AD-joined host
   unless they already have a vault-backed Windows credential on that machine.
   Files:
   - `platform/windows/native/DdsAuthBridge/DdsAuthBridgeMain.cpp`
   - `platform/windows/native/DdsCredentialProvider/DdsBridgeClient.cpp`
   - `platform/windows/native/DdsAuthBridge/DdsNodeHttpClient.{h,cpp}`

---

## 4. Target v1 Behavior

### 4.1 AD-Joined Coexistence Mode

On an AD-joined Windows machine, DDS must behave as follows:

- `dds-node` remains available for enrollment, session issuance, and status.
- DDS FIDO2 logon is allowed **only** for users who have already enrolled on
  that device and therefore already have a local vault entry that wraps the
  current Windows password.
- DDS must not create, claim, or mutate Windows local accounts for the purpose
  of logon on an AD-joined host.
- DDS policy applier must evaluate policy but **apply nothing**; all directives
  are converted to audit-only results.
- The DDS tile list must include only users who can actually complete logon in
  this mode.

### 4.2 Entra-Only Unsupported

On an Entra-only joined Windows machine:

- the auth bridge returns a clear unsupported error;
- the credential provider shows a clear unsupported status;
- the policy agent refuses enforcement and reports unsupported state;
- no best-effort fallback path is attempted.

### 4.3 Expected User Story

1. User signs in to an AD-joined machine through the normal Windows path.
2. User runs DDS enrollment from the logged-in session.
3. DDS enrollment captures the current domain-backed Windows password, encrypts
   it under `hmac-secret`, and stores it in the local vault.
4. On subsequent logons, the DDS credential provider performs FIDO2 proof,
   decrypts the stored password, and submits the domain credential to Windows.
5. Windows still validates the account as a normal domain user, including cached
   domain logon behavior when offline.

This mode is intentionally "FIDO2 unlock for an existing AD account on this
device", not "DDS authorizes arbitrary domain users to appear on arbitrary AD
machines".

---

## 5. Detailed Developer Spec

### 5.1 Introduce JoinState

Replace the current boolean `IsDomainJoined()` model with a richer host
classification:

```text
enum JoinState {
    Workgroup,
    AdJoined,
    HybridJoined,
    EntraOnlyJoined,
    Unknown,
}
```

Rules:

- If the host is domain-joined, classify as `AdJoined` or `HybridJoined`.
- `HybridJoined` behaves the same as `AdJoined` in v1.
- If the host is not domain-joined but is Entra-joined, classify as
  `EntraOnlyJoined`.
- If detection is inconclusive, classify as `Unknown` and fail closed for
  mutating behavior.

Implementation guidance:

- Keep the existing `NetGetJoinInformation` probe for classic AD join state.
- Add a second probe for Entra-only state.
- Prefer a stable native/API-based implementation; if that is not practical in
  the first cut, a tightly-scoped `dsregcmd /status` parser is acceptable as a
  temporary probe.
- Both the .NET policy agent and the native auth bridge must use the same
  classification semantics.

### 5.2 Policy Agent Behavior

For `AdJoined` and `HybridJoined`:

- force **effective mode = Audit** for:
  - registry
  - local accounts
  - password policy
  - services
  - software assignments
- continue to poll `dds-node` and report applied-state results, but report that
  the host is in AD coexistence audit mode.

For `EntraOnlyJoined`:

- return `Unsupported` / `Skipped with reason` at the worker boundary;
- do not execute enforcers;
- emit a single clear service log entry at startup and per poll cycle.

For `Unknown`:

- treat as non-enforcing unless explicitly overridden in future development.

### 5.3 Auth Bridge Behavior

For `AdJoined` and `HybridJoined`:

- allow DDS auth only if a vault entry exists for the selected credential;
- if no vault entry exists, return:
  - `AD coexistence mode requires prior enrollment on this machine`
- do **not** call `/v1/windows/claim-account`;
- continue to call `/v1/session/assert` for DDS-side proof validation and local
  DDS session issuance;
- continue to resolve `domain` and `username` from the stored SID and submit a
  standard Windows credential blob.

For `EntraOnlyJoined`:

- return:
  - `DDS Windows logon is not yet supported on Entra-joined machines`
- do not attempt vault decrypt, claim, or Windows credential serialization.

### 5.4 Credential Provider Tile Enumeration

For `AdJoined` and `HybridJoined`:

- enumerate DDS users from `dds-node` as today;
- intersect them with local vault entries by `credential_id`;
- only surface users who have a vault-backed enrollment on this machine.

Fallback rules:

- if `dds-node` is unavailable, fall back to vault-backed entries only;
- never surface a tile that would require first-claim on an AD-joined host.

### 5.5 Enrollment Flow

Keep the current Windows enrollment shape for v1:

- prompt the logged-in user for the current Windows password;
- store the current SID;
- bind the credential to the local vault entry using `hmac-secret`;
- POST enrollment metadata to `dds-node`.

Required clarifications:

- this enrollment is tied to the **current Windows account on the current
  machine**;
- it is not a generic DDS enrollment that enables arbitrary cross-machine AD
  access;
- if the user's AD password changes later, the vault entry can become stale and
  must be refreshed.

### 5.6 Error Messages

Use specific user-facing failures:

- AD host without vault entry:
  - `DDS sign-in is available only after enrollment on this AD-joined machine.`
- Entra-only host:
  - `DDS sign-in is not yet supported on Entra-joined machines.`
- Stale vault entry:
  - `Stored Windows credential is out of date. Sign in with your Windows password and refresh DDS enrollment.`

---

## 6. Repo Backlog

### Phase 1 - Join-State Foundation

| ID | Task | Repo Area | Deliverable |
| --- | --- | --- | --- |
| AD-01 | Add shared Windows `JoinState` model | `platform/windows/DdsPolicyAgent/`, `platform/windows/native/DdsAuthBridge/` | Replace boolean domain-join checks with a richer state model |
| AD-02 | Implement AD + Entra host-state probes | Same as above | Native and managed detection path with matching semantics |
| AD-03 | Add tests for `JoinState` classification | `platform/windows/DdsPolicyAgent.Tests/`, `platform/windows/native/Tests/` | Workgroup, AD, hybrid, Entra-only, unknown cases |

### Phase 2 - Safe Policy Coexistence

| ID | Task | Repo Area | Deliverable |
| --- | --- | --- | --- |
| AD-04 | Force audit-only behavior on AD / hybrid hosts | `platform/windows/DdsPolicyAgent/Worker.cs` | Centralized effective-mode override |
| AD-05 | Prevent software enforcement on AD / hybrid hosts | `platform/windows/DdsPolicyAgent/Worker.cs`, `SoftwareInstaller.cs` | Software assignments become audit-only too |
| AD-06 | Add unsupported startup path for Entra-only hosts | `platform/windows/DdsPolicyAgent/Program.cs`, `Worker.cs` | Clear service logs and applied-state reason |
| AD-07 | Add reporting reason codes | `platform/windows/DdsPolicyAgent/Client/`, `State/` | Distinguish `audit_due_to_ad_coexistence` vs `unsupported_entra` |

### Phase 3 - Authentication Coexistence

| ID | Task | Repo Area | Deliverable |
| --- | --- | --- | --- |
| AD-08 | Gate claim path by `JoinState` instead of boolean domain join | `platform/windows/native/DdsAuthBridge/DdsAuthBridgeMain.{h,cpp}` | AD / hybrid block claim, Entra-only block full auth path |
| AD-09 | Filter DDS user list to vault-backed users on AD / hybrid | `platform/windows/native/DdsAuthBridge/DdsAuthBridgeMain.cpp`, `DdsBridgeClient.cpp`, `CredentialVault.{h,cpp}` | No impossible tiles on AD hosts |
| AD-10 | Improve CP status text for unsupported and pre-enrollment-required states | `platform/windows/native/DdsCredentialProvider/CDdsCredential.cpp` | Clean operator-facing UX |
| AD-11 | Add native tests for AD coexistence auth path | `platform/windows/native/Tests/` | Existing vault entry succeeds; no-entry path fails cleanly; Entra-only unsupported |

### Phase 4 - Enrollment And Recovery UX

| ID | Task | Repo Area | Deliverable |
| --- | --- | --- | --- |
| AD-12 | Document AD coexistence enrollment flow | `docs/`, possibly tray text strings | Operators know enrollment must happen post-Windows-logon |
| AD-13 | Add "refresh vault password" workflow for post-password-change recovery | `platform/windows/native/DdsTrayAgent/` | User can re-wrap a new AD password without deleting the credential |
| AD-14 | Add stale-password detection / guided recovery text | `platform/windows/native/DdsAuthBridge/`, `DdsCredentialProvider/` | Better response after `STATUS_LOGON_FAILURE` scenarios |

### Phase 5 - End-To-End Validation

| ID | Task | Repo Area | Deliverable |
| --- | --- | --- | --- |
| AD-15 | AD-joined VM E2E test plan | `platform/windows/e2e/` | Repeatable validation on a domain-joined test box |
| AD-16 | Entra-only unsupported test case | Same | Explicit unsupported behavior test |
| AD-17 | Security review of vault semantics on domain accounts | `security-gaps.md` follow-up | Confirm no new password-handling regressions |

---

## 7. Acceptance Criteria

This phase is complete only if all of the following are true:

1. On an AD-joined machine, DDS does **not** mutate registry, local accounts,
   password policy, services, or software state.
2. On an AD-joined machine, DDS can complete FIDO2-backed sign-in for a user who
   previously enrolled on that same machine.
3. On an AD-joined machine, DDS does not surface tiles that require first-claim
   or local account bootstrap.
4. On an Entra-only joined machine, DDS fails fast with a clear unsupported
   message in both the auth path and the policy-agent path.
5. On a workgroup machine, existing DDS behavior remains intact.

---

## 8. Test Plan

### 8.1 Managed Tests

- Unit tests for effective policy mode by join state.
- Worker tests proving that AD / hybrid hosts never invoke mutating enforcers.
- Worker tests proving Entra-only hosts return unsupported state.

### 8.2 Native Tests

- Join-state classification tests.
- Auth path tests:
  - AD joined + vault entry -> success
  - AD joined + no vault entry -> pre-enrollment-required
  - Entra-only -> unsupported
- Tile enumeration tests:
  - DDS users filtered to vault-backed users on AD hosts

### 8.3 Manual / E2E

- Workgroup baseline regression
- AD-joined online logon
- AD-joined cached/offline logon after prior successful domain sign-in
- AD password changed -> stale vault recovery path
- Entra-only joined host -> unsupported

---

## 9. Risks And Follow-Ups

### 9.1 Known Limitation: Stale Vault After AD Password Change

Because v1 replays a wrapped Windows password, a domain password change can make
the vault entry stale. That does not block this phase, but it must be handled as
an expected operational workflow with refresh tooling.

### 9.2 Known Limitation: No First Sign-In Bootstrap On AD Hosts

DDS cannot perform a user's first-ever Windows sign-in on an AD-joined device in
this phase. The user must first establish a normal Windows logon and then enroll
DDS from the running session.

### 9.3 Future Entra Work

Entra support should be treated as a separate project, likely requiring:

- explicit device-state modeling beyond classic domain join;
- a non-password replay path;
- a modern federation / token integration strategy instead of only
  `KERB_INTERACTIVE_UNLOCK_LOGON`.

That work is intentionally deferred out of this document.

---

## 10. Summary

The repo already contains most of the mechanics needed for a safe first AD
coexistence mode:

- enrollment already captures SID + password for the current Windows account;
- logon already serializes a normal Windows credential from the stored SID;
- first-claim is already blocked on domain-joined hosts.

The main missing work is not the FIDO2 ceremony itself. The gap is
**host-state-aware product behavior**:

- classify AD / hybrid / Entra-only correctly;
- force audit-only policy behavior on AD / hybrid hosts;
- show only logon-capable users on AD hosts;
- fail fast on Entra-only hosts.

That is the narrowest slice that lets DDS and AD coexist "in peace" without
pretending DDS already owns Windows enterprise identity.
