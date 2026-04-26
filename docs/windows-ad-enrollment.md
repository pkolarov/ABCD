# DDS Windows AD Coexistence — Operator Enrollment Guide

**Audience:** Site operators and IT administrators rolling out DDS to
Windows endpoints that may be Workgroup, Active-Directory-joined,
hybrid (AD + Microsoft Entra), Entra-only, or in an unclassified state.

**Scope:** End-to-end operator workflow for first-time enrollment, the
post-password-change refresh flow, and what to expect when a host's
join state changes. Cross-references the design contract in
[windows-ad-coexistence-spec.md](windows-ad-coexistence-spec.md) and
the original gap proposal in [AD-gap-plan.md](AD-gap-plan.md).

This guide does **not** repeat the design rationale; it is a flow
checklist with the canonical user-visible text per host classification.

---

## 1. Host Classification at a Glance

The Auth Bridge and Policy Agent classify each Windows host into one of
five `JoinState` values on service start, and re-probe hourly. The
classification drives every operator-visible behaviour described in the
rest of this document.

| JoinState | Detection | What enrollment does | Sign-in afterwards |
|---|---|---|---|
| **Workgroup** | Not domain-joined; no device-Entra signal | Captures the local Windows password and stores it under `hmac-secret`. Claim path is available. | DDS sign-in by FIDO2 + cached password. |
| **AdJoined** | `NetGetJoinInformation == NetSetupDomainName` | Captures the user's AD password and stores it under `hmac-secret`. **No claim path.** | DDS sign-in by FIDO2 + cached AD password; Windows validates online or via cached credentials. |
| **HybridJoined** | AD-joined **and** device-Entra joined or workplace-registered | Same as `AdJoined`. | Same as `AdJoined`. |
| **EntraOnlyJoined** | Device-Entra joined; no AD | **Refused before the password prompt.** | DDS sign-in not yet supported. |
| **Unknown** | Probe failed or returned `NetSetupUnknownStatus` | **First-time enrollment refused before the password prompt.** Existing-vault refresh allowed for the current SID only. | DDS sign-in refused. |

Internal references for these probes:

- Managed: `platform/windows/DdsPolicyAgent/HostState/WindowsJoinStateProbe.cs`
- Native: `platform/windows/native/DdsAuthBridge/JoinState.cpp`
- Spec: §2 ("Host Classification: JoinState") of
  [windows-ad-coexistence-spec.md](windows-ad-coexistence-spec.md)

---

## 2. Initial Enrollment

Enrollment runs from inside an interactively-authenticated Windows
session via the DDS Tray Agent
([EnrollmentFlow.cpp](../platform/windows/native/DdsTrayAgent/EnrollmentFlow.cpp)).
Operators must brief end-users that **DDS cannot bootstrap a Windows
sign-in on a machine where the user has never logged in** — DDS only
wraps a Windows password the user already knows and uses. Enrollment is
therefore always a post-Windows-logon operation.

### 2.1 Workgroup

1. User signs in to Windows as themselves.
2. User opens the DDS tray menu → **"Enroll this user"**.
3. Tray prompts: *"Enter your Windows password"*.
4. User taps the FIDO2 authenticator twice (MakeCredential, then
   GetAssertion-with-`hmac-secret`).
5. Tray re-encrypts the password under the derived secret and writes
   the entry to the local vault.
6. Tray POSTs the attestation to `dds-node` at `/v1/enroll/user`.

The Windows password is **never** sent to `dds-node`; it stays in the
local vault, decrypted only by FIDO2 GetAssertion at sign-in time.

### 2.2 AD-joined / Hybrid

Mechanically identical to §2.1. The user must already have completed a
normal interactive Windows sign-in for the same AD account before
running enrollment, so they know the password. Operationally:

- Run enrollment in the user's own session — not in `runas` or a
  service context.
- The AD password is captured at enrollment time. After any subsequent
  AD password change (admin reset, expiry, change from another
  machine), the vault entry is stale; see §3 for the recovery flow.
- DDS does **not** trigger a Kerberos pre-auth at enrollment — Windows
  validates the password the next time the user signs in via a DDS
  tile.

The tray must not initiate enrollment on a host whose JoinState has not
yet been classified; if the user opens enrollment immediately after a
service restart and the cache is empty, the flow falls into §2.4
("Unknown") behaviour rather than capturing a password speculatively.

### 2.3 Entra-only

Enrollment is **blocked before the password prompt** with the canonical
unsupported message:

> "DDS sign-in is not yet supported on Entra-joined machines."

Capturing and storing a password for a host classification that cannot
use DDS sign-in would create unnecessary credential exposure. The
classification is sticky for the duration of the service process and
re-probed hourly; if a tenant re-joins the host as workgroup or AD,
the next probe re-enables enrollment.

### 2.4 Unknown

`Unknown` covers a transient failure of `NetGetJoinInformation` /
`NetGetAadJoinInformation`. Behaviour:

- **First-time enrollment is blocked before the password prompt** with
  the canonical text:

  > "DDS could not classify this machine. Please retry after the DDS
  > services have been able to detect the host state."

- **Refresh** of an existing vault entry is allowed for the current
  SID only. The intent is to keep an already-trusted user from being
  stranded after a transient probe failure, while still preventing a
  first-time password capture in an unclassified state.

Operators seeing repeated `Unknown` should check the Auth Bridge log
for `host_state_probe_failed` entries and confirm that the
`netapi32.dll` / `dsreg` symbols required by the probe are present.

---

## 3. Recovery After an AD Password Change

When an AD password changes outside DDS — admin reset, scheduled
expiry, change from another machine, in-session change via Ctrl-Alt-Del
— the local vault entry becomes stale. DDS detects this on next
sign-in and routes the user through the tray refresh flow.

### 3.1 First failed sign-in

1. User selects a DDS tile on the Windows logon screen.
2. CP submits the cached password to `LogonUI`. Windows returns
   `STATUS_LOGON_FAILURE`.
3. CP receives the failure in `ReportResult` and shows the canonical
   stale-password text:

   > "Your DDS stored password may be out of date. Sign in normally
   > with your Windows password, then refresh DDS from the system tray."

4. CP sends `DDS_REPORT_LOGON_RESULT` to the Auth Bridge.
5. Auth Bridge starts a **15-minute cooldown** for that
   `(credential_id, SID)` pair. Further DDS sign-in attempts during
   the cooldown short-circuit before WebAuthn and before any Windows
   credential serialization is submitted — this prevents AD lockout.

### 3.2 Refresh from the tray

After the user signs in normally with the new password:

1. User opens the DDS tray menu → **"Refresh stored password"**.
2. Tray reads the existing vault entry for the current SID. The
   credential_id is matched by SID, not user-selected.
3. Tray prompts: *"Enter your current Windows password"*.
4. Tray runs WebAuthn `GetAssertion` with `hmac-secret` against the
   **existing** credential_id — no MakeCredential, no new FIDO2
   credential is created.
5. Tray re-encrypts the new password under the derived key and saves
   the vault.
6. Tray sends a clear-cooldown notification to the Auth Bridge for
   that `(credential_id, SID)` pair.
7. Next DDS sign-in succeeds.

The vault file format is unchanged by refresh — only the password
ciphertext is rewritten under the same credential_id.

### 3.3 Special password-state codes

CP distinguishes three password-state outcomes from generic failures:

| NTSTATUS | Operator-facing text |
|---|---|
| `STATUS_LOGON_FAILURE` after a DDS serialization | "Your DDS stored password may be out of date. Sign in normally with your Windows password, then refresh DDS from the system tray." |
| `STATUS_PASSWORD_MUST_CHANGE` (`0xC0000224`) | "AD requires you to set a new password. Sign in normally to change it, then refresh DDS." |
| `STATUS_PASSWORD_EXPIRED` (`0xC0000071`) | Same recovery path as above. |
| `STATUS_ACCOUNT_DISABLED` / `STATUS_ACCOUNT_RESTRICTION` | "The account is disabled." |
| `LookupAccountSid` fails before serialization | "This DDS account no longer exists in your directory. Contact your administrator." |

The mapping is wired in the Credential Provider's `ReportResult`
handler. The Auth Bridge sees these outcomes only when CP sends
`DDS_REPORT_LOGON_RESULT`.

---

## 4. Host-State Transitions

A workgroup machine that is later joined to AD is the only transition
that has lasting state implications. The probe runs hourly so the
state change is detected within ≤ 1 hour, or immediately on next
service restart, whichever is first.

When the probe observes a change since the last cycle:

- A single `host_state_transition_detected` audit entry is emitted.
- Effective enforcement mode for every policy surface flips to
  `Audit` (no writes). `EnforcementMode.Audit` overrides any
  `Enforce` requested by the policy document.
- Stranded items in `applied-state.json` keep their inventory record
  with `audit_frozen: true`. **No automatic rollback** of registry
  keys, accounts, password policy, or installed MSIs.
- Manual cleanup of stranded local accounts or registry entries is
  supported via the inventory; it is not automated in v1.

A transition the other way (AD → workgroup) clears `audit_frozen` on
the next reconcile that re-lists the same item, so active management
resumes deterministically.

---

## 5. Operator Pre-flight Checklist

Before rolling out DDS to a fleet that may include AD-joined hosts:

1. Confirm the target image classifies correctly. Run
   `dsregcmd /status` interactively (operators only — DDS itself does
   not parse this output) and cross-check it against the values
   reported by the DDS Auth Bridge log on first start.
2. Ensure every user has a working interactive Windows sign-in path
   before they run enrollment. DDS does not bootstrap first sign-in.
3. Brief end-users on the canonical text strings in §3 — recovery
   requires the user to type their current AD password into the
   normal Windows logon screen first, then return to the tray.
4. Verify that AD password policy lockout thresholds are higher than
   the cooldown intercept: the bridge prevents repeated DDS-driven
   submissions of a stale password, but the user can still trip
   lockout by typing the wrong password directly into LogonUI.
5. For Entra-only fleets, plan to deploy the tray with the
   `unsupported_entra` heartbeat-only mode — the policy agent emits
   one heartbeat per cycle and skips dispatch entirely. No
   uninstallation is necessary; classification gates the behaviour.

---

## 6. Appendix — Status Strings Reference

Canonical strings shown to the operator. These are the source of truth;
both CP and the Tray Agent source from this list.

| Situation | String |
|---|---|
| Entra-only block at enrollment | "DDS sign-in is not yet supported on Entra-joined machines." |
| Unknown block at first-time enrollment | "DDS could not classify this machine. Please retry after the DDS services have been able to detect the host state." |
| AD/Hybrid + no vault entry at sign-in | "DDS sign-in is available only after enrollment on this AD-joined machine." |
| Stale vault password | "Your DDS stored password may be out of date. Sign in normally with your Windows password, then refresh DDS from the system tray." |
| AD requires password change | "AD requires you to set a new password. Sign in normally to change it, then refresh DDS." |
| Account disabled | "The account is disabled." |
| Account no longer in directory | "This DDS account no longer exists in your directory. Contact your administrator." |

Mapped IPC error codes are listed in §8 ("IPC Contract") of
[windows-ad-coexistence-spec.md](windows-ad-coexistence-spec.md).

---

## 7. History

- **2026-04-26** — Initial guide published. Closes
  [AD-gap-plan.md](AD-gap-plan.md) AD-12 (operator workflow
  documentation). Tray-side text-string updates in
  `EnrollmentFlow.cpp` are tracked separately as part of AD-13
  (vault-refresh flow), since the tray does not yet host its own
  `JoinState` probe seam — wiring that probe into the tray agent
  is in scope when AD-13 is implemented.
