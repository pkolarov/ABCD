# DDS Windows AD Coexistence Specification

**Status:** Locked for v1
**Date:** 2026-04-25
**Owner:** Windows platform / auth / policy-agent workstream
**Supersedes:** [AD-gap-plan.md](AD-gap-plan.md) (kept as the originating proposal)

---

## 1. Goals and Non-Goals

### 1.1 Goals

Define the first safe coexistence mode between DDS and Microsoft directory-managed
Windows machines. The integrated Windows endpoint (Credential Provider, Auth
Bridge, Tray Agent, Policy Agent, local vault) must behave correctly across five
host classifications and six operational scenarios (§9).

- AD-joined machines coexist with AD without breaking the host.
- DDS may participate in authentication by brokering FIDO2 into an
  already-enrolled AD account.
- DDS policy enforcement on AD/hybrid hosts is forced to audit-only.
- Entra-only joined machines fail fast with a clear unsupported error.
- Workgroup machines retain existing DDS behavior.

### 1.2 Non-Goals (v1)

- No first-account bootstrap or local-account claim on AD/hybrid hosts.
- No DDS ownership of GPO-equivalent settings on AD/hybrid hosts.
- No Intune / Graph / MSAL / OIDC / SAML / SCIM integration.
- No Entra sign-in support.
- No proactive AD account-state polling. Stale entries are detected on auth
  failure, not anticipated.
- No automatic rollback of stranded DDS-applied state after a host transitions
  workgroup → AD-joined. The inventory is preserved; cleanup is an explicit
  operator action.

---

## 2. Host Classification: JoinState

### 2.1 Enumeration

```
enum JoinState {
    Workgroup,         // not domain-joined, not Entra-joined
    AdJoined,          // classic Active Directory domain join
    HybridJoined,      // AD-joined and Entra-registered/joined
    EntraOnlyJoined,   // Entra-only (no AD)
    Unknown            // probe failed; fail-closed for mutating ops
}
```

The same five values, in the same order, in both managed
(`DdsPolicyAgent/HostState/JoinState.cs`) and native
(`DdsAuthBridge/JoinState.h`) code.

### 2.2 Probe Contract

Both probes consult the same two Win32 APIs and degrade identically when one is
unavailable.

| Signal | Outcome |
|---|---|
| `NetGetJoinInformation` → `NetSetupDomainName` | `AdJoined` (refined to `HybridJoined` if Entra signal also present) |
| `NetGetAadJoinInformation` (loaded via `GetProcAddress` / `EntryPointNotFoundException`) reports `IsJoined=TRUE` | Combined with above: `HybridJoined` |
| `NetGetJoinInformation` → `NetSetupWorkgroupName` AND `NetGetAadJoinInformation` reports `IsJoined=TRUE` | `EntraOnlyJoined` |
| `NetGetJoinInformation` → `NetSetupWorkgroupName` AND no Entra signal | `Workgroup` |
| Either probe throws / fails / returns `NetSetupUnknownStatus` | `Unknown` |

**Forbidden inputs.** `dsregcmd /status` parsing is rejected — output is not
API-stable, and shelling from a LocalSystem service introduces a process-spawn
footgun. The proposal in the gap-plan doc that allowed it as a temporary
fallback is overruled here.

**Edge cases that must behave identically in both probes:**
1. `NetGetAadJoinInformation` symbol missing on the host: treat as "no Entra
   signal", not `Unknown`.
2. `NetGetAadJoinInformation` reports `IsJoined=TRUE` with empty `TenantId`:
   still treat as Entra-joined.
3. Domain name non-empty but `joinStatus == NetSetupUnknownStatus`: `Unknown`.

### 2.3 Caching and Re-probe

- Each service caches its probe result for the process lifetime, refreshed on
  start.
- A periodic re-probe runs every **3600 seconds** (configurable via
  `JoinStateRefreshSeconds` in `AgentConfig` and an analogous setting in the
  Auth Bridge config). On state change, both services log a single
  `host_state_transition_detected` audit entry, update the cached value, and
  apply the new behavior on the next poll cycle.
- The transition workgroup → AD-joined is the only one that has stranded-state
  consequences (§9.2). All other transitions are rare in practice but handled
  by the re-probe.

---

## 3. Endpoint Behavior Matrix (Summary)

| Component | Workgroup | AdJoined / HybridJoined | EntraOnlyJoined | Unknown |
|---|---|---|---|---|
| **Policy Agent** | Enforce | Audit-only (all 4 enforcers) | Idle, log unsupported | Audit-only with distinct reason |
| **Auth Bridge — claim path** | Enabled | Refused (`PRE_ENROLLMENT_REQUIRED`) | Refused (`UNSUPPORTED_HOST`) | Refused (`UNSUPPORTED_HOST`) |
| **Auth Bridge — sign-in path** | Allowed | Allowed if vault entry exists | Refused (`UNSUPPORTED_HOST`) | Refused |
| **CP — tile enumeration** | All enrolled DDS users | Vault-backed users only | Empty + unsupported text | Empty + unsupported text |
| **Tray — initial enrollment** | Allowed | Allowed (must be in active session) | Allowed but warn it is unusable | Warn |
| **Tray — vault refresh** | Allowed | Allowed | N/A | Allowed |

Per-scenario detail is in §9.

---

## 4. Authentication Endpoint Behavior

### 4.1 Tile Enumeration (CP → Auth Bridge → dds-node)

- Workgroup: Auth Bridge returns the full enrolled-user list from `dds-node`
  joined with vault entries. CP shows all.
- AD/Hybrid: Auth Bridge intersects the dds-node list with the local vault by
  `credential_id`. Users with no local vault entry are dropped.
- Entra-only / Unknown: Auth Bridge returns an empty list with a single
  `unsupported` flag. CP shows no DDS tiles; status text from §4.4.

### 4.2 Sign-in Flow (Vault Hit)

Identical across Workgroup and AD/Hybrid:

1. CP → Auth Bridge `START_AUTH` with credential_id.
2. Auth Bridge invokes WebAuthn `GetAssertion` with `hmac-secret`.
3. Auth Bridge decrypts vault entry → recovers `(domain\user, password)`.
4. Auth Bridge resolves `domain\user` from stored SID via `LookupAccountSid`.
5. Auth Bridge packs `KERB_INTERACTIVE_UNLOCK_LOGON` and calls `LsaLogonUser`.
6. On success, CP completes the logon. Windows handles online vs. cached
   credentials transparently.

### 4.3 Sign-in Flow (No Vault Entry)

- Workgroup: claim path runs — Auth Bridge can create/reset the local account
  via `/v1/windows/claim-account`.
- AD/Hybrid: claim path is **refused before the FIDO2 ceremony** in
  `HandleDdsStartAuth`. Returns `IPC_ERROR::PRE_ENROLLMENT_REQUIRED` so the
  user is not asked to touch their key for a flow that is doomed.
- Entra-only / Unknown: returns `IPC_ERROR::UNSUPPORTED_HOST`.

### 4.4 NTSTATUS → IPC Error Mapping

The current code maps `STATUS_LOGON_FAILURE` and `STATUS_ACCOUNT_RESTRICTION /
STATUS_ACCOUNT_DISABLED` generically. v1 expands the mapping so the operator
gets specific guidance:

| NTSTATUS | IPC code | CP status text |
|---|---|---|
| `STATUS_LOGON_FAILURE` (after vault decrypt succeeded) | `STALE_VAULT_PASSWORD` | "Your DDS stored password may be out of date. Sign in normally with your Windows password, then refresh DDS from the system tray." |
| `STATUS_PASSWORD_MUST_CHANGE` (`0xC0000224`) | `AD_PASSWORD_CHANGE_REQUIRED` | "AD requires you to set a new password. Sign in normally to change it, then refresh DDS." |
| `STATUS_PASSWORD_EXPIRED` (`0xC0000071`) | `AD_PASSWORD_EXPIRED` | Same recovery path as above. |
| `STATUS_ACCOUNT_DISABLED` | (existing) `STATUS_ACCOUNT_RESTRICTION` mapping | "The account is disabled." |
| `LookupAccountSid` fails (account deleted) | `ACCOUNT_NOT_FOUND` | "This DDS account no longer exists in your directory. Contact your administrator." |
| Probe → `EntraOnlyJoined` | `UNSUPPORTED_HOST` | "DDS sign-in is not yet supported on Entra-joined machines." |
| AD/Hybrid + no vault entry | `PRE_ENROLLMENT_REQUIRED` | "DDS sign-in is available only after enrollment on this AD-joined machine." |

Distinguishing the three password-state codes matters because Windows's default
UX collapses them, leaving the operator unsure whether the issue is in DDS or
in AD.

### 4.5 Lockout Prevention

Repeating a stale-vault sign-in attempt risks tripping AD lockout policy
(default 3–10 attempts). The Auth Bridge mitigates as follows:

- After **the first** `STATUS_LOGON_FAILURE` from a vault-decrypted credential
  (FIDO2 ceremony succeeded; failure is post-decrypt), the bridge marks
  `(SID, credential_id)` as cooldown for **15 minutes**.
- During cooldown, further `START_AUTH` for that pair returns
  `STALE_VAULT_PASSWORD` immediately without invoking `LsaLogonUser`.
- Cooldown is **in-memory**, lost on service restart. A restart is itself a
  reasonable retry boundary; the goal here is rate-limiting, not audit.
- Successful refresh via the tray (§6.2) clears the cooldown for that pair.
- Cooldown duration is configurable; default 900 s. Should remain at or below
  the AD lockout reset window.

---

## 5. Policy Endpoint Behavior

### 5.1 Effective Enforcement Mode

`Worker.cs` introduces a centralized override:

```
EnforcementMode EffectiveMode(EnforcementMode requested) =>
    JoinState is AdJoined or HybridJoined or Unknown
        ? EnforcementMode.Audit
        : requested;
```

- This single function wraps every `mode` argument passed to enforcers and to
  reconciliation. No enforcer reads `JoinState` directly.
- Software dispatch (currently hardcoded `EnforcementMode.Enforce` at
  `Worker.cs:177`) routes through the same wrapper.
- On `EntraOnlyJoined`, `ExecuteAsync` short-circuits before the dispatch: the
  worker logs `unsupported_entra` once per cycle and skips polling entirely.

### 5.2 Reconciliation Matrix

The existing reconcile path already threads `mode` through stale-item cleanup
(`Worker.cs:231-285`), so the audit-only behavior extends for free once
`EffectiveMode` is in place.

| Situation | Workgroup | AD/Hybrid | Entra-only | Unknown |
|---|---|---|---|---|
| In policy + matches actual | No-op | No-op | (idle) | Audit, no-op |
| In policy + drift detected | Enforce write | Audit-log drift, no write | (idle) | Audit, no write |
| Dropped from policy + still in `applied-state` | Stale-cleanup write | **Audit-log only**, no write | (idle) | Audit, no write |
| Never DDS-managed but matches policy | Enforce | Audit | (idle) | Audit |

### 5.3 Stale-Item Handling Under Audit

When a directive disappears from policy but the host's `applied-state.json`
still owns the item:

- Workgroup: existing behavior — delete registry value, disable account,
  remove group membership, uninstall MSI.
- AD/Hybrid/Unknown: do **not** unwind. The item stays in the inventory with
  `audit_frozen: true` set on the record. AD may now own that key/account/MSI
  and unwinding could damage the host.
- A later transition back to workgroup mode (rare but possible: machine
  unjoined from AD) would clear `audit_frozen` on next reconcile and resume
  active management.

### 5.4 Entra-Only Idle Behavior

- Worker emits exactly one applied-state report per poll cycle:
  `{"item": "_host_state", "outcome": "unsupported", "reason": "unsupported_entra"}`.
- No directive evaluation, no reconciliation, no enforcer invocation.
- Default poll cadence is unchanged (60 s) so the audit log shows clear
  evidence the agent is alive and refusing.

---

## 6. Enrollment and Recovery

### 6.1 Initial Enrollment

Enrollment runs from inside an authenticated Windows session via the Tray
Agent ([EnrollmentFlow.cpp](../platform/windows/native/DdsTrayAgent/EnrollmentFlow.cpp)).

- Workgroup: unchanged.
- AD/Hybrid: unchanged mechanically — the user must already have completed a
  normal Windows sign-in (so they know their AD password). Enrollment captures
  SID + AD password and wraps under `hmac-secret`.
- Entra-only: enrollment is allowed but the tray surfaces a warning that the
  resulting vault entry will not be usable for sign-in (CP refuses on
  `UNSUPPORTED_HOST`). This is permitted only because we do not want
  enrollment to silently fail before the user sees the explanation.

### 6.2 Vault Refresh Flow (AD-13)

A new tray menu item "Refresh stored password" runs `RunRefreshVaultFlow`:

1. Tray reads the existing vault entry for the current SID (matches by SID,
   not user-selected).
2. Prompts the user for their current Windows password.
3. Performs `GetAssertion` with `hmac-secret` against the **existing**
   credential_id (no MakeCredential, no new FIDO2 credential).
4. Re-encrypts the new password under the derived key.
5. Saves vault, clears any active cooldown for the pair (§4.5).

The vault file format is unchanged — this is purely a re-wrap of the password
bytes under the same credential_id and key.

### 6.3 Stale-Vault Detection (AD-14)

Detection happens in the Auth Bridge as described in §4.4 / §4.5. The CP
surfaces the `STALE_VAULT_PASSWORD` text immediately on first failure; the
operator path is:

1. Native Windows sign-in (typing the new password).
2. From the active session, open the DDS tray menu.
3. "Refresh stored password" → enter current Windows password → tray runs
   §6.2.
4. Next DDS sign-in succeeds.

**No proactive password-change detection in v1.** Three options exist
(Credential Provider `CredentialsChanged` callback, WTS session events,
Security event log 4724/4738) and all are deferred to v2.

---

## 7. Persisted State Schema

### 7.1 `applied-state.json` Additions

Two new fields per managed-item record:

```jsonc
{
  "item": "registry:HKLM\\Software\\DDS\\Foo",
  "outcome": "applied" | "audit_only" | "drift_detected" | "stale_cleaned" | "would_clean_stale" | ...,
  "reason": "audit_due_to_ad_coexistence",   // optional, see §7.2
  "host_state_at_apply": "Workgroup",         // NEW: JoinState in effect when written
  "audit_frozen": false                        // NEW: true if stranded across host-state transition
}
```

- `host_state_at_apply` defaults to `"Unknown"` for legacy records on first
  load.
- `audit_frozen` is set when reconciliation in audit mode would have removed
  the item but couldn't.

### 7.2 Reason Code Taxonomy

| Code | Meaning |
|---|---|
| `audit_due_to_ad_coexistence` | Effective mode forced to Audit because host is AD/Hybrid |
| `audit_due_to_unknown_host_state` | Effective mode forced to Audit because probe failed |
| `unsupported_entra` | Heartbeat from idle worker on Entra-only hosts |
| `host_state_transition_detected` | Re-probe observed a JoinState change since last cycle |
| `would_apply` | Sub-reason on audit records: enforcement would have written |
| `would_correct_drift` | Sub-reason: enforcement would have corrected drift |
| `would_clean_stale` | Sub-reason: reconciliation would have unwound a stranded item |

Sub-reasons are concatenated with the primary code:
`audit_due_to_ad_coexistence:would_correct_drift`.

### 7.3 Vault File

No schema change. The same `(SID, credential_id) → encrypted_password`
structure works across Workgroup, AD-joined, and Hybrid. Refresh re-wraps the
password bytes under the same key; the file format does not need a version
bump.

---

## 8. IPC Contract

New `IPC_ERROR` codes added to
[ipc_messages.h](../platform/windows/native/DdsBridgeIPC/ipc_messages.h):

```
IPC_ERROR::UNSUPPORTED_HOST            // Entra-only / Unknown
IPC_ERROR::PRE_ENROLLMENT_REQUIRED     // AD/Hybrid + no vault entry
IPC_ERROR::STALE_VAULT_PASSWORD        // post-decrypt LsaLogonUser STATUS_LOGON_FAILURE
IPC_ERROR::AD_PASSWORD_CHANGE_REQUIRED // STATUS_PASSWORD_MUST_CHANGE
IPC_ERROR::AD_PASSWORD_EXPIRED         // STATUS_PASSWORD_EXPIRED
IPC_ERROR::ACCOUNT_NOT_FOUND           // LookupAccountSid failed
```

CP-side handling adds branches for each in `CDdsCredential.cpp:369-420` and
the parallel block at `:516-572`, mapping to the canonical strings from §4.4.
No new IPC message types are required.

---

## 9. Behavioral Scenarios (Canonical Examples)

These six scenarios are the source of truth for behavior. Tests
(§11) and acceptance criteria (§10) refer to them by number.

### 9.1 PC already AD-joined, then enrolling in DDS

**Probe result:** `AdJoined` (or `HybridJoined` if Entra-registered).

| Component | Behavior |
|---|---|
| Tray enrollment | Captures current SID + AD password. Wraps under `hmac-secret`. Vault saved. |
| Policy Agent | All four enforcers run in `Audit` via `EffectiveMode`. Reconciliation read-only. Reason: `audit_due_to_ad_coexistence`. |
| Auth Bridge sign-in (vault hit) | FIDO2 → decrypt → `KERB_INTERACTIVE_UNLOCK_LOGON` → `LsaLogonUser`. AD validates online; Windows uses cached credentials offline. |
| Auth Bridge claim path | Refused before FIDO2 ceremony with `PRE_ENROLLMENT_REQUIRED`. |
| CP tile list | Vault-backed users only. |

### 9.2 PC enrolled in DDS as workgroup, then joins AD later

**Trigger:** `netdom join` + reboot, **or** the periodic 1h re-probe (§2.3).

| Time | Behavior |
|---|---|
| Pre-join | Workgroup mode. Registry/account/PWD/software directives applied normally. Each record stamps `host_state_at_apply: Workgroup`. |
| Domain-join | Probe re-runs on next reboot or hourly tick. State changes to `AdJoined`. |
| First post-join cycle | `host_state_transition_detected` audit entry emitted once. `EffectiveMode` flips to `Audit`. |
| Reconciliation | Stale items in inventory get `audit_frozen: true`. **No automatic rollback** of registry keys, accounts, password policy, or installed MSIs. |
| Vault entries for local accounts | Mechanically still work for those local accounts. Domain users get no DDS tile until they enroll their domain account from inside an active session. |
| Operator follow-up | Manual cleanup of stranded local accounts / registry keys is supported via `applied-state.json` inventory but not automated in v1. |

### 9.3 AD changes settings DDS once owned (and vice versa)

| Direction | Behavior |
|---|---|
| AD/GPO writes a key DDS once owned | Reconciliation in audit mode detects drift, logs `audit_due_to_ad_coexistence:would_correct_drift`. **No write.** Operator sees in audit log that GPO is now authoritative. |
| DDS writes a key AD wants different (post-Phase 2) | Should not happen on AD/Hybrid — `EffectiveMode` is Audit. If observed, treat as bug. |
| AD admin disables the user | Vault survives. `LsaLogonUser` returns `STATUS_ACCOUNT_DISABLED` → existing CP mapping shows "The account is disabled." |
| AD admin deletes the user | `LookupAccountSid` fails → `ACCOUNT_NOT_FOUND` → CP shows guidance. Tray surfaces "Stale vault entry detected" notification with one-click removal. |
| AD admin renames the user | Transparent — SID-based lookup resolves the new name at sign-in. |
| AD admin changes group membership | Not relevant to auth path. Policy-side group directives are audit-only on AD/Hybrid. |

No proactive AD account-state polling. Detect-on-failure is the sole signal.

### 9.4 Reconciliation scenarios

See the matrix in §5.2. Key rules:

- Audit mode never writes, never deletes, never disables, never uninstalls.
- Stranded inventory items survive in `applied-state.json` with
  `audit_frozen: true` rather than being dropped, so a transition back to
  workgroup mode can resume management.
- On Entra-only, reconciliation is skipped entirely; the worker only emits
  the `unsupported_entra` heartbeat.

### 9.5 AD password changed outside DDS (admin reset, expiry, change from another machine)

| Step | Behavior |
|---|---|
| User attempts DDS sign-in with stale vault | FIDO2 succeeds; `LsaLogonUser` returns `STATUS_LOGON_FAILURE`. |
| First failure | Auth Bridge returns `STALE_VAULT_PASSWORD`; CP shows recovery text; bridge starts 15-min cooldown for `(SID, credential_id)`. |
| Repeated attempts during cooldown | Bridge returns `STALE_VAULT_PASSWORD` immediately without calling `LsaLogonUser` — **prevents AD lockout**. |
| Special: `STATUS_PASSWORD_MUST_CHANGE` | Maps to `AD_PASSWORD_CHANGE_REQUIRED` (distinct from stale). |
| Special: `STATUS_PASSWORD_EXPIRED` | Maps to `AD_PASSWORD_EXPIRED`. |
| Recovery | Native Windows sign-in (typing new password) → tray "Refresh stored password" → `GetAssertion` (existing credential_id) → re-wrap → vault saved → cooldown cleared. |

### 9.6 User changed their own password interactively while signed in

End state is identical to §9.5: vault is stale, recovery is the same tray
refresh flow.

**No proactive detection in v1.** Stale state surfaces on next sign-in via §9.5.

A v2 enhancement could subscribe to the Security event log (events 4724 /
4738) opportunistically and prompt the user to refresh while they are still
in an active session, but this is explicitly out of v1 scope.

---

## 10. Acceptance Criteria

This phase is complete only if all of the following are true.

1. On an AD-joined machine, DDS does **not** mutate registry, local accounts,
   password policy, services, or software state — verified by reconciliation
   audit logs across one full poll cycle.
2. On an AD-joined machine, DDS can complete FIDO2-backed sign-in for a user
   who previously enrolled on that same machine (§9.1).
3. On an AD-joined machine, DDS does not surface tiles that require
   first-claim or local-account bootstrap (§4.1).
4. On an Entra-only joined machine, DDS fails fast with a clear unsupported
   message in both the auth path and the policy-agent path (§4.4, §5.4).
5. On a workgroup machine, existing DDS behavior remains intact —
   regression-tested via the existing E2E smoke.
6. A workgroup → AD-joined transition is detected within one re-probe cycle
   (≤ 1 hour) or one service restart, whichever comes first, and emits exactly
   one `host_state_transition_detected` audit entry (§9.2).
7. After a stale AD password (§9.5), no DDS-driven AD lockout occurs across
   five rapid retry attempts. The cooldown intercepts after the first failure.
8. After a vault refresh, DDS sign-in succeeds without the user having to
   re-enroll a new FIDO2 credential.

---

## 11. Test Plan

### 11.1 Managed Tests (xUnit + NSubstitute)

- `JoinStateProbeTests` — five cases: Workgroup, AdJoined, HybridJoined,
  EntraOnlyJoined, Unknown — driven through `FakeJoinStateProbe`. Confirms
  `EffectiveMode` returns the right value for each.
- `WorkerTests` extensions — for each JoinState, drive one poll cycle and
  assert the enforcer mock was called with the expected `EnforcementMode` and
  the applied report carries the expected reason code.
- `ReconciliationAuditTests` — simulate a stale item under AD mode; assert
  inventory keeps the entry with `audit_frozen: true` and no enforcer write
  was issued.
- `EntraIdleTests` — under EntraOnly, assert worker emits the
  `unsupported_entra` heartbeat and skips dispatch.
- `HostStateTransitionTests` — flip the probe's return value mid-test; assert
  exactly one `host_state_transition_detected` entry on the next cycle.

### 11.2 Native Tests

- `test_join_state.cpp` — pure helpers (enum names, serialization round-trip
  if used in IPC) plus an opportunistic logging-only invocation of the real
  probe so developers see the result on their own host.
- `test_ad_coexistence.cpp` — three cases per §9 using
  `SetJoinStateForTest(...)` (gated by `-DDDS_TESTING`):
  1. AdJoined + populated vault → `HandleDdsStartAuth` proceeds.
  2. AdJoined + empty vault → `PRE_ENROLLMENT_REQUIRED`.
  3. EntraOnlyJoined → `UNSUPPORTED_HOST`.
- `test_lockout_prevention.cpp` — drive two rapid failed sign-ins; assert the
  second is rejected without invoking `LsaLogonUser`.
- `test_vault_refresh.cpp` — round-trip refresh: encrypt, decrypt, assert
  password and credential_id integrity.

### 11.3 E2E (PowerShell, on real or VM hosts)

- `ad_joined_smoke.ps1` — domain-joined VM:
  - workgroup baseline regression (run existing `smoke_test.ps1` first)
  - AD-joined enrollment + online sign-in
  - AD-joined offline sign-in (cached credentials path)
  - AD password reset → stale detection → tray refresh → next sign-in OK
  - Lockout prevention: 5 rapid retries do not trip AD lockout
- `entra_only_unsupported.ps1` — Entra-only VM: assert canonical unsupported
  text in CP and `unsupported_entra` heartbeat in policy agent log.
- `transition_workgroup_to_ad.ps1` — provision workgroup, enroll, apply
  policy directives, then `netdom join`, restart services, assert
  `host_state_transition_detected` and `audit_frozen` propagation.

---

## 12. Risks and Known Limitations

| # | Risk / Limitation | Mitigation |
|---|---|---|
| L1 | Stale vault after AD password change requires manual tray refresh | Documented; AD-13 ships the refresh UX; lockout prevention bounds the damage. |
| L2 | No first sign-in bootstrap on AD hosts — user must have a working AD logon first | Documented in §6.1. |
| L3 | Workgroup → AD-joined transition strands previously-applied state | Inventory preserved with `audit_frozen`; manual cleanup supported via inventory; automatic rollback is explicitly out of scope. |
| L4 | Probe is cached for service lifetime + 1h re-probe — host-state changes are detected with up to 1h delay | Acceptable for v1; documented. |
| L5 | `NetGetAadJoinInformation` registry-fallback may report false-positive Hybrid after Entra unjoin | Prefer the API call wherever available; only fall back on `EntryPointNotFoundException`. |
| L6 | No proactive AD account-state polling | Detect-on-failure (§9.3) is sufficient for v1. |
| L7 | Cooldown is in-memory; service restart resets the counter | Acceptable; restart is itself a retry boundary. |
| L8 | No proactive detection of in-session password change (§9.6) | v2 work via Security event log. |

---

## 13. History

- **2026-04-13** — [AD-gap-plan.md](AD-gap-plan.md) drafted as the initial gap
  analysis and proposed backlog (AD-01 through AD-17).
- **2026-04-25** — This specification locked. Six behavioral scenarios
  analyzed against the actual codebase. Cross-cutting decisions confirmed:
  periodic re-probe at 1h, `host_state_at_apply` schema field, expanded
  reason-code taxonomy, six new `IPC_ERROR` codes, 1-failure / 15-minute
  lockout-prevention cooldown, audit-mode reconciliation preserves stranded
  inventory with `audit_frozen`, no proactive AD account polling.

---

# Appendix A — Implementation Plan

The 17-task backlog from [AD-gap-plan.md §6](AD-gap-plan.md) is refined here
into code-level deliverables.

## A.1 Phasing

The 5-phase split holds, with these refinements:

- Phase 1 lands managed and native halves in the **same PR**. A window where
  the policy agent and auth bridge disagree about host classification is the
  worst possible bug.
- AD-07 (reason codes) lands with — or before — AD-04/05/06; otherwise Phase 2
  ships hardcoded strings that AD-07 then has to refactor.
- Phase 3: AD-08 → AD-09 → AD-10 → AD-11.
- Phase 4: AD-14 (stale detection) before AD-13 (refresh flow), since the
  refresh flow needs a trigger.

## A.2 JoinState Model Placement

### Managed (C#)

- `c:\ABCD\platform\windows\DdsPolicyAgent\HostState\JoinState.cs` — enum.
- `c:\ABCD\platform\windows\DdsPolicyAgent\HostState\IJoinStateProbe.cs` — seam.
- `c:\ABCD\platform\windows\DdsPolicyAgent\HostState\WindowsJoinStateProbe.cs` —
  production probe with cached value + re-probe scheduling.
- DI registered in
  `c:\ABCD\platform\windows\DdsPolicyAgent\Program.cs:109`.
- `IAccountOperations.IsDomainJoined()`
  ([IAccountOperations.cs:53](../platform/windows/DdsPolicyAgent/Enforcers/IAccountOperations.cs#L53))
  removed; the P/Invokes for `NetGetJoinInformation` move to the new probe.

### Native (C++)

- `c:\ABCD\platform\windows\native\DdsAuthBridge\JoinState.h` — enum + free
  function `DetectJoinState()`.
- `c:\ABCD\platform\windows\native\DdsAuthBridge\JoinState.cpp` — impl + cache
  via `std::once_flag` + periodic refresh thread.
- `CDdsAuthBridgeMain::IsDomainJoined()`
  ([DdsAuthBridgeMain.h:115](../platform/windows/native/DdsAuthBridge/DdsAuthBridgeMain.h#L115))
  replaced by `static JoinState GetJoinState()`.

## A.3 Per-Task Deliverables

### Phase 1 — Join-State Foundation

| Task | Files | Function-level change |
|---|---|---|
| **AD-01** | New: `JoinState.cs`, `IJoinStateProbe.cs`, `JoinState.h`. Modify: `AccountEnforcer.cs:34,208,250`, `IAccountOperations.cs:53`, `WindowsAccountOperations.cs:18-25`, `InMemoryAccountOperations.cs:118`, `DdsAuthBridgeMain.h:115`, `DdsAuthBridgeMain.cpp:487-500,1035`. | Replace `_ops.IsDomainJoined()` with injected probe; remove interface method; replace native static helper with `GetJoinState()`. |
| **AD-02** | `WindowsJoinStateProbe.cs`, `JoinState.cpp`. | P/Invoke `NetGetJoinInformation` + `NetGetAadJoinInformation` (managed); load `netapi32.dll` + `GetProcAddress` for `NetGetAadJoinInformation` (native). Catch missing-symbol case → "no Entra signal". Periodic re-probe via `IHostedService` (managed) and a dedicated thread (native). |
| **AD-03** | `JoinStateProbeTests.cs`, `test_join_state.cpp` + `build_test_join_state.bat`. | Five managed test cases via `FakeJoinStateProbe`. Native tests run pure helpers; real-host probe is logged not asserted. |

### Phase 2 — Safe Policy Coexistence

| Task | Files | Change |
|---|---|---|
| **AD-07** | `Client/DdsNodeClient.cs:53-75 AppliedReport`, new `State/AppliedReason.cs`, `Worker.cs:343 ReportAsync`. | Add `Reason` JSON property; declare reason-code constants; thread `reason` through `ReportAsync`. |
| **AD-04** | `Worker.cs:91 PollAndApplyAsync`, `:64 ExecuteAsync`. | Inject `IJoinStateProbe`, cache result on start. Add `EffectiveMode(EnforcementMode)` helper, wrap every `mode` argument passed to enforcers and reconciliation. |
| **AD-05** | `Worker.cs:177` software dispatch, `Worker.cs:284` reconcile dispatch. | Replace hardcoded `EnforcementMode.Enforce` with `EffectiveMode(EnforcementMode.Enforce)`. |
| **AD-06** | `Program.cs`, `Worker.cs:64`. | On `EntraOnlyJoined`, short-circuit `ExecuteAsync` to a heartbeat-only loop reporting `unsupported_entra`. |
| **(AD-04/05 schema)** | `State/AppliedStateStore.cs:47`. | Add `host_state_at_apply` and `audit_frozen` fields. Default legacy records to `Unknown` / `false`. |

### Phase 3 — Authentication Coexistence

| Task | Files | Change |
|---|---|---|
| **AD-08** | `DdsAuthBridgeMain.cpp:696 HandleDdsStartAuth`, `:1035`, `DdsBridgeIPC/ipc_messages.h`. | Move the join-state gate to before the FIDO2 ceremony. Switch on `GetJoinState()` returning `PRE_ENROLLMENT_REQUIRED` / `UNSUPPORTED_HOST` / proceed. Add new `IPC_ERROR` codes. |
| **AD-09** | `DdsAuthBridgeMain.cpp:1193 HandleDdsListUsers`, `CredentialVault.{h,cpp}`. | Intersect dds-node user list with vault by credential_id on AD/Hybrid. Add `VaultHasCredentialId(...)` helper. EntraOnly returns empty list. |
| **AD-10** | `CDdsCredential.cpp:369-420`, `:516-572`. | Extend `errorCode` switch for the six new IPC codes; map to canonical strings from §4.4. |
| **AD-11** | `Tests/test_ad_coexistence.cpp`, `build_test_ad_coexistence.bat`, `JoinState.h` (`SetJoinStateForTest` under `-DDDS_TESTING`). | Three native tests per §11.2. Register in `run_all_tests.bat`. |
| **AD-04/05 NTSTATUS expansion** | `DdsAuthBridgeMain.cpp` (LsaLogonUser result handling). | Map `STATUS_PASSWORD_MUST_CHANGE` / `STATUS_PASSWORD_EXPIRED` / `STATUS_LOGON_FAILURE` (post-decrypt) / `LookupAccountSid` failure to the corresponding new IPC codes. |
| **(Lockout prevention)** | `DdsAuthBridgeMain.{h,cpp}`. | Per-`(SID, credential_id)` cooldown map (in-memory); 15-min default; cleared on successful refresh. |

### Phase 4 — Enrollment And Recovery UX

| Task | Files | Change |
|---|---|---|
| **AD-14** | `DdsAuthBridgeMain.cpp` LsaLogonUser handler. | Already covered by AD-08+NTSTATUS expansion above. |
| **AD-13** | New `DdsTrayAgent/RefreshVaultFlow.{h,cpp}`, modify `DdsTrayAgent.cpp` (menu). | Existing credential_id, `GetAssertion`, re-wrap, save. No new credential. Clear cooldown. |
| **AD-12** | `docs/windows-ad-coexistence-spec.md` (this doc) operator appendix or a new `docs/windows-ad-enrollment.md`; tray text strings in `EnrollmentFlow.cpp:126`. | Operator workflow documentation; clarify enrollment password prompt on AD hosts. |

### Phase 5 — End-to-End Validation

| Task | Files | Change |
|---|---|---|
| **AD-15** | `e2e/ad_joined_smoke.ps1`, `e2e/README.md`. | Domain-joined VM E2E covering §11.3 cases. |
| **AD-16** | `e2e/entra_only_unsupported.ps1`. | Entra-only VM E2E. |
| **AD-17** | `security-gaps.md` follow-up section. | Document password-replay model on domain accounts; lockout-prevention security review. |

## A.4 Test Strategy

- Managed: `IJoinStateProbe` is the only seam needed. NSubstitute stubs each
  state. No real domain-joined VM required for unit tests.
- Native: `SetJoinStateForTest` gated by `-DDDS_TESTING` so production binaries
  cannot have their state overridden.
- Vault refresh testable via temp-file path override
  (`DDS_VAULT_PATH_OVERRIDE` env var, new — added in
  `CredentialVault.cpp::GetVaultFilePath`).

---

# Appendix B — First PR Scope (Phase 1 Only)

Pure refactor + new probe, **zero behavior change**. The aim is to land the
JoinState seam on both sides without altering any user-visible flow.

## B.1 Files Added

- `platform/windows/DdsPolicyAgent/HostState/JoinState.cs`
- `platform/windows/DdsPolicyAgent/HostState/IJoinStateProbe.cs`
- `platform/windows/DdsPolicyAgent/HostState/WindowsJoinStateProbe.cs`
- `platform/windows/DdsPolicyAgent.Tests/HostState/JoinStateProbeTests.cs`
- `platform/windows/native/DdsAuthBridge/JoinState.h`
- `platform/windows/native/DdsAuthBridge/JoinState.cpp`
- `platform/windows/native/Tests/test_join_state.cpp`
- `platform/windows/native/Tests/build_test_join_state.bat`

## B.2 Files Modified

- `platform/windows/DdsPolicyAgent/Program.cs` — DI register `IJoinStateProbe`.
- `platform/windows/DdsPolicyAgent/Enforcers/AccountEnforcer.cs:34,208,250` —
  inject probe; constructor change.
- `platform/windows/DdsPolicyAgent/Enforcers/IAccountOperations.cs:53` —
  remove `IsDomainJoined()`.
- `platform/windows/DdsPolicyAgent/Enforcers/WindowsAccountOperations.cs:18-25` —
  drop impl; move `NetGetJoinInformation` P/Invoke to the probe.
- `platform/windows/DdsPolicyAgent/Enforcers/InMemoryAccountOperations.cs:118` —
  drop impl.
- `platform/windows/DdsPolicyAgent.Tests/WorkerTests.cs:36-56` — adjust
  constructor call if signature changes (it does not in this PR; AD-04 will).
- `platform/windows/native/DdsAuthBridge/DdsAuthBridgeMain.h:115` — replace
  `IsDomainJoined()` with `GetJoinState()`.
- `platform/windows/native/DdsAuthBridge/DdsAuthBridgeMain.cpp:487-500,1035` —
  delete old impl; preserve current behavior at line 1035 with
  `GetJoinState() != JoinState::Workgroup`.
- `platform/windows/native/DdsAuthBridge/DdsAuthBridge.vcxproj` — add
  `JoinState.cpp`.
- `platform/windows/native/Tests/run_all_tests.bat` — register the new test.

## B.3 Reviewer Checklist

1. Behavior is **unchanged**. AccountEnforcer still rejects on AD/Hybrid;
   Registry/PWD/Software still apply on AD (the Phase 2 wrong behavior is
   preserved here, intentionally).
2. The two probes return the same value on the same host. Manual verification
   on a workgroup dev box: managed unit test logs `Detect() == Workgroup`;
   native `test_join_state.exe` prints `Workgroup`.
3. `NetGetAadJoinInformation` failure modes degrade to `Unknown` rather than
   throwing.
4. No new dependency on `dsregcmd` or `Process.Start`.
5. The `IJoinStateProbe` seam is clean enough for AD-04 worker tests to use
   without further refactoring.
6. The native `SetJoinStateForTest` seam is gated by `-DDDS_TESTING` and not
   present in the production binary.
7. Periodic re-probe schedule (1h default) is configurable and disabled by
   default in unit-test contexts.
