# FIDO2 login `0x8000401A` — root cause, fix plan, verification

**Status:** root cause proven (high confidence) 2026-07-02. Stage 1 (honest UX +
diagnostics) landed and build-verified. Stage 2 (raw-CTAP fallback) designed,
gated on a physical-key parity test. Cold-boot passwordless login is **still
broken** until Stage 2 ships.

## Symptom

At the lock screen, DDS FIDO2 sign-in fails instantly: `dds_cp.log` shows
`WebAuthNAuthenticatorGetAssertion` returning `CO_E_RUNAS_LOGON_FAILURE
(0x8000401A)` in 15–47 ms, no prompt, the security key never blinks. On this
ARM64 Win 11 Home VM: 6 successes on 2026-06-13, then 13 straight failures on
06-14/15, nothing since (user on password fallback for 17 days).

## Root cause

`WebAuthNAuthenticatorGetAssertion` on the secure desktop internally DCOM-activates
the credential-UX broker chain (`CredentialUIBroker.exe`, `ShellServiceHost`,
`ImmersiveShell`). On this machine those AppIDs are all registered
**`RunAs="Interactive User"`** (verified in `HKCR\AppID`). That COM identity can
only be launched once an **interactive logon token exists in the session**.
Before the **first** interactive logon of a boot, no such token exists →
activation fails instantly with `0x8000401A`, before CTAP is ever dispatched.

**Discriminator (holds across 26 failing calls + 6 successes, zero
counterexamples):** the call fails **iff** no interactive user has logged on
since boot. NgcSvc ("Microsoft Passport") is already RUNNING at every failure,
and NgcCtnrSvc ("Microsoft Passport Container") is up too — so the 256th-pass
"NgcSvc idle-stop" theory and its re-kick are wrong; no service action fixes this.

**ARSO refinement (confirmed live 2026-07-02 22:18):** on a *clean restart
initiated from inside a logged-in session*, Windows ARSO (automatic restart
sign-on, default ON for Home; `DisableAutomaticRestartSignOn` unset here)
silently re-logs the user in ~4 s after boot (Security 4624 LT=2 via svchost at
22:17:57, boot 22:17:53) — so an interactive token already exists at the first
logon screen and FIDO2 succeeds (observed: attempt=0 `hr=0` with hmac-secret).
The failing case therefore requires a boot with NO ARSO restore: **crash/forced
power-off boots, restarts initiated from the logon screen, or ARSO disabled by
policy**. All 13 June failures fall in the first two buckets. Production impact:
consumer default-ARSO machines rarely hit this; **enterprise baselines (CIS)
commonly set `DisableAutomaticRestartSignOn=1`, making every reboot hit the
broken case** — Stage 2 remains the production fix.

Corroboration: Microsoft documents `RunAs="Interactive User"` servers failing
`0x8000401A` when no user is logged on ("by design"); MS Q&A reproduces this exact
WebAuthn-from-credential-provider case with no fix; Windows' own Web Sign-In works
around it by first logging on a throwaway `WsiAccount`; Yubico/HYPR use raw CTAP
at the logon screen rather than `webauthn.dll`.

## Stage 1 — landed 2026-07-02 (does not restore passwordless cold boot)

`DdsBridgeClient.cpp`: `AnyInteractiveUserSessionCP()` probe; honest tile message
on the pre-first-logon case; `interactiveUserPresent` recorded in the failure log.
Built clean `Release|ARM64` + `Release|x64`. Purpose: stop the misleading error,
make field failures unambiguous. Users still type a password once per cold boot.

## Stage 2 — the real fix (raw CTAP2-over-HID fallback), GATED

The bridge (`DdsAuthBridge`, LocalSystem, session 0) opens FIDO HID devices
directly and performs `getAssertion` + hmac-secret with **no UI broker**, so it
works before first logon. Building blocks already in-repo, compiled but unused:
`DdsAuthBridge/ctap2/ctap2_protocol.{h,cpp}` (get-assertion + hmac-secret CBOR),
`ctap2_pin_protocol.{h,cpp}` (PIN-protocol-1 ECDH P-256 + salt enc/dec), `cbor.cpp`.

Missing pieces to build:
1. `ctap2/ctaphid_transport.{h,cpp}` — enumerate HID usage page `0xF1D0`, open,
   `CTAPHID_INIT` (channel alloc), 64-byte CBOR framing + continuations,
   `KEEPALIVE` (UP-needed) during touch, error frames, ~55 s timeout. Port the
   SetupDi enumeration from `DdsBridgeClient.cpp::AnyFidoHidDevicePresent`.
2. IPC `DDS_CTAP_FALLBACK (0x0066)` in `DdsBridgeIPC/ipc_protocol.h` + a payload
   struct `{seqId, clientDataHash[32]}` in `ipc_messages.h`; response reuses the
   existing `DDS_AUTH_COMPLETE`/`DDS_AUTH_ERROR` flow (bridge already holds the
   challenge, rpId, allow-list and salts for the seqId).
3. `DdsAuthBridgeMain.cpp` — new case in the `OnIpcRequest` dispatch that runs
   raw `getAssertion` and hands the assertion to the existing per-seqId worker.
4. `DdsBridgeClient.cpp` `HandleWebAuthnChallenge` — on `0x8000401A` (and other
   activation HRESULTs) with no interactive session, send `DDS_CTAP_FALLBACK`
   instead of the doomed re-kick+retry; keep cancel machinery wired to abort the
   bridge-side CTAP wait.

### HARD GATE before writing any of Stage 2

**Prove hmac-secret parity.** The raw-CTAP hmac-secret output (options `up=true`,
UV state matching enrollment, PIN-protocol-1 salt encryption) MUST equal what
`webauthn.dll` produced when the credential was enrolled — otherwise every vault
password decrypt fails. CTAP2 authenticators keep two CredRandoms (UV-true vs
UV-false); the CP already hit an hmac-output change from a flag difference once
before. Build a bridge self-test (`DdsAuthBridge --ctap-selftest`) run from the
user's session that does a raw-CTAP getAssertion against the enrolled credential
and confirms the vault envelope decrypts. **If parity fails, the plan changes
(needs PIN/UV-token support) — do not build the logon path until this passes.**

## Stage 2 — BUILT 2026-07-03 (raw-CTAP logon fallback)

Parity was **empirically confirmed** on the user's bio key: the PRF-transformed salt
reproduced webauthn's hmac-secret and decrypted the vault. Stage 2 is built on that:

- `DdsAuthBridge/ctap2/ctap_authenticator.{h,cpp}` — `CtapAuthenticator::GetAssertionWithHmac`:
  raw CTAP2 getAssertion over HID with the PRF salt transform baked in, iterating the
  offered credentials until the present one is found. Interruptible via a cancel event.
- IPC `DDS_CTAP_FALLBACK` (0x0066); `IPC_PIPE::CTAP_FALLBACK_TIMEOUT_MS` = 45 s.
- Bridge: `HandleDdsCtapFallback` (validates seqId **and** clientId), and
  `RunCtapFallbackFill` in the worker — builds the same clientDataJSON as the CP,
  runs the raw getAssertion, and fills `responseData` so the unchanged downstream
  (POST /v1/session/assert + vault decrypt + DDS_AUTH_COMPLETE) proceeds.
- CP (`DdsBridgeClient.cpp`): on WebAuthn `0x8000401A`, sends `DDS_CTAP_FALLBACK` and
  keeps waiting instead of failing.

Built clean Release ARM64+x64, 0 warnings. Passed a 4-lens adversarial review; the
confirmed critical/high concurrency + lifetime findings were fixed before this build:
interruptible CTAP HID I/O (cancel event through the transport), a per-spawn opToken
so a superseded worker can't recycle the successor's slot, shutdown joins the worker
to completion, a 45 s CTAP window shorter than the CP's 60 s budget, and the CTAP hmac
key zeroed on the worker's local copy.

**Deferred (not blocking a supervised cold-boot smoke test; fix before unsupervised use):**
- **F4** — the fallback's progress/error IPC sends use the unvalidated `pClientCtx` path
  (not the clientId-checked `SendResponseToClient`); the interruptible+45 s window narrows
  the race but a torn/wrong-client *non-secret* progress frame is still possible. The
  password path stays clientId-gated.
- **F11** — no live "touch your key" tile text during the fallback (LogonUI reads the
  status out-param once). Mitigated: **the security key physically blinks** during the
  getAssertion, which is the cue. A proper `SetFieldString` cue is a follow-up.
- **F6** — parity is proven on the user's *bio* key; a PIN-only key whose enrollment ran
  under UV could need `CredRandomWithUV` (the fallback is UP-only). Fails **closed** (vault
  decrypt error), never a security hole. Validate the self-test on a PIN-enabled non-bio
  key before shipping to that population.

## Verification plan (needs the user + physical key on THIS machine)

**Phase 0 — reconfirm the repro on today's build (no code needed):**

> **ARSO trap (live-confirmed 2026-07-02 22:27): a logon-screen restart is NOT
> sufficient to reproduce.** After any clean restart, ARSO has already signed
> the user in ~4 s post-boot, so the "login screen" is really the lock screen of
> a hidden live session — clicking Restart there re-arms ARSO for the next boot
> (verified: winlogon 1074 at 22:26:45 → boot 22:26:59 → ARSO 4624 LT=2 at
> 22:27:03.7 → FIDO2 succeeded). Clean restarts are self-sustaining; the chain
> must be broken explicitly.

1. Break the ARSO chain, then attempt FIDO2 **before** any sign-in. Either:
   (a) **force power-off** (QEMU hard reset / hold power) and boot — crash
   boots never restore ARSO; this is exactly the June failure condition; or
   (b) **sign out first** (ending the session), then power → Restart from the
   logon screen, then attempt FIDO2 after boot.
   Expect `dds_cp.log`: `0x8000401A` in <500 ms on both attempts (and, once the
   Stage-1 DLL is installed, `interactiveUserPresent=0`);
   WebAuthN/Operational shows `CreateTicket` → `Error=0x8000401a`, no CTAP
   GetAssertion. Then log in with password.
2. From the logged-in session, `Win+L` lock, attempt FIDO2 → **expect success**
   (warm path), reconfirming the discriminator on today's build.

**Phase 1 — hmac-secret parity self-test (BUILT 2026-07-02, awaiting a run):**
From an elevated prompt with the enrolled key inserted, run the freshly built
bridge:
`C:\ABCD\platform\windows\native\build\Release-ARM64\DdsAuthBridge.exe --ctap-selftest`
It loads the vault, does a raw-CTAP2 getAssertion (up=true, no UV, stored salt)
per credential, and checks the AES-GCM vault password decrypts. It never prints
the password or its length. Touch the key when prompted. Exit codes:
`0`=PARITY CONFIRMED (Stage 2 viable) · `1`=mixed · `2`=no/unreadable vault ·
`3`=inconclusive (key not the enrolled one) · `4`=parity failed (real mismatch) ·
`5`=needs-UV (key forces UV — Stage 2 needs pinUvAuthToken). Also written to
`%ProgramData%\DDS\authbridge.log`. The transport + driver
(`ctap2/ctaphid_transport.*`, `ctap2/ctap_selftest.*`) passed a 4-lens adversarial
review (transport framing, hmac-secret parity semantics, memory safety,
integration); the review's critical/high/medium findings were fixed before this
build. Blocks Stage 2 until it returns 0.

**Phase 2 — cold-boot fix verification** (after Stage 2): install MSI, Restart,
at the first logon screen trigger FIDO2 → key blinks pre-logon (first time ever),
touch, `DDS_AUTH_COMPLETE`, Security log `4624 LogonType=2` with no password
typed. Repeat 3× plus once after a forced power-off boot.

**Phase 3 — warm regression:** logon + `Win+L` + FIDO2 must still take the
webauthn.dll primary path (no fallback lines). **Phase 4 — abort paths:** pull
key mid-touch and select-another-tile must not wedge LogonUI. **Phase 5 — soak:**
one week FIDO2-only across reboots, zero `0x8000401A`-terminal failures.

## Log checkpoints

`%ProgramData%\DDS\logs\dds_cp.log`, `authbridge.log`;
`Microsoft-Windows-WebAuthN/Operational`; Security `4624`/`4625`;
`Microsoft-Windows-HelloForBusiness/Operational` `8025`.
