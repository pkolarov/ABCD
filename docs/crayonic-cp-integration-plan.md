# Crayonic Credential Provider — DDS Integration Plan

**Date:** 2026-04-10
**Source:** `/Users/peter/Dev/Crayonic/CP` branch `feature/bridge-service-integration`
**Target:** `/Users/peter/ABCD/platform/windows/`

**Status (2026-04-13):** the current tree has the native DDS
Credential Provider + Auth Bridge login path implemented, including
`/v1/session/assert`, `/v1/enrolled-users`, and the first-account
claim path via `/v1/windows/claim-account`. This document remains the
architecture/rationale record plus the list of packaging work still
left to do.

---

## 1. Executive Summary

The Crayonic Credential Provider (CP) is a **production-grade native C++
Windows Credential Provider** with BLE-connected FIDO2 hardware
authenticator support. Integrating it into the DDS Windows platform gives
us a real CP implementation (solving blocker B1), a working CTAP2/hmac-secret
stack, and a BLE connection manager — all things we'd otherwise build
from scratch.

**What we get from Crayonic:**

| Component | Value | Effort to Integrate |
| --- | --- | --- |
| CP COM shell (ICredentialProvider, ICredentialProviderCredential) | Production-quality COM impl with tile management, auto-logon, re-enumeration | Medium — needs new auth backend |
| CTAP2 protocol engine (makeCredential + getAssertion) | Complete CBOR codec, hmac-secret extension, PIN protocol | Low — reuse as-is |
| BLE connection manager | WinRT BLE GATT, scanning, proximity, reconnection | Skip for DDS v1 (see §3) |
| Named-pipe IPC (CrayonicBridgeIPC) | Clean TLV protocol, extensible message catalog | Medium — extend with DDS messages |
| Bridge Service architecture | Windows Service scaffold, credential vault, session management | Medium — merge with DdsPolicyAgent or run alongside |
| WiX installer | MSI packaging, COM registration, service install | Low — merge into DDS WiX bundle |
| Tests | CTAP2, IPC, BLE, enrollment, CP lockout tests | Low — adapt test harness |

**What we must change:**

| Layer | Crayonic Today | DDS Target |
| --- | --- | --- |
| Trust anchor | Windows domain / local SAM | Vouchsafe trust graph via dds-node |
| Auth backend | hmac-secret → plaintext password → KERB_INTERACTIVE_UNLOCK_LOGON | FIDO2 assertion → DDS session token (+ optional password bridge for v1) |
| Identity model | Windows SID | Vouchsafe URN (`urn:vouchsafe:passkey.<hash>`) |
| User enumeration | Bridge Service vault (enrolled SIDs) | dds-node trust graph (enrolled device + user URNs) |
| Credential storage | DPAPI-encrypted vault.dat | DDS trust graph (attestation tokens) |

---

## 2. Architecture Decision: Three Components, Not Two

The Crayonic architecture has CP (DLL) ↔ Bridge Service (Windows Service)
communicating over named pipes. DDS already has `dds-node` (Rust, Windows
Service) and `DdsPolicyAgent` (.NET, Windows Service). The key decision:

**Recommended: Keep Bridge Service separate from dds-node and DdsPolicyAgent.**

```
                      Windows Logon Screen
                              │
                    ┌─────────┴──────────┐
                    │  DDS Credential    │  (C++ DLL, COM)
                    │  Provider          │  merged from Crayonic CP
                    │  CLSID: {new}      │
                    └─────────┬──────────┘
                              │ named pipe (extended IPC)
                    ┌─────────┴──────────┐
                    │  DDS Auth Bridge   │  (C++, Windows Service)
                    │  Service           │  merged from Crayonic Bridge
                    │                    │
                    │  • CTAP2 engine    │──── BLE ──── FIDO2 HW Key
                    │  • Session mgmt   │       (optional, Phase 2+)
                    │  • dds-node client│
                    └─────────┬──────────┘
                              │ HTTP 127.0.0.1:5551
                    ┌─────────┴──────────┐
                    │  dds-node          │  (Rust, Windows Service)
                    │  • Trust graph     │
                    │  • Policy eval     │
                    │  • Gossip + sync   │
                    │  • /v1/session/assert │
                    │  • /v1/windows/*   │
                    └────────────────────┘
```

**Rationale:**
- The CP DLL runs **inside LogonUI's process** (STA, restricted).
  It cannot make HTTP calls or run async Rust. It needs a local
  service to broker requests — this is exactly what Bridge Service does.
- Bridge Service already handles the BLE/CTAP2 stack and credential
  vault. Adding an HTTP client to dds-node is a small extension.
- dds-node stays a pure Rust directory service. No C++ dependencies.
- DdsPolicyAgent stays a policy enforcer. No auth logic.

---

## 3. Component Disposition

### 3.1 Keep and Adapt

| Crayonic Component | Disposition | Changes Needed |
| --- | --- | --- |
| **CrayonicCredentialProvider/** (CP DLL) | Fork → `DdsCredentialProvider/` (C++) | Replace CLSID; add DDS auth path in `GetSerialization`; enumerate users from dds-node instead of vault |
| **CrayonicBridgeIPC/** (IPC library) | Fork → `DdsBridgeIPC/` | Add new message types for DDS session flow |
| **CrayonicBridgeService/** (Windows Service) | Fork → `DdsAuthBridge/` | Add dds-node HTTP client; wire DDS session issuance; keep CTAP2 engine |
| **CrayonicBridgeService/ctap2/** | Keep as-is | No changes — CTAP2 protocol is standard |
| **Helpers/** (COM factory, DLL entry) | Keep, update GUIDs | New CLSID for DDS CP |
| **Tests/** | Adapt test harness | Mock dds-node HTTP responses |
| **CrayonicCredentialProvider.wxs** | Merge into DDS WiX bundle | Add dds-node + DdsPolicyAgent components |

### 3.2 Skip for v1

| Crayonic Component | Reason |
| --- | --- |
| **BLE stack** (BleScannerWinRT, BleGattClientWinRT, BleConnectionManager) | DDS v1 targets platform authenticators (Windows Hello, USB keys), not BLE badges. BLE is a Phase 2+ add-on. |
| **CrayonicSCRemovalPolicy/** | Smart card removal lock — irrelevant for FIDO2/passkey flow |
| **CrayonicEnrollment/** | DDS enrollment is via `dds-cli` or a future web UI, not a tray app |
| **PIV/CCID paths** (CcidExchange, certificate flows) | DDS uses Vouchsafe tokens, not X.509/PIV |

### 3.3 Replace with DDS Equivalent

| Crayonic Piece | DDS Replacement |
| --- | --- |
| Credential vault (DPAPI vault.dat) | dds-node trust graph (attestation + vouch tokens) |
| User enumeration from vault | HTTP `GET /v1/enrolled-users?device_urn=...` (new endpoint) |
| Password bridge / claim seeding | DDS session token from `/v1/session/assert` + hmac-secret-backed vault bridge (§5) |
| `KERB_INTERACTIVE_UNLOCK_LOGON` packing | Keep for v1 hybrid; Phase 2 moves to custom LSA Authentication Package |

---

## 4. The Authentication Flow — Before and After

### 4.1 Crayonic Today

```
User clicks tile → CP calls BridgeClient::AuthenticateFido()
  → IPC START_AUTH_FIDO(sid, rpId="crayonic.local.login")
  → Bridge Service: CTAP2 GetAssertion via BLE to KeyVault
  → hmac-secret output → derive plaintext password from vault
  → IPC AUTH_COMPLETE_FIDO(domain, username, password)
  → CP packs KERB_INTERACTIVE_UNLOCK_LOGON
  → LSA verifies password against SAM/AD → logon
```

### 4.2 DDS Target (v1 — Hybrid Bridge)

```
User clicks tile → CP calls DdsBridgeClient::AuthenticateDds()
  → IPC DDS_START_AUTH(selected_subject_urn, credential_id)
  → Auth Bridge Service:
      1. CTAP2 GetAssertion to platform authenticator (USB/platform)
         rpId = "dds.local"
         with hmac-secret extension
      2. HTTP POST /v1/session/assert to dds-node with the assertion proof
      3. dds-node validates the assertion against the trust graph and
         returns a local `dds:session` token
      4a. If a vault entry already exists:
            Auth Bridge derives the Windows password from hmac-secret
            and completes logon
      4b. If no vault entry exists yet:
            POST /v1/windows/claim-account(device_urn, session_token)
            → dds-node resolves the one policy-authorized local account
            → Auth Bridge generates a random Windows password locally
            → creates/resets the local account and applies groups/flags
            → wraps the password into the local vault with hmac-secret
  → IPC DDS_AUTH_COMPLETE(domain, username, password, session_token_b64)
  → CP packs KERB_INTERACTIVE_UNLOCK_LOGON (password-based logon)
  → LSA verifies password → logon
```

### 4.3 DDS Target (v2 — Pure Token)

```
Same as v1, but:
  - Auth Bridge does NOT derive a password
  - CP packs a custom LSA Authentication Package struct
  - Custom AP validates the DDS session token directly
  - No Windows password needed
```

v2 requires writing a custom LSA Authentication Package (C++, kernel-adjacent,
must be signed). This is a multi-week effort and should be deferred.

---

## 5. The Password Bridge Problem

Windows LogonUI / LSA requires one of:
1. A plaintext password (`KERB_INTERACTIVE_UNLOCK_LOGON`)
2. A smart card + PIN (`KERB_SMARTCARD_CSP_INFO`)
3. A custom Authentication Package blob

Crayonic solves this with hmac-secret: the FIDO2 authenticator's
hmac-secret extension produces a deterministic 32-byte key from a
per-credential secret + a salt. The Bridge Service uses this to
decrypt the user's stored Windows password from the vault.

**DDS v1 still needs the same bridge** because we do not have a custom
LSA authentication package yet, but DDS now supports two vault-seeding
modes:

1. **Existing local account enrollment** — the user's current Windows
   password is captured once during enrollment, encrypted with
   hmac-secret, and stored in the local vault.
2. **Policy-bound first claim** — when no vault entry exists and policy
   binds `claim_subject_urn` to a local account, the Auth Bridge
   generates a random password locally on the first successful DDS
   logon, sets that password on the claimed Windows account, and then
   encrypts it into the vault with hmac-secret.

In both cases, later logons regenerate the same hmac-secret output,
decrypt the vault entry, and hand the password to
`KERB_INTERACTIVE_UNLOCK_LOGON`.

**DDS-specific addition:** After successful Windows logon, the CP also
holds a DDS session token. Post-logon processes (DdsPolicyAgent, DDS
CLI) can use this token for directory operations without re-authenticating.

---

## 6. FIDO2 Logic Merge

### What DDS Has (Rust, `dds-domain/src/fido2.rs`)

- Attestation parsing only (makeCredential response)
- Ed25519 self-attestation + `none` format
- CBOR via ciborium
- No assertion (getAssertion) support
- No hmac-secret

### What Crayonic Has (C++, `CrayonicBridgeService/ctap2/`)

- Full CTAP2: makeCredential + getAssertion + getInfo + clientPIN
- ECDH P-256 key agreement for hmac-secret
- PIN protocol v1/v2
- Custom CBOR encoder/decoder
- Supports ES256 (P-256), RS256; no Ed25519

### Merge Strategy

**Do NOT merge the codebases.** They serve different purposes at
different layers:

| Function | Implementation | Language | Where |
| --- | --- | --- | --- |
| Enrollment attestation validation | DDS `fido2.rs` (Rust) | Rust | dds-node |
| Logon-time getAssertion | Crayonic `ctap2_protocol` (C++) | C++ | DDS Auth Bridge |
| hmac-secret key agreement | Crayonic `ctap2_protocol` (C++) | C++ | DDS Auth Bridge |
| Assertion signature verification | **New**: add to DDS `fido2.rs` or `dds-node` service | Rust | dds-node |

**Implemented in DDS Rust side:**
- `verify_assertion(auth_data, client_data_hash, signature, public_key)` in
  `dds-domain/src/fido2.rs`
- Ed25519 + ECDSA P-256 assertion verification
- `POST /v1/session/assert`
- `GET /v1/enrolled-users`
- `POST /v1/windows/claim-account`

**Implemented in Auth Bridge:**
- WinHTTP client for `/v1/session/assert`, `/v1/enrolled-users`, and
  `/v1/windows/claim-account`
- DDS-specific IPC messages (§7)
- First-account claim mode that seeds the vault on the first successful
  DDS logon when policy authorizes a local account claim
- Crayonic CTAP2 engine retained for getAssertion + hmac-secret

---

## 7. IPC Protocol Extension

Add these messages to the Crayonic IPC protocol:

```
// --- DDS-specific messages (0x0060–0x007F range) ---

// CP → Auth Bridge: start DDS authentication
0x0060  DDS_START_AUTH {
    wchar_t device_urn[256];     // this device's Vouchsafe URN
    wchar_t credential_id[256];  // FIDO2 credential ID (base64url)
    wchar_t rp_id[256];          // "dds.local" (or configurable)
}

// Auth Bridge → CP: DDS auth progress
0x8060  DDS_AUTH_PROGRESS {
    uint32_t state;              // reuse IPC_AUTH_STATE enum
    wchar_t  message[512];
}

// Auth Bridge → CP: DDS auth complete
0x8061  DDS_AUTH_COMPLETE {
    bool     success;
    wchar_t  domain[256];        // Windows domain (or ".")
    wchar_t  username[256];      // Windows username
    wchar_t  password[256];      // decrypted via hmac-secret
    char     session_token[4096];// DDS session token (CBOR base64)
    wchar_t  subject_urn[256];   // authenticated Vouchsafe URN
    uint64_t expires_at;         // session expiry (Unix seconds)
}

// Auth Bridge → CP: DDS auth error
0x806F  DDS_AUTH_ERROR {
    uint32_t error_code;
    wchar_t  message[512];
}

// CP → Auth Bridge: list DDS-enrolled users for tile enumeration
0x0062  DDS_LIST_USERS {
    wchar_t device_urn[256];
}

// Auth Bridge → CP: DDS user list
0x8062  DDS_USER_LIST {
    uint32_t count;
    // followed by `count` entries:
    //   wchar_t display_name[256]
    //   wchar_t subject_urn[256]
    //   wchar_t credential_id[256]
}
```

The existing Crayonic messages (0x0001–0x0041) stay intact so the BLE
badge path continues to work alongside the DDS path.

---

## 8. New dds-node Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/v1/session/assert` | Issue session from a FIDO2 assertion proof (new) |
| `GET` | `/v1/enrolled-users?device_urn=...` | List enrolled user URNs + display names for CP tile enumeration (new) |

`/v1/session/assert` request:
```json
{
  "subject_urn": "urn:vouchsafe:passkey.xxx",
  "credential_id": "base64url...",
  "client_data_hash": "base64...",
  "authenticator_data": "base64...",
  "signature": "base64...",
  "duration_secs": 3600
}
```

dds-node looks up the credential's public key from the trust graph
(stored at enrollment in the `UserAuthAttestation` body), verifies
the assertion signature, then issues a `SessionDocument` from
`/v1/session/assert` using cryptographic proof instead of a
caller-supplied subject URN.

---

## 9. Implementation Phases

### Phase I — Fork & Strip (1 week)

1. Copy Crayonic CP repo into `platform/windows/native/`:
   ```
   platform/windows/native/
   ├── DdsCredentialProvider/   (forked from CrayonicCredentialProvider/)
   ├── DdsAuthBridge/           (forked from CrayonicBridgeService/)
   ├── DdsBridgeIPC/            (forked from CrayonicBridgeIPC/)
   ├── Helpers/                 (forked, new CLSID)
   └── Tests/                   (forked)
   ```
2. Strip BLE stack from DdsAuthBridge (keep CTAP2 engine, remove
   `ble/` directory, replace `BleGattClientWinRT` with a
   `PlatformAuthenticatorClient` that calls Windows WebAuthn API
   `webauthn.h` for platform/USB authenticators)
3. Strip PIV/CCID paths, smart card removal policy, enrollment tray app
4. Generate new COM CLSID for DDS CP
5. Update WiX manifest to register DDS CP alongside (not replacing)
   any existing credential provider
6. **Exit criterion:** builds on Windows, CP appears on logon screen
   with a static "DDS" tile, clicking it returns a failure (no auth
   backend yet)

### Phase II — Auth Bridge → dds-node (1 week)

1. Add WinHTTP client to DdsAuthBridge for calling dds-node
2. Add `DDS_START_AUTH` / `DDS_AUTH_COMPLETE` IPC messages
3. Implement the DDS auth flow in `DdsAuthBridge`:
   - Receive `DDS_START_AUTH` from CP
   - Call platform WebAuthn API for getAssertion
   - POST assertion proof to dds-node `/v1/session/assert`
   - Receive session token
   - Use hmac-secret to decrypt stored password from vault
   - Return `DDS_AUTH_COMPLETE` with password + session token
4. Wire CP's `GetSerialization()` to call `DDS_START_AUTH` instead of
   `START_AUTH_FIDO`
5. **Exit criterion:** full logon flow works: user clicks DDS tile →
   FIDO2 assertion → dds-node session → Windows logon

### Phase III — dds-node Assertion Verification (1 week)

1. Add `verify_assertion()` to `dds-domain/src/fido2.rs`:
   - P-256 signature verification (reuse existing `p256` crate)
   - Ed25519 signature verification (existing)
   - authData parsing (reuse existing `parse_auth_data`)
2. Add `POST /v1/session/assert` endpoint to `dds-node/src/http.rs`
3. Add `GET /v1/enrolled-users` endpoint
4. Add `LocalService::issue_session_from_assertion()` method
5. Tests: Rust unit tests for assertion verification; reqwest
   integration test for the new endpoint
6. **Exit criterion:** `cargo test --workspace` green; assertion-based
   session issuance works end-to-end

### Phase IV — User Enumeration & Enrollment (1 week)

1. Wire CP tile enumeration to `DDS_LIST_USERS` → Auth Bridge →
   dds-node `GET /v1/enrolled-users`
2. Implement enrollment flow:
   - Admin enrolls user via `dds-cli` (creates `UserAuthAttestation`)
   - On first Windows logon, Auth Bridge calls platform WebAuthn
     makeCredential → dds-node `/v1/enroll/user`
   - Existing-account enrollment can still capture the current Windows
     password once and store it in the local vault
   - Claim-bound accounts can now skip human password entry entirely:
     first DDS logon resolves policy via `/v1/windows/claim-account`,
     creates/resets the local account, and seeds the vault locally
   - Subsequent logons use getAssertion + hmac-secret to decrypt password
3. **Exit criterion:** new user enrollment works end-to-end on Windows VM

### Phase V — WiX Bundle & Polish (1 week)

1. Merge all components into single WiX MSI:
   - `dds-node.exe` (Rust)
   - DDS Auth Bridge (C++)
   - DDS Credential Provider DLL (C++)
   - DdsPolicyAgent (.NET)
   - Configuration files
2. Service dependencies: Auth Bridge depends on dds-node; DdsPolicyAgent
   depends on dds-node
3. Authenticode signing scaffolding
4. Uninstall: clean removal of COM registration, services, vault
5. **Exit criterion:** single MSI installs everything; clean
   install/uninstall cycle on Windows VM. Resolves B1.

### Phase VI — Tests & CI (1 week)

1. Port Crayonic test harness to DDS conventions
2. Mock dds-node HTTP responses for Auth Bridge unit tests
3. `windows-latest` GitHub Actions job:
   - Build Rust (`dds-node.exe` for `x86_64-pc-windows-msvc`)
   - Build C++ (MSBuild for Auth Bridge + CP)
   - Build .NET (DdsPolicyAgent)
   - Run unit tests for all three
4. **Exit criterion:** CI green on `windows-latest`. Resolves B2 for Windows.

---

## 10. File Mapping: Crayonic → DDS

| Crayonic Source | DDS Target | Changes |
| --- | --- | --- |
| `CrayonicCredentialProvider/CCrayonicProvider.*` | `native/DdsCredentialProvider/CDdsProvider.*` | New CLSID; enumerate from dds-node; add DDS auth path |
| `CrayonicCredentialProvider/CCrayonicCredential.*` | `native/DdsCredentialProvider/CDdsCredential.*` | `GetSerializationDds()` alongside existing `GetSerializationBridge()` |
| `CrayonicCredentialProvider/guid.h` | `native/DdsCredentialProvider/guid.h` | New CLSID `{...}` |
| `CrayonicBridgeIPC/ipc_protocol.h` | `native/DdsBridgeIPC/ipc_protocol.h` | Add 0x0060–0x006F DDS messages |
| `CrayonicBridgeIPC/ipc_messages.h` | `native/DdsBridgeIPC/ipc_messages.h` | Add DDS message structs |
| `CrayonicBridgeIPC/BridgeClient.*` | `native/DdsBridgeIPC/DdsBridgeClient.*` | Add `AuthenticateDds()` method |
| `CrayonicBridgeService/BridgeServiceMain.*` | `native/DdsAuthBridge/DdsAuthBridgeMain.*` | Add dds-node HTTP client; handle DDS_START_AUTH |
| `CrayonicBridgeService/ctap2/*` | `native/DdsAuthBridge/ctap2/*` | Keep as-is |
| `CrayonicBridgeService/ble/*` | **Skip** | BLE deferred to Phase 2+ |
| `CrayonicBridgeService/BridgeSession.*` | `native/DdsAuthBridge/AuthSession.*` | Strip BLE session; add platform authenticator path |
| `CrayonicBridgeService/CredentialVault.*` | `native/DdsAuthBridge/CredentialVault.*` | Keep for password bridge; add DDS session token caching |
| `Helpers/*` | `native/Helpers/*` | New GUIDs, update version |
| `Tests/*` | `native/Tests/*` | Adapt; add DDS-specific tests |
| `CrayonicCredentialProvider.wxs` | `installer/DdsBundle.wxs` | Merge with DdsPolicyAgent + dds-node |

---

## 11. Risks & Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Crayonic CP is C++; DDS team may be less fluent | Slower iteration | Fork minimally; keep Crayonic structure intact; change only auth backend |
| Hybrid password bridge has two onboarding modes (existing-password capture vs first-claim seeding) | UX / implementation complexity | Keep both paths explicit: existing accounts can enroll with one password capture; claim-bound accounts seed a random password on first DDS logon |
| Custom LSA AP (v2) is complex and must be signed | Multi-week effort, driver signing | Defer to v2; password bridge is adequate for pilot |
| Platform WebAuthn API (`webauthn.h`) requires Windows 10 1903+ | OS floor | Already within our Win10 1809+ floor (1903 adds webauthn.h; 1809 has basic support) |
| BLE badge support deferred | Crayonic users may expect it | Document as Phase 2+; platform authenticators cover USB keys + Windows Hello |

---

## 12. Open Decisions

1. **New CLSID or reuse Crayonic's?** Recommend: new CLSID so both
   can coexist during development. Crayonic's `{c378fb70-...}` stays
   for their standalone product.

2. **Auth Bridge as separate service or merge into DdsPolicyAgent?**
   Recommend: separate. Auth Bridge is C++ (CTAP2 engine); DdsPolicyAgent
   is .NET. Different lifecycles, different failure modes. Also, the
   CP needs the Auth Bridge at logon time (before .NET runtime is
   initialized).

3. **rpId for DDS FIDO2 credentials:** Recommend `"dds.local"` — unique,
   won't collide with web origins, clear what it's for.

4. **Platform authenticator API:** Windows `webauthn.h` (WinRT) vs.
   raw CTAP2 over USB HID. Recommend: `webauthn.h` — it handles
   authenticator selection UI, PIN prompts, and supports both platform
   (Windows Hello) and roaming (USB) authenticators.

5. **Dual-path CP:** Should the merged CP support both Crayonic BLE
   badge auth AND DDS token auth as separate tiles? Recommend: yes
   for development, but ship only the DDS tile in the DDS MSI.
