# Windows E2E Smoke Tests

Validates the complete DDS Windows stack. Three scripts are provided:

| Script | When to run | Requirement |
|--------|-------------|-------------|
| `smoke_test.ps1` | Any Windows machine | `cargo build --workspace` + native build |
| `ad_joined_smoke.ps1` | AD / Hybrid-joined VM | Domain membership + builds |
| `entra_only_unsupported.ps1` | Entra-only joined VM | Entra-only machine + builds |

---

## smoke_test.ps1

Validates the complete DDS Windows stack on a single machine:

| Layer | Component | What's tested |
|-------|-----------|---------------|
| Rust  | dds-node  | HTTP API: enroll device/user, FIDO2 assertion, session, policy |
| Rust  | dds-cli   | `cp enrolled-users`, `cp session-assert` subcommands |
| C++   | DdsCredentialProvider.dll | COM exports, DLL loads |
| C++   | DdsAuthBridge.exe | Launches, HTTP client to dds-node |
| C++   | DdsBridgeIPC.lib | Named-pipe TLV protocol |
| .NET  | DdsPolicyAgent | Registry/account/password policy enforcement |

## Prerequisites

```
cargo build --workspace
msbuild platform\windows\native\DdsNative.sln /p:Configuration=Debug /p:Platform=x64
dotnet build ABCD.sln
```

## Run

```powershell
# Full smoke test
.\platform\windows\e2e\smoke_test.ps1

# Just the Rust FIDO2 E2E tests
cargo test -p dds-node --test cp_fido_e2e

# Specific test
cargo test -p dds-node --test cp_fido_e2e cp_fido2_ed25519_full_lifecycle
```

## Test matrix

| Test | Algorithm | Flow |
|------|-----------|------|
| `cp_fido2_ed25519_full_lifecycle` | Ed25519 | Full: device enroll -> user enroll (packed) -> list users -> assert -> session -> policy -> wrong-key reject -> unknown-cred reject |
| `cp_fido2_p256_assertion` | P-256 ES256 | Enroll + assert with ECDSA P-256 |
| `cp_fido2_reenrollment_invalidates_old_credential` | Ed25519 | Two enrollments, both credentials listed |

## Architecture

```
smoke_test.ps1
  |
  +-- cargo test -p dds-node --test cp_fido_e2e
  |     (spawns real dds-node process per test, synthetic FIDO2 keys)
  |
  +-- Check native C++ artifacts (DLL exports, EXE launch)
  |
  +-- Check .NET build artifacts
```

The Rust tests use the same `build_packed_self_attestation()` and
`build_assertion_auth_data()` helpers from `dds-domain::fido2` that
the unit tests use, but exercise them through the full HTTP API stack
against a real dds-node binary.

## CI

The smoke test runs automatically in the `windows-native` job of
`.github/workflows/ci.yml` on every push to `main` and every PR.
The CI job also verifies that the WiX MSI compiles successfully
with all staged binaries.

---

## ad_joined_smoke.ps1 (AD-15)

Validates DDS behaviour on an **Active Directory-joined** Windows host.
Covers §11.3 of `docs/windows-ad-coexistence-spec.md`.

### What it tests

| Step | Case |
|------|------|
| 0 | Baseline workgroup regression (binary responds) |
| 1 | Initialise test domain + verify node starts |
| 2 | Policy agent runs in Audit mode on AD-joined host |
| 3 | Stale-vault detection (`STALE_VAULT_PASSWORD` after failure) |
| 4 | Lockout prevention (≤1 DC failure per stale-vault incident) |
| 5 | Vault refresh issues `DDS_CLEAR_STALE` IPC to bridge |

### Run

```powershell
# On an AD-joined machine:
.\platform\windows\e2e\ad_joined_smoke.ps1

# Override port if 15553 is in use:
.\platform\windows\e2e\ad_joined_smoke.ps1 -Port 15560
```

The script exits **0** with a SKIP notice if the machine is not AD-joined.
It exits **1** if any assertion fails.

---

## entra_only_unsupported.ps1 (AD-16)

Validates that DDS correctly rejects authentication on an
**Entra-only joined** Windows host and emits the canonical unsupported
error codes and log strings.

### What it tests

| Step | Case |
|------|------|
| 1 | `IPC_ERROR::UNSUPPORTED_HOST = 20` in `ipc_protocol.h` |
| 2 | Auth Bridge logs Entra-only unsupported state at startup |
| 3 | Policy agent emits `unsupported_entra` reason code |
| 4 | CP binary/source contains canonical "not yet supported on Entra-joined" string |
| 5 | `AppliedReason.UnsupportedEntra = "unsupported_entra"` constant value |

### Run

```powershell
# On an Entra-only joined machine:
.\platform\windows\e2e\entra_only_unsupported.ps1
```

The script exits **0** with a SKIP notice if the machine is not Entra-only joined.
