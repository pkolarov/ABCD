# Windows E2E Smoke Test

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
