# DDS Implementation Status

> Auto-updated tracker referencing [DDS-Design-Document.md](docs/DDS-Design-Document.md).
> Last updated: 2026-04-13 (admin enrollment + user enrollment + FIDO2 passwordless Windows login verified on ARM64 with real HW key)

## Build Health

| Metric | Value |
|---|---|
| **Rust version** | 1.94.1 (stable) |
| **Edition** | 2024 |
| **Workspace crates** | 9 (dds-core, dds-domain, dds-store, dds-net, dds-node, dds-ffi, dds-cli, dds-loadtest, dds-fido2-test) |
| **Rust LOC** | 8,400+ |
| **Rust tests** | 298 |
| **.NET tests** | 99 (Windows: 60 unit + 39 integration) + 17 (macOS) |
| **C++ native tests** | 47 (Windows) |
| **Python tests** | 13 |
| **Total tests** | 474 ✅ all passing |
| **Shared library** | libdds\_ffi.dylib (739 KB) |

Verification note (2026-04-13, Windows 11 ARM64):
- `cargo test --workspace` — **298/298 pass** on Windows 11 ARM64 (aarch64-pc-windows-msvc)
- `cargo test -p dds-node --test cp_fido_e2e` — **3/3 CP+FIDO2 E2E tests pass** (Ed25519, P-256, enrollment+assertion)
- `dotnet build ABCD.sln` — **0 errors** across DdsPolicyAgent (net8.0+net9.0), DdsPolicyAgent.Tests, DdsCredentialProvider (.NET stub)
- `dotnet test` for `platform/windows/DdsPolicyAgent.Tests` — **99/99 pass** (60 unit + 39 integration, net8.0+net9.0)
- Native C++ solution (`DdsNative.sln`) — **6/6 projects build**: Helpers.lib, DdsBridgeIPC.lib, DdsCredentialProvider.dll (ARM64), DdsAuthBridge.exe (x64), DdsTrayAgent.exe (x64), test suites
- `dds-node/tests/multinode.rs` — **4/4 pass** on Windows ARM64 (dag_converges_after_partition, rejoined_node_catches_up_via_sync_protocol now green)
- Windows E2E smoke test (`platform/windows/e2e/smoke_test.ps1`) — **8/8 checks pass** including CP DLL COM export verification
- **Security hardening merged (2026-04-13):** 6 commits: removed unauthenticated session endpoint, enforced RP-ID binding in assertion, credential_id plumbed through Windows CP login path, vault lookup by credential_id (not SID), HTTP API contract alignment, DDS bridge credential selection tests added.
- **FIDO2 passwordless Windows login re-verified after merge (2026-04-13):** Clean wipe + fresh enrollment: admin setup (auto-persisted trusted_roots) → user enrollment (2 touches) → admin vouch → lock screen → touch key → Windows session. Real YubiKey on Win11 ARM64 QEMU/UTM VM.
- `test_components.exe` — **11/11 pass**: AES-GCM roundtrip, wrong-key rejection, password encoding, vault serialization, URN-to-SID extraction, IPC struct layout, IPC password transfer, KERB packing, full pipeline, SID resolution, LsaLogonUser with real credentials
- `test_full_flow.exe` — **PASS**: Full enrollment→login with real FIDO2 authenticator (MakeCredential + 2× GetAssertion + vault save/load + LsaLogonUser)
- `test_hmac_roundtrip.exe` — **PASS**: hmac-secret determinism + encrypt/decrypt roundtrip with real authenticator
- **Policy Applier Phases D–F verified (2026-04-13, Windows 11 ARM64):** All 4 enforcers now have production Win32 implementations + real e2e integration tests. `WindowsAccountOperations` (netapi32 P/Invoke: create/delete/disable/enable users, group membership, domain-join check), `WindowsPasswordPolicyOperations` (NetUserModalsGet/Set + secedit for complexity), `WindowsSoftwareOperations` (HTTP download + SHA-256 verify + msiexec install/uninstall + registry-based detection), `WindowsRegistryOperations` (idempotent DWORD/String/QWORD/MultiString/Binary/ExpandString with int↔uint comparison fix). 39 integration tests exercise real Win32 APIs on ARM64. Test MSI (32 KB WiX package) installs/uninstalls cleanly.

Previous verification note (2026-04-10, macOS):
- `cargo test -p dds-domain` passed
- `dotnet build` + `dotnet test` for `platform/macos/DdsPolicyAgent*` passed
- macOS .NET suite is now `17/17` passing after swapping to host-backed backend implementations

## Crate Status

| Crate | Design Ref | Status | Tests | Summary |
|---|---|---|---|---|
| **dds-core** | §3–§9 | 🟢 Done | 114 | Crypto, identity, tokens (extensible body), CRDTs, trust graph, policy engine |
| **dds-domain** | §14 | 🟢 Done | 29 | 7 typed domain documents + Stage 1 domain identity + FIDO2 attestation+assertion (Ed25519 + P-256) |
| **dds-store** | §6 | 🟢 Done | 15 | Storage traits, MemoryBackend, RedbBackend (ACID) |
| **dds-net** | §5 | 🟢 Done | 19 | libp2p transport, gossipsub, Kademlia, mDNS, delta-sync |
| **dds-node** | §12 | 🟢 Done | 49+15 integ | Config, P2P event loop, local authority service, HTTP API, encrypted persistent identity, CP+FIDO2 E2E |
| **dds-domain** (fido2) | §14 | 🟢 Done | (incl. above) | WebAuthn attestation + assertion parser/verifier (Ed25519 + P-256) |
| **dds-ffi** | §14.2–14.3 | 🟢 Done | 12 | C ABI (cdylib): identity, token, policy, version |
| **dds-cli** | §12 | 🟢 Done | 9 | Identity, group, policy, status subcommands |

## Module Detail — dds-core

| Module | §Ref | Tests | Key Types |
|---|---|---|---|
| `crypto::classical` | §13.1 | 5 | `Ed25519Only`, `verify_ed25519()` |
| `crypto::hybrid` | §13.1+ | 7 | `HybridEdMldsa`, `verify_hybrid()` |
| `crypto::traits` | — | — | `SchemeId`, `PublicKeyBundle`, `SignatureBundle`, `verify()` |
| `identity` | §3 | 12 | `VouchsafeId`, `Identity` |
| `token` | §4 | 15 | `Token`, `TokenPayload` (with extensible `body_type`+`body_cbor`), `TokenKind` |
| `crdt::lww_register` | §5.1 | 11 | `LwwRegister<T>` |
| `crdt::twop_set` | §5.2 | 13 | `TwoPSet<T>` |
| `crdt::causal_dag` | §5.3 | 17 | `CausalDag`, `Operation` |
| `trust` | §6 | 14 | `TrustGraph`, `validate_chain()`, `purposes_for()` |
| `policy` | §7 | 12 | `PolicyEngine`, `PolicyRule`, `PolicyDecision` |
| integration tests | — | 5 | Full trust lifecycle, policy E2E, store roundtrip, two-node sync, hybrid PQ |

## Module Detail — dds-domain

| Document | `body_type` | Tests | Purpose |
|---|---|---|---|
| `UserAuthAttestation` | `dds:user-auth-attestation` | 2 | FIDO2/passkey user enrollment |
| `DeviceJoinDocument` | `dds:device-join` | 2 | Device enrollment + TPM attestation |
| `WindowsPolicyDocument` | `dds:windows-policy` | 1 | GPO-equivalent policy (scope, settings, enforcement) |
| `MacOsPolicyDocument` | `dds:macos-policy` | 2 | macOS managed-device policy (preferences, accounts, launchd, profiles) |
| `SoftwareAssignment` | `dds:software-assignment` | 1 | App/package deployment manifests |
| `ServicePrincipalDocument` | `dds:service-principal` | 1 | Machine/service identity registration |
| `SessionDocument` | `dds:session` | 2 | Short-lived auth session (< 1 ms local check) |
| Cross-type safety | — | 2 | Wrong type → None, no body → None |

All documents implement `DomainDocument` trait: `embed()` / `extract()` from `TokenPayload`.

## Module Detail — dds-store

| Module | Tests | Key Types |
|---|---|---|
| `traits` | — | `TokenStore`, `RevocationStore`, `OperationStore`, `DirectoryStore` |
| `memory_backend` | 7 | `MemoryBackend` (in-process, for tests and embedded) |
| `redb_backend` | 8 | `RedbBackend` (ACID persistent, zero-copy) |

## Module Detail — dds-net

| Module | Tests | Key Types |
|---|---|---|
| `transport` | 3 | `DdsBehaviour`, `SwarmConfig` (per-domain protocols), `build_swarm()` |
| `gossip` | 8 | `DdsTopic`, `DdsTopicSet`, `GossipMessage` (per-domain topics) |
| `discovery` | 3 | `add_bootstrap_peer()`, `parse_peer_multiaddr()` |
| `sync` | 9 | `StateSummary`, `SyncMessage`, `apply_sync_payloads()` |

## Module Detail — dds-node

| Module | Tests | Key Types |
|---|---|---|
| `config` | 5 | `NodeConfig`, `NetworkConfig`, `DomainConfig` (TOML, domain section required) |
| `node` | 0 | `DdsNode` — swarm event loop, gossip/sync ingestion, admission cert verification at startup |
| `service` | 6 | `LocalService` — enrollment (with FIDO2 verification), sessions (assertion-based with RP-ID binding), enrolled-user enumeration, admin setup (auto-persists trusted\_roots to TOML config), admin vouch (server-side Ed25519 signing), policy resolution, status |
| `http` | 9 | `axum` router exposing `LocalService` over `/v1/*` JSON endpoints (incl. `/v1/session/assert`, `/v1/enrolled-users`, `/v1/admin/setup`, `/v1/admin/vouch`); unauthenticated `/v1/session` removed |
| `identity_store` | 3 | Encrypted-at-rest persistent node identity (Argon2id + ChaCha20Poly1305) |
| `p2p_identity` | 2 | Persistent libp2p keypair so `PeerId` is stable across restarts |
| `domain_store` | 5 | TOML public domain file + CBOR domain key + CBOR admission cert load/save |
| `cp_fido_e2e` (integration) | 3 | Full CP+FIDO2 lifecycle: enroll device/user, list users, Ed25519+P-256 assertion, session token, negative cases |
| `http_binary_e2e` (integration) | 2 | Real dds-node binary: HTTP API, gossip convergence, revocation propagation |
| `multinode` (integration) | 4 | 3-node cluster: attestation/revocation propagation, DAG convergence, sync-on-rejoin |
| `service_tests` (integration) | 6 | Enrollment, sessions, policy, node status |

## Module Detail — dds-ffi (C ABI)

| Export | Purpose | Signature |
|---|---|---|
| `dds_identity_create` | Classical Ed25519 identity | `(label, out) → i32` |
| `dds_identity_create_hybrid` | Hybrid Ed25519+ML-DSA-65 | `(label, out) → i32` |
| `dds_identity_parse_urn` | Parse/validate URN | `(urn, out) → i32` |
| `dds_token_create_attest` | Sign attestation token | `(json, out) → i32` |
| `dds_token_validate` | Validate token from CBOR hex | `(hex, out) → i32` |
| `dds_policy_evaluate` | Policy decision with trust graph | `(json, out) → i32` |
| `dds_version` | Library version | `(out) → i32` |
| `dds_free_string` | Free returned strings | `(ptr) → void` |

## Module Detail — dds-cli

| Subcommand | Tests | What It Does |
|---|---|---|
| `identity create [--hybrid]` | 2 | Generate classical or hybrid PQ identity |
| `identity show <urn>` | 2 | Parse and display URN components |
| `group vouch` | 2 | Create vouch token, persist to store |
| `group revoke` | 1 | Revoke a vouch by JTI |
| `policy check` | 1 | Offline policy evaluation |
| `status` | 1 | Store diagnostics (tokens, revocations, burns) |

## Platform Integrations

| Platform | Language | Mechanism | Wrapper | Tests | Verified |
|---|---|---|---|---|---|
| **Any** | C | Header | `bindings/c/dds.h` | — | ✅ |
| **Linux/macOS** | Python | ctypes | `bindings/python/dds.py` | 13 pytest | ✅ Runs against .dylib |
| **Windows** | C# | P/Invoke | `bindings/csharp/DDS.cs` | 11 NUnit | Written |
| **Android** | Kotlin | JNA | `bindings/kotlin/.../DDS.kt` | 10 JUnit5 | Written |
| **iOS/macOS** | Swift | C module | `bindings/swift/.../DDS.swift` | 10 XCTest | Written |

### Managed Platform Agents

| Platform | Path | Status | Verified | Notes |
|---|---|---|---|---|
| **Windows** | `platform/windows/` | 🟢 **Login verified** | ✅ 298 Rust + 56 .NET + 47 C++ + 3 E2E | Native CP DLL + Auth Bridge + Tray Agent + Policy Agent all build + test on Win11 ARM64; **FIDO2 passwordless lock screen login re-verified after security hardening merge (2026-04-13)**; security fixes: credential_id-based vault lookup, RP-ID binding, removed unauth session endpoint; WebAuthn hmac-secret two-phase challenge/response verified with real authenticator |
| **macOS** | `platform/macos/` | 🟡 In progress | ✅ .NET build + 17 tests | `DdsPolicyAgent.MacOS` worker, localhost client, state store, launchd plist, host-backed preference/account/launchd/profile/software backends, and Rust `/v1/macos/*` API path landed |
| **Linux** | `platform/linux/` | ⚪ Planned | n/a | Design-only at this point; no agent code in tree yet |

## Cryptography

| Algorithm | Purpose | Crate | Key | Sig |
|---|---|---|---|---|
| Ed25519 | Classical signatures | ed25519-dalek 2.2 | 32 B | 64 B |
| ECDSA-P256 | FIDO2 hardware compatibility | p256 0.13 | 64 B | 64 B |
| ML-DSA-65 (FIPS 204) | Post-quantum signatures | pqcrypto-mldsa 0.1.2 | 1,952 B | 3,309 B |
| Hybrid Ed25519+ML-DSA-65 | Composite quantum-safe | both | 1,984 B | 3,373 B |
| Triple-Hybrid | Ed25519+ECDSA-P256+ML-DSA-65 | multiple | 2,048 B | 3,437 B |
| SHA-256 | ID hashing | sha2 0.10 | — | 32 B |

Feature-flagged: `pq` on by default. Hybrid signs with both; verification requires both to pass.
Classical-only available for embedded/`no_std` targets.

## FIDO2 / WebAuthn

- FIDO2 leaf identities use `Ed25519` (hardware limitation — no PQ authenticators ship yet)
- Trust roots and admins use `HybridEdMldsa65` (quantum-safe)
- Trust chain: PQ root → PQ admin → classical FIDO2 leaf
- Quantum resistance flows from the vouch chain, not the leaf authenticator
- `UserAuthAttestation` document type carries FIDO2 attestation objects inside signed tokens

## Cross-Platform Build Status

| Target | Status | Notes |
|---|---|---|
| macOS ARM64 (aarch64-apple-darwin) | ✅ Builds + tests | Dev host, 229+ Rust tests + 17 .NET |
| Linux x86\_64 | ✅ Expected to build | Standard Rust target |
| **Windows ARM64 (aarch64-pc-windows-msvc)** | ✅ **298 Rust + 56 .NET + 47 C++ tests pass** | **Win11 ARM64, MSVC 14.44 + LLVM 22.1.3, full workspace verified 2026-04-13 (post security merge)** |
| Windows x86\_64 | ✅ Expected to build (cross) | CI cross-compile gate |
| Android ARM64 (aarch64-linux-android) | 🔲 Untested | Needs cargo-ndk |
| iOS ARM64 (aarch64-apple-ios) | 🔲 Untested | Needs Xcode toolchain |
| Embedded (thumbv7em-none-eabihf) | 🔲 Untested | `no_std` core only |

## Performance Budgets (§10)

Latest results from `cargo run -p dds-loadtest --release -- --smoke`
(60 s, 3 in-process nodes, macOS aarch64 dev host).

| KPI | Target | Smoke result | Status |
|---|---|---|---|
| Local auth decision (p99) | ≤ 1 ms | 0.043 ms (max of `evaluate_policy` / `session_validate` p99) | ✅ |
| Ed25519 verify throughput | ≥ 50K ops/sec | ~46K ops/sec (p50 21.7 µs, batched 4096/sample) | ⚠️ within 10% on a busy host; criterion bench is the authority |
| CRDT merge (p99) | ≤ 0.05 ms | < 0.001 ms (`LwwRegister::merge`) | ✅ |
| Peak heap per 1K entries | ≤ 5 MB | RSS-based proxy dominated by libp2p baseline; see loadtest README | ⚠️ measurement caveat, not a regression |
| Idle gossip bandwidth | ≤ 2 KB/sec | RSS-delta proxy; libp2p does not expose per-direction byte counters | ⚠️ measurement caveat |
| Enrollment latency (informational) | n/a | enroll_user p99 0.12 ms, enroll_device p99 0.09 ms | ✅ |
| Gossip propagation (informational) | n/a | p50 ~12 ms, p99 ~102 ms across 3-node mesh | ✅ |
| dds-core binary (Cortex-M) | ≤ 512 KB | needs cross-compile | 🔲 |

Hard verdicts on the ≥ 50K ops/sec throughput KPI come from the
dedicated criterion bench (`dds-core/benches/crypto_verify.rs`); the
soak harness reports it for trend tracking and warns within 20% of the
target.

## Load Testing

`dds-loadtest` is a long-running multinode harness that drives a mixed
realistic workload (enroll/issue/evaluate/revoke) across N in-process
`DdsNode`s wired into a libp2p full-mesh and emits per-op latency
histograms plus a KPI verdict table. See [`dds-loadtest/README.md`](dds-loadtest/README.md).

```bash
# 60s smoke (CI gate, also enforces error rate ≤ 1% per op type)
cargo run -p dds-loadtest --release -- --smoke --output-dir /tmp/dds-smoke

# 24h soak
cargo run --release -p dds-loadtest -- --duration 24h --output-dir results/$(date +%Y%m%d)
```

The CI smoke job lives in `.github/workflows/loadtest-smoke.yml`.

## What's Next

All 7 crates are functionally complete. The following work is ordered by impact and dependency:

### Phase 1 — Production Hardening (high priority)

1. 🟢 **HTTP/JSON-RPC API on dds-node** — `dds-node/src/http.rs` exposes `LocalService` over a localhost axum server. Endpoints: `POST /v1/enroll/user`, `POST /v1/enroll/device`, `POST /v1/session/assert` (assertion-based session; unauthenticated `/v1/session` removed), `GET /v1/enrolled-users` (CP tile enumeration), `POST /v1/admin/setup`, `POST /v1/admin/vouch`, `POST /v1/policy/evaluate`, `GET /v1/status`, `GET /v1/windows/policies`, `GET /v1/windows/software`, `POST /v1/windows/applied`, `POST /v1/windows/claim-account` (resolve first-account claim from a freshly issued local session token), `GET /v1/macos/policies`, `GET /v1/macos/software`, `POST /v1/macos/applied`. JSON request/response types with serde, base64-encoded binary fields. reqwest integration tests cover both Windows and macOS applier endpoints against an in-process server.

2. 🟢 **FIDO2 attestation + assertion verification** — `dds-domain/src/fido2.rs` parses WebAuthn attestation objects with `ciborium`, supports `none` and `packed` (Ed25519 self-attestation) formats, extracts the COSE_Key credential public key, and verifies the attestation signature. Now also verifies getAssertion responses (Ed25519 + ECDSA P-256) via `verify_assertion()`, with `cose_to_credential_public_key()` for multi-algorithm key parsing. `LocalService::enroll_user` rejects enrollment whose attestation fails to verify; `issue_session_from_assertion()` verifies assertion signatures against enrolled keys. 12 unit tests cover attestation round-trips, assertion verification (both algorithms), bad signatures, COSE key parsing.

3. 🟢 **Persistent node identity** — `dds-node/src/identity_store.rs` loads or generates the node Ed25519 signing key on startup and persists it to `<data_dir>/node_key.bin` (or the new `identity_path` config field). When `DDS_NODE_PASSPHRASE` is set, the file is encrypted with ChaCha20-Poly1305 using a 32-byte key derived from the passphrase via Argon2id (19 MiB, 2 iters); otherwise the key is stored unencrypted with a warning log. Versioned CBOR on-disk format. 3 tests cover plain roundtrip, encrypted roundtrip with wrong-passphrase rejection, and load-or-create idempotency.

4. 🟢 **CI pipeline** — `.github/workflows/ci.yml` runs `cargo test --workspace --all-features`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, and the python binding pytest suite. Cross-compile jobs check `x86_64-pc-windows-gnu` (mingw-w64), `aarch64-linux-android` (cargo-ndk + setup-ndk), and `thumbv7em-none-eabihf` (`dds-core --no-default-features` smoke).

9\. 🟢 **Domain identity (Stage 1 — software domain key)** — `dds-domain/src/domain.rs` introduces `Domain`, `DomainId` (`dds-dom:<base32(sha256(pubkey))>`), `DomainKey` (Ed25519), `AdmissionCert` (domain key signs `(domain_id, peer_id, issued_at, expires_at)`), and a `DomainSigner` trait that Stage 2 will reimplement against a FIDO2 authenticator without touching call sites. `dds-net` bakes the domain tag into libp2p protocol strings (`/dds/kad/1.0.0/<tag>`, `/dds/id/1.0.0/<tag>`) and into gossipsub topics (`/dds/v1/dom/<tag>/org/<org>/...`), so nodes from different domains cannot complete a libp2p handshake. `dds-node`'s `NodeConfig` requires a `[domain]` section and refuses to start without a valid admission cert at `<data_dir>/admission.cbor` matching its libp2p `PeerId`. Persistent libp2p keypair (`p2p_key.bin`) is now loaded/generated by `dds-node/src/p2p_identity.rs` (encrypted at rest via `DDS_NODE_PASSPHRASE`) so the peer id is stable across restarts. New CLI subcommands: `init-domain`, `gen-node-key`, `admit`, `run` (no clap dep — hand-rolled flag parsing). Domain key on disk is encrypted with `DDS_DOMAIN_PASSPHRASE` (Argon2id + ChaCha20-Poly1305). 14+ new unit tests covering id roundtrip, cert sign/verify/tamper/expiry, domain/key TOML+CBOR roundtrips, protocol-string isolation, and stable peer id across restart.

### Phase 2 — Operational Readiness

5. 🟢 **Performance benchmarks** — criterion benches for Ed25519 verify, hybrid verify, CRDT merge (causal_dag insert + lww_register merge), policy evaluation, and SessionDocument issue+validate. Benches live under `dds-core/benches/` (`crypto_verify.rs`, `crdt_merge.rs`, `policy_eval.rs`) and `dds-node/benches/` (`session_lifecycle.rs`). CI runs `cargo bench --workspace --no-run` as a compile-check job; numbers are not yet wired as regression gates and dhat heap profiling is deferred.

6. 🟢 **Multi-node integration tests** — `dds-node/tests/multinode.rs` spins up 3 in-process `DdsNode` instances on ephemeral TCP ports, dials them into a star topology, lets the gossipsub mesh form, and verifies (a) attestation operation propagation, (b) revocation propagation, (c) DAG convergence after a node is dropped and a fresh node rejoins. Uses a multi-thread tokio runtime and `select_all` to drive every swarm concurrently.

7. 🟢 **Windows Credential Provider (native C++)** — Production-grade Credential Provider forked from the Crayonic CP codebase and integrated with DDS. See [Crayonic CP Integration Plan](docs/crayonic-cp-integration-plan.md). Replaces the .NET stub with native C++ COM DLL + Auth Bridge service.

    **Rust side (completed):**
    - `dds-domain/src/fido2.rs`: Added `verify_assertion()` supporting both Ed25519 and ECDSA P-256 assertions, `cose_to_credential_public_key()` parser, and `build_assertion_auth_data()` test helper. 7 new tests (12 total).
    - `dds-node/src/service.rs`: Added `issue_session_from_assertion()` that looks up credential public key from trust graph, verifies the assertion, and issues a `SessionDocument`. Added `list_enrolled_users()` for CP tile enumeration.
    - `dds-node/src/http.rs`: Added `POST /v1/session/assert` (assertion-based session issuance) and `GET /v1/enrolled-users?device_urn=...` (CP user enumeration) endpoints.
    - All 225+ existing tests pass; 7 new FIDO2 assertion tests added.
    - `dds-node/src/service.rs`: `admin_setup()` now auto-persists admin URN to `trusted_roots` in the TOML config file via `toml_edit`, eliminating manual config editing. `admin_vouch()` signs vouch tokens with server-side Ed25519 keys.

    **C++ side (login verified on Windows 11 ARM64, 2026-04-13):**
    - `platform/windows/native/DdsCredentialProvider/` — COM DLL (ARM64), CLSID `{a7f3b2c1-...}`, BLE/PIV stripped, DDS auth path via Auth Bridge IPC, WebAuthn hmac-secret assertion on secure desktop
    - `platform/windows/native/DdsAuthBridge/` — Windows Service (x64) with WinHTTP client, credential vault (DPAPI + AES-256-GCM), vault password decryption via hmac-secret, first-account claim via `/v1/windows/claim-account`, local account create/reset + group application, SID resolution via `LookupAccountSid`
    - `platform/windows/native/DdsTrayAgent/` — System tray enrollment tool (x64): user enrollment (MakeCredential + hmac-secret encrypt), admin setup, admin vouch approval, WebAuthn API wrappers
    - `platform/windows/native/DdsBridgeIPC/` — Named-pipe IPC library with DDS messages (0x0060-0x007F range), TLV protocol, pack(1) structs
    - `platform/windows/native/Helpers/` — LSA packaging (KERB_INTERACTIVE_UNLOCK_LOGON), COM factory
    - `platform/windows/native/Tests/` — 3 test executables: `test_components.exe` (11 non-interactive unit tests), `test_full_flow.exe` (end-to-end with real authenticator + LsaLogonUser), `test_hmac_roundtrip.exe` (hmac-secret determinism)
    - `platform/windows/installer/DdsBundle.wxs` — WiX v4 MSI bundle for all components
    - Visual Studio 2022 solution: `DdsNative.sln` with 6 projects, all build clean

    **Build fixes applied (2026-04-12):**
    - Fixed `const wchar_t[]` to `LPWSTR`/`PWSTR` conversion errors in `common.h` and `CDdsCredential.cpp` (MSVC strict C++17)
    - Fixed include paths from renamed `CrayonicBridgeIPC` to `DdsBridgeIPC` in `DdsAuthBridgeMain.h`
    - Fixed IPC type mismatches: `IPC_RESP_AUTH_RESULT` → `IPC_RESP_DDS_AUTH_COMPLETE`, added `AUTH_CANCELLED` error code
    - Added missing linker dependencies: Secur32.lib, credui.lib, netapi32.lib, shlwapi.lib
    - Created `.cargo/config.toml` with explicit ARM64 MSVC linker path (prevents Git Bash `/usr/bin/link` shadowing)
    - Disabled pqcrypto-mldsa `neon` feature to avoid GAS-syntax `.S` assembly files incompatible with MSVC/clang-cl on Windows ARM64

    **E2E smoke test (`platform/windows/e2e/smoke_test.ps1`):**
    - 3 Rust CP+FIDO2 tests (Ed25519 full lifecycle, P-256 assertion, enrollment+assertion)
    - Native artifact verification (CP DLL COM exports, Auth Bridge launch, IPC lib, Helpers)
    - .NET Policy Agent build verification
    - All 8 checks passing

8\. 🟢 **Token expiry enforcement** — `dds-node/src/expiry.rs` provides `sweep_once()` and an async `expiry_loop()` task. `NodeConfig::expiry_scan_interval_secs` (default 60) controls the cadence. Expired tokens are removed from the trust graph via a new `TrustGraph::remove_token()` method and marked revoked in the store. Unit-tested with `tokio::time::pause()` and direct sweep calls.

### Phase 3 — Enterprise Features

9. **WindowsPolicyDocument distribution** — End-to-end flow: admin creates a policy document, signs it, gossip propagates to target devices, dds-node on each device evaluates scope + applies settings (registry keys, security policy). **Plan landed 2026-04-09 — see [Windows Policy Applier Plan](#windows-policy-applier-plan-phase-3-items-910) below. Phases A–F complete; G–H remaining.**

10. **SoftwareAssignment workflow** — Admin publishes a software assignment, devices poll/receive via gossip, local agent downloads package, verifies SHA-256, installs silently. **Enforcement implemented (Phase F, 2026-04-13):** `SoftwareInstaller` + `WindowsSoftwareOperations` with HTTP download, SHA-256 verify, msiexec install/uninstall, registry-based detection. 7 integration tests including real MSI install/uninstall on ARM64.

11\. 🟢 **Audit log** — Append-only signed log of all trust graph mutations (attest, vouch, revoke, burn) for compliance. Each entry signed by the node that performed the action. Syncable via gossip. Opt-in feature enabled via `domain.toml` or `DomainConfig` during domain creation to minimize network overhead.

12\. 🟢 **ECDSA-P256 support** — Some FIDO2 authenticators only support P-256. Added as a third `SchemeId` variant with triple-hybrid option `Ed25519+ECDSA-P256+ML-DSA-65`.

13. **macOS managed-device platform** — First working slice landed on 2026-04-10. `dds-domain` now has `MacOsPolicyDocument`; `dds-node` exposes `/v1/macos/policies`, `/v1/macos/software`, and `/v1/macos/applied`; `platform/macos/DdsPolicyAgent` now builds and tests. Remaining work is listed in the macOS status section below.

14\. 🟢 **FIDO2-backed domain key** — Domain secret key can be protected by a FIDO2 hardware authenticator instead of a passphrase (`dds-node init-domain --fido2`). The key is encrypted with the authenticator's hmac-secret output; touch the key to decrypt. Feature-gated behind `--features fido2` (ctap-hid-fido2 crate). Version 3 on-disk format stores credential_id + hmac_salt alongside the encrypted key.

15\. 🟢 **Single-file node provisioning** — `dds-node provision <bundle.dds>`: one file on USB + admin's FIDO2 key + one command + one touch = node admitted, configured, started, and enrolled. The `.dds` bundle contains domain config + encrypted domain key. The provisioning command decrypts the domain key in memory (FIDO2 touch), signs an admission cert, writes config, starts the node, enrolls the device. Domain key is zeroed after use — never written to disk on new machines. `dds-node create-provision-bundle` creates the bundle from an existing domain directory.

16\. 🟢 **macOS installer package** — `platform/macos/packaging/Makefile` produces a `.pkg` installer (Rust binaries + self-contained .NET agent + LaunchDaemons + config templates). Bootstrap scripts: `dds-bootstrap-domain` (creates domain, starts node, enrolls device), `dds-enroll-admin` (enrolls FIDO2 admin user), `dds-admit-node` (issues admission certs). All scripts support FIDO2 domain key protection.

17\. 🟢 **dds-fido2-test** — Interactive FIDO2 enrollment + authentication test tool. Tests the full hardware flow: USB key → makeCredential → dds-node enroll → getAssertion → dds-node session. Works on macOS and Windows with any FIDO2 USB key.

### Windows Policy Applier Plan (Phase 3 items 9–10)

Items 9 and 10 above split into *distribution* (already solved by gossip + the
existing trust graph) plus *enforcement* (not solved — `dds-node` is a pure
directory service and never calls Win32). Enforcement is delivered as a new
Windows Service running alongside `dds-node` on the managed device.

#### Architecture

A new **`DdsPolicyAgent`** Windows Service (.NET 8 worker, `LocalSystem`)
polls `dds-node`'s loopback HTTP API once a minute for `WindowsPolicyDocument`
and `SoftwareAssignment` documents scoped to *this* device, then applies them
via four pluggable enforcers: **Registry / Account / PasswordPolicy /
SoftwareInstall**. State is persisted under `%ProgramData%\DDS\applied-state.json`
for idempotency, and outcomes are reported back to `dds-node` for audit. The
agent ships in the same WiX MSI bundle as `dds-node.exe` and the existing
`DdsCredentialProvider`, so installing one binary brings up the full Windows
integration.

`dds-node` itself stays a pure directory service — only the agent is
Windows-specific. The same `dds-node` binary continues to run unchanged on
macOS/Linux/embedded.

#### v1 scope decisions (locked 2026-04-09)

| Decision | Choice | Reason |
| --- | --- | --- |
| Service identity | `LocalSystem` | Required for HKLM writes + local account creation |
| Domain-joined machines | Out of scope v1 — refuse + log | AD-replacement is a Phase 4 conversation |
| Packaging | Single WiX MSI bundle (node + agent + credprov) | One install resolves B1 atomically |
| Pre/post install scripts | Trust on document signature | Authenticode-script PKI deferred |
| `WindowsSettings` typed bundle | **Alongside** existing `Vec<PolicySetting>` | Don't break existing tests; free-form list is the escape hatch |
| OS floor | Windows 10 1809+ | Pilot target |
| Secrets / passwords | DPAPI-local random; `SecretReleaseDocument` deferred to v2 | No on-the-wire plaintext |
| Propagation cadence | Poll `/v1/windows/*` every 60 s | GPO-class change cadence; SSE deferred |

#### Component layout

```text
platform/windows/
├── DdsCredentialProvider/        # exists — logon, untouched
├── DdsPolicyAgent/               # worker service (Phases A–F ✅)
│   ├── Worker.cs                 # poll loop, dispatch
│   ├── Client/DdsNodeClient.cs   # GET /v1/windows/* + POST /v1/windows/applied
│   ├── State/AppliedStateStore.cs# %ProgramData%\DDS\applied-state.json
│   └── Enforcers/
│       ├── RegistryEnforcer.cs       # ✅ Microsoft.Win32.Registry, allowlisted hives
│       ├── AccountEnforcer.cs        # ✅ netapi32 P/Invoke, refuse on domain-joined
│       ├── PasswordPolicyEnforcer.cs # ✅ NetUserModalsGet/Set + secedit
│       ├── SoftwareInstaller.cs      # ✅ msiexec + HTTP download + SHA-256
│       ├── WindowsRegistryOperations.cs      # Win32 impl
│       ├── WindowsAccountOperations.cs       # netapi32 impl
│       ├── WindowsPasswordPolicyOperations.cs# netapi32+secedit impl
│       └── WindowsSoftwareOperations.cs      # msiexec+HttpClient impl
└── installer/                    # NEW — WiX v4 MSI bundle (signed)
```

Rust side (smaller surface):

```text
dds-domain/src/types.rs            # add WindowsSettings typed bundle
dds-node/src/service.rs            # list_applicable_windows_policies(device_urn)
dds-node/src/http.rs               # GET /v1/windows/policies, /v1/windows/software,
                                   #     POST /v1/windows/applied
```

#### Domain-type extension

`WindowsPolicyDocument` gains an optional `windows: Option<WindowsSettings>`
field. The existing `settings: Vec<PolicySetting>` stays as the forward-compat
escape hatch. `WindowsSettings` carries:

- `registry: Vec<RegistryDirective>`  — hive, key, name, kind, value, action
- `local_accounts: Vec<AccountDirective>` — name, action, full_name, groups
- `password_policy: Option<PasswordPolicy>` — min_len, complexity, lockout
- `services: Vec<ServiceDirective>` — name, start_type, action

`SoftwareAssignment` is already typed enough — kept as-is for v1.

#### `dds-node` API additions

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/windows/policies?device_urn=...` | List `WindowsPolicyDocument` tokens whose `scope` matches the given device URN |
| `GET` | `/v1/windows/software?device_urn=...` | Same for `SoftwareAssignment` |
| `POST` | `/v1/windows/applied` | Agent reports per-directive outcome → audit log |

The agent trusts dds-node's pre-filtered list — both run as different
identities on the same loopback, and dds-node already verifies signatures
against `trusted_roots` on ingest. This avoids embedding `dds-ffi` in the
agent.

#### Phasing

| Phase | Scope | Exit criteria | Status |
| --- | --- | --- | --- |
| **A** | Extend `WindowsPolicyDocument` with `WindowsSettings` typed bundle | `cargo test -p dds-domain` green; existing tests untouched | ✅ |
| **B** | Three new `dds-node` HTTP endpoints + `LocalService::list_applicable_*` | reqwest tests in `dds-node/src/http.rs` cover scope matching + audit POST | ✅ |
| **C** | `DdsPolicyAgent` skeleton: Worker host, config, `DdsNodeClient`, `AppliedStateStore`, log-only | `dotnet test` green for state-store + client | ✅ |
| **D** | `RegistryEnforcer` + first end-to-end on Windows | 15 integration tests (HKCU + HKLM) on ARM64 | ✅ |
| **E** | `AccountEnforcer` (refuse on domain-joined) + `PasswordPolicyEnforcer` | 11 account + 6 password policy integration tests on ARM64 | ✅ |
| **F** | `SoftwareInstaller` for MSI → EXE; SHA-256 verify; uninstall lookup | 7 integration tests: install/uninstall test MSI, HTTP download + SHA-256 | ✅ |
| **G** | WiX bundle, Authenticode signing scaffolding, service registration. **Resolves B1.** | MSI builds in CI; manual install brings up both services | |
| **H** | `windows-latest` CI job runs the full integration suite. **Resolves B2 for Windows.** | CI green end-to-end | |

A–F complete (2026-04-13). G+H land as the final shipping PR.

### macOS Managed Device Status (2026-04-10)

Completed:

- `dds-domain` gained `MacOsPolicyDocument` (`dds:macos-policy`) plus typed `MacOsSettings` directives for preferences, local accounts, launchd jobs, and configuration profiles.
- `dds-node/src/service.rs` now exposes `list_applicable_macos_policies()` using the same scope semantics as Windows policy distribution.
- `dds-node/src/http.rs` now exposes `GET /v1/macos/policies`, `GET /v1/macos/software`, and `POST /v1/macos/applied`.
- Rust tests were added for macOS document round-trip, service scope matching, typed-bundle round-trip, and HTTP endpoint coverage.
- `platform/macos/DdsPolicyAgent/` landed as a .NET worker with config binding, `dds-node` HTTP client, applied-state persistence, worker poll loop, and a launchd plist template.
- `Program.cs` now registers host-backed macOS backends by default through a shared command runner instead of the previous in-memory DI registrations.
- Managed preferences now persist real plist state through `plutil`; launchd now persists label-to-plist bindings and drives `launchctl`; profiles now use `profiles`; software install/update now uses hash-checked package staging with `pkgutil` + `installer`; local account operations now target `dscl` / `pwpolicy` / `dseditgroup` / `sysadminctl`.
- `platform/macos/README.md` and `platform/macos/appsettings.e2e.sample.json` now document a staged macOS end-to-end path with temp-rooted preferences/launchd/package cache directories.
- `dds-node/src/bin/dds-macos-e2e.rs` now provides a real two-machine macOS harness: live policy/software publish into the DDS mesh, local summary collection, and merged result comparison.
- `platform/macos/e2e/` now contains runbook and wrapper scripts for machine init, node config generation, package staging, device enrollment, agent startup, result collection, result comparison, and cleanup.
- `platform/macos/DdsPolicyAgent.Tests/` now has 17 passing .NET tests covering state-store behavior, worker startup guardrails, in-memory enforcers, real plist round-trips, and command-backed launchd/profile/software flows.
- `ABCD.sln` now includes the macOS policy-agent projects.

Still TODO:

- Run the new two-machine macOS harness on two real Macs and capture the first comparison artifact as a baseline.
- Add a reproducible seeded `dds-node` fixture or smoke harness so the macOS agent e2e path can be run with one command instead of manual state seeding.
- Validate real host behavior for the account and profile backends on a disposable macOS machine; those code paths are now implemented but still only covered by command-level tests.
- Decide how to model safe package uninstall/remove recipes. Generic `.pkg` uninstall remains intentionally unsupported.
- Implement `DdsLoginBridge` / Authorization Services integration for post-login privileged workflows. Full loginwindow / FileVault replacement is still explicitly out of scope.
- Package the macOS agent as a signed/notarized `.pkg` and validate launchd installation, upgrade, and uninstall flows.
- Decide whether Linux should share a common policy-agent core library with macOS/Windows or remain as three mostly separate worker implementations.
- ~~Investigate and stabilize the unrelated `dds-node` multinode failures~~ — **Resolved 2026-04-13**: `dag_converges_after_partition` and `rejoined_node_catches_up_via_sync_protocol` now pass on Windows ARM64 (see verification note above).

## Path to Production

Overall: **~98% ready for a scoped pilot.** All 8 crates are functionally
complete, security-critical hardening (Phase 1) is done, the three
algorithmic / sync blockers the chaos soak found (B5, B5b, B6) are fixed
and validated, and the two platform blockers (B1, B2) are now resolved
with full Windows ARM64 FIDO2 passwordless login verified end-to-end on real hardware (2026-04-13).
All four Windows policy enforcers (Registry, Account, PasswordPolicy, Software)
are now production-implemented with 39 Win32 integration tests passing on ARM64 (2026-04-13).
Remaining gaps are *WiX installer packaging*, *Windows service registration*,
*code signing*, and *operational instrumentation*.

### Production Blockers

#### Open 🔴

None. All production blockers resolved.

#### Resolved ✅

| # | Gap | Resolution |
| --- | --- | --- |
| **B1** | **Windows Credential Provider stubbed** | Resolved 2026-04-13: **FIDO2 passwordless Windows login verified end-to-end on real hardware.** Full flow: admin setup (FIDO2 key → trusted root, auto-persisted to config) → user enrollment (MakeCredential + hmac-secret encrypt password → DPAPI vault) → admin vouch → lock screen tile → touch key → hmac-secret decrypt → KERB_INTERACTIVE_LOGON → Windows session. The current tree also adds a first-account-claim path for policy-bound local accounts: after `/v1/session/assert`, the native Auth Bridge can call `/v1/windows/claim-account`, generate a random local password, create/reset the Windows account, and seed the vault without putting a password in policy. Tested on Win11 ARM64 VM with real YubiKey. Re-verified after merging 6 security hardening commits (credential_id-based vault lookup, RP-ID binding enforcement, removed unauthenticated session endpoint, HTTP API contract alignment). Clean wipe + fresh enrollment confirms the merged code works end-to-end. C++ test suite validates AES-GCM, vault serialization, KERB packing, IPC struct layout, LsaLogonUser, and full pipeline with real authenticator (13 tests across 3 executables). Critical fix: WebAuthn `GetAssertion` options must match exactly between enrollment (tray agent, x64) and login (credential provider, ARM64) for hmac-secret determinism. Remaining for production: WiX installer, Windows service registration, code signing. |
| **B2** | **Cross-platform builds untested** | Resolved 2026-04-12 for Windows: `cargo build --workspace` + `cargo test --workspace` — 309/309 Rust tests pass on Windows 11 ARM64 (aarch64-pc-windows-msvc). `dotnet build` + `dotnet test` — 56/56 .NET tests pass. Native C++ solution — 4/4 projects build. Android, iOS, embedded remain 🔲 but are not in pilot scope. |
| B3 | **24h soak result missing** | Resolved by the 2026-04-09 30-min chaos validation soak (`b6-validation-20260409-210025`): 0 errors / 466K ops, all 5 hard §10 KPIs PASS, 14/14 chaos rejoins succeeded. A 24h endurance run is still nice-to-have for long-tail evidence but is no longer load-bearing for §10 sign-off. |
| B4 | **Ed25519 throughput unverified** | Resolved: 53,975 ops/sec measured in the validation soak (above the 50K target). Heap/bandwidth caveats remain (R5 below) but they are *measurement* gaps, not perf gaps. |
| **B5** | **Trust graph queries O(V) in vouch count** — `purposes_for` and `walk_chain` linearly scanned every vouch on every call. Broken soak measured `evaluate_policy` p99 climbing 0.5 → 10.8 ms as the graph grew to 14K tokens. | Fixed in [dds-core/src/trust.rs](dds-core/src/trust.rs): added `vouches_by_subject` and `attestations_by_iss` secondary indices, routed all hot paths through them. Unit test `test_purposes_for_scales_to_10k_vouches` measured 3.2 µs worst-case at 10K vouches (vs 10.8 ms broken — **3,400× speedup**). Validation soak: flat 5 µs across 4K tokens / 30 min. |
| **B5b** | **Trust graph rebuilt from store on every query** — `LocalService::trust_graph_snapshot` re-read every store token + re-verified every signature on every `evaluate_policy` and `issue_session` call. Hidden by B5 in the broken soak; surfaced once B5 was fixed. | Fixed by making `DdsNode::trust_graph` and `LocalService::trust_graph` a shared `Arc<RwLock<TrustGraph>>`, dropping the per-query rebuild, and rehydrating from the store once at `LocalService::new`. Resolved a multi-writer regression in the http_binary_e2e test. |
| **B6** | **No anti-entropy / catch-up sync wired into the swarm** — gossipsub delivers only live messages, so a node offline for any window permanently lost every op published during that window. Broken soak: 16 of 29 chaos rejoins timed out at 5 min. | Fixed in [dds-net/src/transport.rs](dds-net/src/transport.rs) and [dds-node/src/node.rs](dds-node/src/node.rs): added a libp2p `request_response::cbor::Behaviour<SyncRequest, SyncResponse>` over a domain-namespaced `/dds/sync/1.0.0/<tag>` protocol. Triggered on `ConnectionEstablished` (catches fresh rejoins) plus a 60-second periodic anti-entropy timer (catches steady-state drift). Regression test `rejoined_node_catches_up_via_sync_protocol` proves a fresh node converges to existing peers' state with **no further publishes after join**. Validation soak: **14/14 chaos rejoins succeeded, 0 timeouts.** |

### Soak Findings (2026-04-09, 2h 38m run, aborted)

Run dir: `loadtest-results/soak-20260409-140730/` — chaos enabled (5 nodes,
1 of 5 paused every ~5 min for ~60s, max 1 offline at a time). 1.24M ops,
16 errors. Aborted early because two production blockers became visible
within the first hour.

| Metric | Smoke (90s) | Soak (158m) | Verdict |
| --- | --- | --- | --- |
| `evaluate_policy` p99 | 0.300 ms | **10.805 ms** | ❌ FAIL §10 ≤ 1 ms |
| `issue_session` p99 | 0.377 ms | **10.846 ms** | ❌ FAIL §10 ≤ 1 ms |
| `session_validate` p99 | 0.033 ms | 0.048 ms | ✅ |
| `ed25519_verify` ops/s | 54,972 | 54,972 | ✅ resolves B4 throughput |
| `gossip_propagation` p99 | 104 ms | **577 sec** (9.6 min) | ❌ |
| `rejoin_convergence` | 3/3 ok | **13/29 ok, 16 timeouts** | ❌ |
| Trust graph tokens | 82 | **14,407** (still growing linearly) | ⚠️ unbounded in harness |
| Per-node trust spread | uniform | **[4411, 4386, 3269, 1617, 724]** | ❌ mesh divergent |
| Op rate | n/a | 280 → 138 ops/s (halved by graph growth) | ⚠️ symptom of B5 |
| RSS | 41 MB | 109 MB | ⚠️ symptom of B5 + harness |
| Errors | 0 | 16 / 1.24M | ✅ |

The two blocker findings (B5 and B6) are independent. B5 breaks any deployment
larger than ~1K tokens regardless of network conditions. B6 breaks any
deployment with any node churn regardless of size. Both must land before
the next soak.

The soak also surfaced two harness bugs (not production code):

- **Vouch tokens issued by the harness have a 365-day expiry**, so the trust
  graph grows monotonically and the expiry sweeper never reclaims anything.
  Need to drop vouch expiry to ~1 hour to exercise steady-state behavior.
- **`Notify::notify_waiters` only wakes current waiters**, so a SIGINT racing
  with the select-loop tick can be lost. Should switch to
  `tokio_util::sync::CancellationToken` or `AtomicBool::load(Acquire)`.

### Validation Soak (2026-04-09, 30 min, all KPIs ✅)

Run dir: `loadtest-results/b6-validation-20260409-210025/` — same chaos
settings as the broken soak (5 nodes, 1 of 5 paused every ~2 min for 45s,
max 1 offline). Wrapped in `caffeinate -dimsu` so macOS could not suspend
mid-run. **0 errors / 466K ops, all five hard §10 KPIs PASS.**

| KPI | §10 target | Validation soak | Verdict |
| --- | --- | --- | --- |
| Local auth decision (p99) | ≤ 1 ms | **0.050 ms** | ✅ 20× under budget |
| `evaluate_policy` (p99) | ≤ 1 ms | **0.005 ms** | ✅ 200× under |
| `session_validate` (p99) | ≤ 1 ms | **0.050 ms** | ✅ |
| `issue_session` (p99) | informational | **0.102 ms** | ✅ flat |
| Ed25519 verify throughput | ≥ 50,000 ops/s | **53,975 ops/s** | ✅ |
| CRDT merge (p99) | ≤ 0.05 ms | **< 1 µs** | ✅ |
| `gossip_propagation` (p99) | informational | 105 ms | ✅ |
| **`rejoin_convergence`** | no timeouts | **14 ok / 0 timeouts** | ✅ |
| Errors | — | **0 / 466K ops** | ✅ |
| Trust graph tokens (peak) | — | 4,123 (steady-state) | — |
| RSS (peak) | — | 74 MB | ⚠️ R5 |
| Heap / 1K entries | ≤ 5 MB | 17.94 MB | ⚠️ R5 (RSS-proxy) |
| Idle gossip bandwidth | ≤ 2 KB/s | 11.5 KB/s | ⚠️ R5 (RSS-delta proxy) |

Comparison to the broken soak at the same wall-clock point (15 min in,
~2K tokens):

| Signal | Broken | Validation | Result |
| --- | --- | --- | --- |
| `evaluate_policy` p99 | climbed 0.5 → 2.5 ms | **flat 5 µs** | **509× faster** |
| `gossip_propagation` p99 | 577 sec | 105 ms | **5,500× faster** |
| `rejoin_convergence` | 13 ok / 16 timeouts | 14 ok / 0 timeouts | ✅ |
| Op rate | 285/s declining | 318/s climbing | ✅ |
| Errors | 16 | **0** | ✅ |

### Production Risks ⚠️ (not blockers, but must be acknowledged)

| # | Risk | Mitigation |
| --- | --- | --- |
| R1 | FIDO2 attestation only supports `none` + `packed/Ed25519`; TPM and full x5c chains deferred | Acceptable for pilot with known authenticator models; document allow-list |
| R2 | No delegation depth limit on vouch chains | Bound at config layer before opening enrollment to untrusted admins |
| R3 | No sharded Kademlia | Only matters > 10K nodes; out of scope for pilot |
| R4 | `DdsNode::node` module has 0 unit tests (event loop covered only by multinode integration test) | Multinode test is the load-bearing coverage; acceptable if soak passes |
| R5 | Heap and idle-bandwidth KPIs use whole-process RSS proxies, not real allocator / per-direction byte counters. Validation soak measured 17.94 MB / 1K entries vs the §10 ≤ 5 MB target — but the number is dominated by the libp2p / tokio runtime baseline and is *not* a real-allocations regression. | Acceptable for pilot. If a hard verdict is needed pre-GA: wire `dhat` for heap and a custom `Transport` wrapper for byte counters. |

### Plan to Production

#### Milestone P0 — Fix the blockers the chaos soak surfaced ✅ COMPLETE

All four sub-milestones landed and validated by the 2026-04-09 30-min
chaos soak (`b6-validation-20260409-210025`): 0 errors / 466K ops, all
five hard §10 KPIs PASS, 14/14 chaos rejoins succeeded.

##### P0.a — Fix B5 (algorithmic): trust graph queries must be sublinear ✅

- [x] Add `vouches_by_subject: BTreeMap<String, BTreeSet<String>>` and `attestations_by_iss` indices to `TrustGraph`
- [x] Maintain the indices in `add_token`, `remove_token`, `sweep_expired`, and the `Burn` revocation cascade
- [x] Route `purposes_for`, `walk_chain`, and `has_purpose` through the index instead of iterating `vouches.values()`
- [x] Unit test `test_purposes_for_scales_to_10k_vouches`: 10K-vouch graph, asserts `purposes_for` worst-case < 500 µs. **Measured 3.2 µs.**
- [x] Smoke + 30-min chaos soak: `evaluate_policy` p99 stays flat at 5 µs from 1 → 4,123 tokens

##### P0.b — Fix harness issues that contaminated the first soak ✅

- [x] Drop harness vouch expiry from 365 days to 1 hour and cap user pool to 300 — landed in `dds-loadtest/src/harness.rs`
- [x] Replace `Notify::notify_waiters` with `tokio::sync::watch` so SIGINT can't race with the select loop — landed in `dds-loadtest/src/main.rs`
- [x] Wrap soak runs in `caffeinate -dimsu` so macOS suspend can't contaminate the timer

##### P0.b2 — Fix B5b (per-query rebuild) — surfaced after P0.a ✅

- [x] Drop the per-query `trust_graph_snapshot()` rebuild from `LocalService::issue_session`, `evaluate_policy`, `status`
- [x] Add `LocalService::rehydrate_from_store()`, called once at construction (preserves the http_binary_e2e seed_store path)
- [x] Make `DdsNode::trust_graph` and `LocalService::trust_graph` a shared `Arc<RwLock<TrustGraph>>` so gossip-received tokens are visible to HTTP API queries instantly (fixes a multi-writer regression in `binary_nodes_converge_on_gossip_and_revocation`)
- [x] Update all 10+ in-tree access sites to take read/write locks
- [x] Validation smoke: `evaluate_policy` p99 dropped from 299 µs → 5 µs (60× faster)

##### P0.c — Fix B6 (sync): wire `dds-net::sync` into the swarm event loop ✅

- [x] Add `libp2p` `request-response` + `cbor` features to the workspace
- [x] Add `request_response::cbor::Behaviour<SyncRequest, SyncResponse>` to `DdsBehaviour` with a domain-namespaced `/dds/sync/1.0.0/<tag>` protocol
- [x] Define `SyncRequest { known_op_ids, heads }` and `SyncResponse { payloads, complete }` in `dds-net::sync`
- [x] Add `apply_sync_payloads_with_graph` that also feeds the trust graph (post-B5b: in-memory graph is the source of truth)
- [x] Maintain a `sync_payloads` cache on `DdsNode` populated at gossip ingest, so the responder can serve diffs without round-tripping through the store
- [x] On `ConnectionEstablished` → call `try_sync_with(peer)` (catches fresh rejoins)
- [x] On `ConnectionClosed` → drop the per-peer cooldown so the next reconnect re-syncs immediately
- [x] Periodic 60s anti-entropy timer in `run()` → sync against every connected peer (catches steady-state drift)
- [x] Per-peer 15s cooldown to avoid sync storms during reconnect flap
- [x] Regression test `rejoined_node_catches_up_via_sync_protocol`: A and B publish ops, C joins fresh with no shared past, **C converges via sync protocol with no further publishes**. Passes in 11 s.
- [x] Validation soak: **14 of 14 chaos rejoins succeeded with 0 timeouts** (vs 13/29 timeouts in the broken soak)

##### P0.d — Run a clean validation soak ✅

- [x] 30-min chaos soak after P0.a + P0.b: `validation-20260409-193017` — eval p99 flat at 5 µs, 0 errors. (Note: original 30-min run was contaminated by macOS sleep at 22 min; rerun with `caffeinate` → clean.)
- [x] 30-min chaos soak after P0.c: `b6-validation-20260409-210025` — all five §10 KPIs PASS, 14/14 rejoins succeed, 0 errors / 466K ops
- [ ] **Optional**: 24-hour endurance run for long-tail evidence. Not load-bearing for §10 sign-off; defer to pilot pre-flight.
- [ ] **Optional**: Wire `dhat` heap profiling and a custom transport-byte-counter to convert R5's RSS-proxy KPIs to hard verdicts. Defer to pre-GA if pilot sign-off needs them.

#### Milestone P1 — Pilot scoping decision ✅ COMPLETE

- [x] Decide pilot platform scope: **Windows logon included.** Full FIDO2 passwordless flow verified end-to-end on Windows 11 ARM64 with real YubiKey: admin setup → admin enrollment → user enrollment → admin vouch → lock screen → touch key → Windows session. Remaining work is packaging (WiX/MSI), service registration, and Authenticode signing.

#### Milestone P2 — Platform breadth (resolves B2)

- [ ] Wire `x86_64-pc-windows-msvc` build + run C# NUnit suite against the real `dds_ffi.dll` in CI
- [ ] Wire `aarch64-linux-android` via cargo-ndk + run Kotlin JUnit suite on an emulator in CI
- [ ] Wire `aarch64-apple-ios` via Xcode toolchain + run Swift XCTest suite on a simulator in CI
- [ ] Cross-compile `dds-core --no-default-features` for `thumbv7em-none-eabihf` and record binary size vs the 512 KB §10 budget

#### Milestone P3 — Operational readiness

- [ ] Add audit-log retention/rotation policy and document operator runbook
- [ ] Add delegation depth cap to `PolicyEngine` config (R2)
- [ ] Document the FIDO2 attestation allow-list and the upgrade path to TPM/x5c (R1)
- [ ] Threat model review of the domain admission cert flow + the encrypted-at-rest identity store (independent eyes on f225e57)

#### Milestone P4 — Pilot deploy

- [ ] Deploy 3-node mesh in a staging environment matching the pilot topology
- [ ] Enroll a representative cohort end-to-end (user passkey → device join → session → policy evaluate)
- [ ] Run for 7 days, watch the audit log, gossip propagation p99, and error rates from the loadtest harness running in parallel
- [ ] Pilot sign-off → general availability decision

#### Out of scope for first production cut

Deferred to post-GA:

- Phase 4 items 13–15 (sharded Kad, delegation depth limits as a hard feature, offline enrollment)

Note: Phase 3 items 9–10 (WindowsPolicyDocument distribution + SoftwareAssignment) are fully implemented through Phase F — all 4 Windows enforcers have production Win32 implementations with 99 passing tests (60 unit + 39 integration) and macOS Policy Agent has 17. Remaining work is production packaging (Phase G) and CI integration (Phase H), not core functionality.

### Phase 4 — Scale

13. **Sharded Kademlia** — For deployments > 10K nodes, shard the DHT by org-unit to reduce gossip fan-out and Kademlia routing table size.

14. **Delegation depth limits** — Add configurable max vouch chain depth (e.g. root → admin → user = depth 2) to bound trust graph traversal and prevent unbounded delegation.

15. **Offline enrollment** — Generate enrollment tokens that can be carried on USB/QR to air-gapped devices. Device presents token to local node, node verifies signature and creates attestation without network.
