# dds-fido2-test

Interactive FIDO2 hardware tests for the DDS stack. All three binaries
require a FIDO2 USB/HID authenticator plugged in (YubiKey, SoloKey,
Crayonic KeyVault, etc.) — they drive real `makeCredential` /
`getAssertion` rounds and exercise either a single in-process node or
a full 3-node mesh end-to-end.

| Binary | Touches | What it proves |
| --- | --- | --- |
| `dds-fido2-test` | 2 | Single-node enrollment + assertion against a local `dds-node` you started yourself |
| `dds-multinode-fido2-test` | 3 | Multi-node mesh: enroll on A → assert on B → revoke during partition → sync catch-up → assert on C must fail |
| `dds-fido2-probe` | 1–2 | Cross-checks `dds_domain::fido2` against `ctap-hid-fido2` on the same bytes; used to bisect crypto bugs |

The Crayonic KeyVault occasionally returns `CTAP2_ERR_USER_ACTION_TIMEOUT`
on the first `makeCredential` even after a touch — both interactive
binaries auto-retry up to 3 times per touch step. Each prompt is
preceded by a 5 s "get ready" banner so the operator has time to react
before the device's ~30 s CTAP timer starts.

## `dds-multinode-fido2-test` — multinode HW E2E

### What it demonstrates

Spins up three in-process `DdsNode` instances on loopback in a star
mesh sharing a domain key, binds an HTTP API per node, and walks the
authenticator through the full cross-node lifecycle:

```
TOUCH 1  — makeCredential against node A → POST /v1/enroll/user
        — re-broadcast user attestation via gossip
        — wait until node B and node C see the user
        — admin (Identity-signed, no touch) issues a `dds:user` vouch
        — wait until purposes_for(user) contains "dds:user" on all 3 nodes

TOUCH 2  — getAssertion against **node B** (different node from enrollment)
        — POST /v1/session/assert on B → session issued
        — read trust graph on **node C** to confirm cross-node consistency

[ no touch ]
        — disconnect node C from A and B (libp2p disconnect_peer_id)
        — admin signs Revoke(vouch_jti) → publish via node A
        — confirm A and B see the revoke; C is partitioned and does not
        — reconnect C; the H-12 admission handshake re-fires; the
          request_response sync protocol catches C up by replaying the
          revoke from A's sync_payloads cache

TOUCH 3  — getAssertion against **node C** → POST /v1/session/assert
        — must fail with HTTP 400 invalid_input
          ("subject has no granted purposes; cannot issue session")
```

The whole run is around 90 seconds wall-clock if you touch promptly.

### How to run

```sh
# Build both binaries (release; debug builds add ~10× link time)
cargo build --release -p dds-fido2-test --bin dds-multinode-fido2-test \
  --target x86_64-pc-windows-msvc

# Plug in the FIDO2 authenticator, then:
target\x86_64-pc-windows-msvc\release\dds-multinode-fido2-test.exe
```

The binary owns the three nodes' lifecycle — temp dirs, HTTP ports, and
libp2p sockets are all cleaned up on exit. There's no external `dds-node`
to start.

Set `RUST_LOG=info,dds_node=debug` to see admission events, sync
requests, and gossip ingest decisions.

### Architecture sketch

- 3 `DdsNode` instances created via `DdsNode::init`, each pre-seeded
  with a shared admin self-attest token in its store. The orchestrator
  wires a star (A↔B, A↔C, B↔C) using the same one-sided dial pattern
  `dds-node/tests/multinode.rs` uses to dodge the libp2p-tcp
  simultaneous-dial race.
- A separate **swarm pump task** owns the three nodes after wiring.
  Commands flow in via `tokio::mpsc`:
  `PublishVouch` / `PublishRevoke` (Identity-sign + gossipsub.publish
  on a chosen node, then mirror to the local trust graph and seed the
  sync-payload cache so partitioned peers can catch up later);
  `Disconnect` / `Reconnect` (`swarm.disconnect_peer_id` /
  `add_peer_address` + `dial`); `ForceSync` (bypass the 15 s per-peer
  sync cooldown); `Snapshot` (read trust graph + admitted_peers +
  gossipsub mesh state); `Shutdown`.
- HTTP serve loops use the production `dds_node::http::serve` with
  `LocalService::new` sharing the same `Arc<RwLock<TrustGraph>>` as
  the swarm-owning node, so the FIDO2 enrollment route's local writes
  are visible to the orchestrator's snapshot queries immediately.
- The orchestrator polls `/v1/enrolled-users` and the snapshot RPC to
  observe propagation; the wait helpers print a diagnostic table every
  5 s while waiting (`connected / admitted / mesh_ops / attestations`)
  so propagation hangs are easy to root-cause.

### Bugs surfaced while bringing this up

- **`dds-cli/src/client.rs`** imported `tokio::net::UnixStream` and
  `hyper-util` symbols at module scope without `#[cfg(unix)]` →
  broke any Windows build that ran `cargo test -p dds-cli`. Fixed
  earlier (commit `36a2b81`).
- **`dds-fido2-test`'s assertion path was double-hashing the cdh.**
  `ctap-hid-fido2`'s `GetAssertionArgsBuilder::new(rp, challenge)`
  hashes its `challenge` argument internally before sending the cdh
  to the device. We were passing the already-hashed cdh, so the
  device signed over `SHA-256(cdh)` while the server verified over
  `cdh`. ctap-hid-fido2's local verifier hashes the same way so it
  agreed with itself and masked the mismatch. Fix: pass
  `clientDataJSON` bytes; the lib hashes once. (Same bug also
  fixed in the single-node `src/main.rs`.)
- **`dds_domain::fido2::verify_assertion` didn't `normalize_s()` for
  P-256 sigs.** Defensive only — the actual root cause was the
  double-hash above — but the RustCrypto p256 verifier enforces
  low-S to defend against malleability, and authenticators are not
  required to emit normalized signatures. The MAC-replay window is
  closed at the protocol layer by the single-use server challenge
  upstream.
- **`dds-node::ingest_revocation` doesn't call `cache_sync_payload`.**
  Means a node that learned a revoke via gossip cannot relay it via
  the request_response sync protocol to a future reconnecting peer
  — only the originating publisher can. Doesn't affect this
  particular test (A originates and caches), but worth fixing
  separately. **Tracked as a follow-up.**

## `dds-fido2-test` — single-node HW

```sh
# In one terminal:
cargo run -p dds-node -- run path/to/node.toml

# In another:
cargo run -p dds-fido2-test
```

The single-node tool stops at "no granted purposes" because it has
no admin vouch step — that's by design. It's useful for proving the
authenticator + HTTP API + dds_domain crypto stack works without the
overhead of the multinode harness.

## `dds-fido2-probe` — bisecting probe

```sh
target\x86_64-pc-windows-msvc\release\dds-fido2-probe.exe
```

Runs `makeCredential` then `getAssertion` against the connected
authenticator and feeds the bytes directly into both
`dds_domain::fido2::verify_*` (the server's path) and
`ctap-hid-fido2`'s `verifier::verify_*` (the library's
implementation). On disagreement, dumps the COSE pubkey, signed
blob, and DER signature so the divergence can be inspected — this is
how the cdh-double-hash bug above was found.
