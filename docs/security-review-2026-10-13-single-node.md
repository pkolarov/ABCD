# Single-node compromise review — what one hostile admitted node can do to the mesh (2026-10-13)

Source review of `main` at `2da26c9` (the 2026-09-08 follow-up record), focused on one
question: **an adversary fully controls one admitted node — its libp2p key, admission
cert, node identity and disk — what can it do to every other node?** Each finding below
was traced from a network entry point (`DdsNode::ingest_operation`,
`apply_decrypted_sync_response`, `verify_peer_admission`, the sync cache, the trust
graph) to its effect on the rest of the domain, then fixed in this branch with a
regression test. These are source findings, not demonstrations against a running mesh.

## What an admitted node can and cannot do

Can:

- Sign anything with its own node key and with any number of fresh identities it
  generates. Tokens enter every node's trust graph on signature + shape alone; no chain
  to a root is required at ingest (only policy / software / self-update bodies are
  capability-gated).
- Choose every byte of the `Operation` it pairs with a token on gossip and sync.
- Answer any peer's anti-entropy `SyncRequest` with whatever payloads it likes.
- Burn or revoke its own tokens; publish policy only if it already holds the capability.

Cannot:

- Forge a domain-key signature (admission certs, revocations), a trusted root's
  signature, or another publisher's epoch-key release (Ed25519 over the publisher's
  libp2p key, verified since AUDIT-2026-06-11 C2).
- Overwrite an existing JTI (H-4 / B-1), revoke a token it did not issue (H-1), or seed
  an op for a token the graph rejected (AUDIT-2026-06-11 #4).

The previous reviews closed the direct privilege paths. What remained were ways to turn
the *replication machinery itself* against the domain: state that every node accepts,
persists and keeps acting on after the hostile node is revoked.

## Findings

| ID | Severity | Finding | Fix |
|---|---|---|---|
| N1 | **Critical** | A `dds:admin` vouch signed by any identity — one the attacker just generated — against a config-anchored trusted root made every node treat that root as "promoted through the graph", find no live vouch from a current root, **demote it, and persist the demotion to node.toml**. On member nodes the founding admin is exactly such a root (the provisioning bundle seeds `trusted_roots`; `bootstrap_admin_urn` is only exempt where set). Result: every grant chaining through that root stops working domain-wide, across restarts, from one node. | `reconcile_roots_against_graph` now counts a root as promoted only when a `dds:admin` vouch for it was issued by a current root, a root at the start of the pass, or the bootstrap admin; `reconcile_roots_after_token` applies the same rule. Tests: `forged_admin_vouch_from_non_root_cannot_demote_config_anchored_root`, `demotion_cascades_through_sub_admins_in_one_pass`. |
| N2 | High | The op paired with a token was attacker-chosen (`id`, `author`, `deps`, `data`). Delivering one valid token under two op ids to two peers left them permanently divergent: each re-requested the other's id every anti-entropy round, the redelivery was refused as a duplicate JTI, the op never merged, so it was re-requested forever. Ten thousand such pairs filled every response's 1000 slots with perpetually-rejected entries and starved genuine catch-up — and the state outlived the attacker's revocation. `data` also carried up to the gossipsub frame size (~64 KiB) of opaque bytes per op into every store. | `dds_net::sync::validate_op_binding` (id must be `op-<jti>`, author must be the token issuer, no dependency edges, `data` ≤ 64 bytes) is enforced on gossip ingest and on the sync pre-filter before the trust graph. Tests: `op_binding_*` in dds-net, `aliased_op_ids_are_rejected_on_both_replication_paths_and_not_relayed` in dds-node. |
| N3 | High | The sync payload cache evicted with `BTreeMap::pop_first` (lexicographically smallest id, not the oldest) and served in key order. Ten thousand self-signed tokens whose JTIs sort last evicted every genuine entry and then kept the cache 100 % attacker-owned (each new genuine op evicted the previous one), so the node could never again serve catch-up — rebuilt the same way from the store on restart. Ids sorting first instead took every response slot ahead of genuine ops. | `SyncPayloadCache`: insertion-sequenced, evicts the oldest, serves oldest-first. Tests: `sync_payload_cache_tests`. |
| N4 | High | `TrustGraph::walk_chain` (DFS) returned `ChainTooDeep` for the *whole* query as soon as one branch exceeded `max_chain_depth`, and marked a URN visited at whatever depth it was first reached. Six throw-away identities chained behind a vouch whose JTI sorts first vetoed a genuine one-hop chain for that subject, or for any non-root voucher — every grant through that voucher failed on every node. | `validate_chain` is now a breadth-first search: shortest chain wins, first visit is at minimal depth, `ChainTooDeep` is reported only when no chain exists within the cap. Tests: `deep_decoy_chain_cannot_veto_direct_root_vouch`, `intermediate_reached_via_decoy_is_still_found_at_its_real_depth`. |
| N5 | Medium | After applying a sync response the node cached **every** payload in the batch for onward serving, including ones the graph rejected (bad signature, duplicate JTI, unauthorized revoke). A hostile responder's junk was relayed to every peer that synced with the victim and evicted genuine entries under the cache cap. | Only payloads whose op newly merged are cached (`merged_op_ids`). Covered by the N2 node test. |
| N6 | Medium | The sync path applied the 7-day M-9 replay window to revoke/burn tokens, so a node offline for more than a week **never learned the revocations issued during the outage** and re-requested them every round. A genuine old revocation can only add a revocation the node should hold (duplicates: H-4, unknown targets: H-1, forgeries: signature), so the window bought nothing on this path. | Sync keeps only the forward clock-skew half of M-9 (`revocation_iat_not_from_future`); the gossip path is unchanged. Test: `sync_applies_old_genuine_revocation_but_refuses_future_stamped_one`. |
| N7 | Medium | A single sync payload was bounded only by the 5 MiB whole-response budget, so one token of 5 MiB was storable and re-servable; gossip caps a token at 64 KiB. | Per-entry bounds on sync: token ≤ 64 KiB, op ≤ 4 KiB (`oversized` reject reason). |
| N8 | Medium | `TrustGraph::add_token(Burn)` scanned every vouch in the graph to revoke the burned issuer's own; burns of fresh identities are unlimited and self-signed, so the cost of each grew with the whole domain. | `vouches_by_issuer` index; burn is O(k) in the burned identity's vouches. Test: `burn_revokes_only_the_burned_issuers_vouches`. |
| N9 | Medium | `SyncRequest` carries the requester's complete op-id set and libp2p's stock CBOR codec caps requests at 1 MiB: past roughly 15 000–20 000 ops every sync request in the domain is refused by the responder's codec and anti-entropy silently stops for everyone. A hostile node reaches that count with self-signed tokens. | `BoundedCborCodec` (byte-compatible with the stock codec) raises the request cap to 8 MiB (~150 000 ops). The structural fix is a digest/range-based request — see R2. Test: `bounded_cbor_codec_roundtrips_and_caps`. |
| N10 | Low | Two decodes of peer-controlled bytes used ciborium's default 256-level recursion instead of the project's `cbor_bounded` (depth 16): the decrypted `SyncPayload` in `decrypt_sync_payloads` and `EpochKeyRelease::from_cbor`. Not a panic path (ciborium errors out), but outside the I-6 invariant. | Both routed through `dds_core::cbor_bounded`. |

A targeted scan of every network-facing parser (FIDO2 attestation/assertion, admission
cert and revocation, epoch-key release, hybrid/KEM crypto, audit entries, the admission
and sync handlers) found no slice index, `unwrap`, length subtraction or `try_into` on
peer bytes without a preceding length check. No process-crash vector from an admitted
peer was found.

## Residual risks (design-level, not fixed here)

- **R1 — Unbounded self-signed token volume.** An admitted node can publish an unlimited
  number of attestations, vouches and burns from unlimited fresh identities; every node
  verifies, stores (redb) and holds them in RAM (trust graph), forever (no `exp` is
  required). With Ed25519 keys a token is ~0.5 KiB, with hybrid keys ~3.5 KiB; the
  per-peer gossip budget (1200 messages per 60 s by default) bounds the *rate* at roughly
  1.7 million tokens per day per hostile node, not the total. This survives revocation. Options,
  in increasing order of invasiveness: (a) a sweep that drops unanchored self-attestations
  (no vouch from a chain-connected voucher) after a grace period, which also bounds the
  F1/S3 credential-shadow surface; (b) a per-origin quota on unanchored tokens keyed by
  the gossipsub `source` / sync responder; (c) requiring a publisher capability for *all*
  attestation body types, with enrollment going through the local node's API only.
  (a) is the recommended first step.
- **R2 — Sync request size scales with the directory.** Even at 8 MiB the request is sent
  to every connected peer every 60 s. A range- or digest-based `SyncRequest` (requester
  names an id prefix range and sends only its ids in that range; responder answers for
  that range) keeps both message sizes bounded and is wire-compatible via
  `#[serde(default)]`.
- **R3 — Trusted roots are still a per-node view (I-11).** N1 removes the forged-vouch
  demotion, but two nodes can still disagree on the root set through config edits.
- **R4 — Perpetually-rejected sync entries from honest config divergence** (a peer that
  refuses legacy v1 tokens, or whose root set lacks a publisher's capability) still occupy
  response slots until they age out of the responder's cache. A small negative cache of
  terminally-rejected op ids folded into `known_op_ids` would close this.
- **R5 — The node's own authority is intact until revoked.** A compromised node that holds
  a publisher capability can publish policy; one that is a user's enrollment node can
  issue sessions for locally-held credentials. Revoking its admission (and the identities
  it held) is the response; after N1–N5 that revocation leaves no persistent damage other
  than the token volume in R1.

## Operational note

If a node is suspected compromised: `dds-node revoke-admission` for its PeerId (the
revocation propagates on every H-12 handshake), revoke or burn the identities it held,
and rotate the epoch key (`POST /v1/pq/rotate`, also triggered automatically by the
revocation). With this branch, nothing it injected keeps the mesh from converging
afterwards; the tokens it published remain in every store until R1 is addressed.

## Verification

- `cargo test -p dds-core -p dds-net -p dds-node` on the branch; `cargo fmt`,
  `cargo check --all-targets` and `cargo clippy` clean for the three crates. Counts are
  in the commit message. One pre-existing test,
  `http::tests::uds_listener::admin_endpoint_rejects_unknown_uid_caller`, fails when the
  suite runs as root because the UDS admin gate admits uid 0 unconditionally
  (`http.rs`, `*uid == 0 ||`); it passes as an unprivileged user and is unrelated to
  this change.
- The FIDO2 / HID crates (`dds-fido2-test`, `dds-fido2-cli`) were not built in the review
  container (no `libudev`); they are untouched by this change.
