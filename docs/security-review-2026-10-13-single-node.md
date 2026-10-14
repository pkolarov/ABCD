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

## Follow-up (same day): R1 mitigations landed

R1 is now bounded by two mechanisms, both configurable (see the Admin Guide config
reference):

- **Fresh-identity budget per source** (`[network] fresh_identity_budget_per_day`,
  `fresh_identity_grace_secs`, `fresh_identity_hard_cap_per_day`;
  `dds-node/src/identity_flood.rs`). Every node charges the signed gossip publisher,
  or the sync responder, for each identity it introduces that nobody has vouched. An
  identity stops counting the moment someone with a chain to a trusted root signs for
  it, so a bulk onboarding never trips the budget. A publisher whose identities stay
  unanchored past the grace period in numbers beyond the budget is quarantined for the
  rest of the day by every node that saw the flood (disconnected, refused admission,
  messages dropped and not relayed), with an audit entry and a log line naming the
  `revoke-admission` command. A sync responder over budget is only throttled, since an
  honest node may be relaying a flood it accepted before the publisher was caught. The
  storage impact of a flood is therefore bounded to roughly the budget per hostile
  node per day, instead of the gossip rate.
- **Unanchored-identity pruning** (`unanchored_identity_ttl_days`, default 30;
  `dds-node/src/expiry.rs::prune_unanchored_once`). Hourly, each node removes the
  tokens of identities that have had no effective vouch for longer than the TTL —
  measured from the identity's first token or from the revocation / expiry of its
  last vouch, whichever is later, so offboarded users keep their record for the full
  period after offboarding and a never-vouched identity cannot postpone its pruning by
  issuing more tokens (follow-up finding 3 below). Revocation records of pruned tokens
  are kept (follow-up finding 1 below). Trusted roots, the bootstrap admin, the node's own identity,
  device-join identities and identities carrying any document type other than a plain
  or user-auth attestation are never pruned. The matching ingest rule refuses tokens
  older than the TTL from an issuer no vouch claims (a vouch in the same sync batch
  counts), so pruned material does not come back through anti-entropy from a lagging
  peer.

Remaining in R1: identities carrying a device-join document are exempt from pruning
(devices are legitimately unvouched unless `enforce_device_scope_vouch` is on), so a
flood of device-join attestations is bounded only by the budget, not reclaimed.

## Follow-up review of v1.8.0 (2026-10-13): four findings

A second review of the five commits through `b66e077` (v1.8.0) reproduced four issues
with local Rust tests against the ingestion and pruning code. All four were confirmed
against the source and fixed in the next release; each fix carries a regression test
that fails on v1.8.0.

| # | Severity | Finding (as reported) | Verdict and fix |
|---|---|---|---|
| F1 | High | **Pruning can undo revocation.** Removing an old attestation also cleared its revocation from the trust graph (`remove_token` drops the `revocations` / `revoked_at` entries). Replaying the token afterwards restored it live, even though the store still marked it revoked. | Confirmed. The pruner now removes tokens with `TrustGraph::remove_token_keep_revocation`, which leaves the revocation record in place (the record without its target reads as a pending revocation, and a re-added target is immediately revoked). Both ingest paths additionally refuse any token whose JTI has a revocation record in the graph or a revoked mark in the store (`DdsNode::jti_revoked`), so a replayed copy never re-enters the store or the DAG. `remove_token` keeps its old semantics for the expiry sweeper, where an expired token cannot be replayed anyway. Tests: `unanchored_clock_uses_first_own_token_and_prune_keeps_revocations` (dds-core), `prune_keeps_revocation_records_so_a_replayed_token_stays_revoked` (expiry), `revoked_then_pruned_token_is_refused_on_replay` (node). |
| F2 | High | **Root-demotion fix incomplete.** An untrusted identity could issue a `dds:admin` vouch targeting a configured root, then revoke it; `reconcile_roots_after_token` demoted the root from the swarm's in-memory set, and the periodic reconcile never restored it. | Confirmed. N1 fixed the periodic pass but not the token-driven path. The Revoke branch now applies the same gate as `reconcile_roots_against_graph`: a root is demotable only if the graph shows it was promoted — it holds a `dds:admin` vouch (live or not) signed by a current root or the bootstrap admin. A config-anchored root nobody authorised ever vouched is left alone; a genuine promotion is still undone when its promoter revokes it. Test: `throwaway_admin_vouch_then_revoke_does_not_demote_a_config_root`. |
| F3 | High | **Flood protection does not bound token volume.** A known identity bypassed further accounting: 32 distinct tokens were accepted with an identity hard cap of 1 and no quarantine. Continued issuance also moved `unanchored_since` forward, delaying pruning indefinitely. | Confirmed. The ledger now also charges each source for every token from an *unanchored* issuer — a per-window token count (`[network] unanchored_token_budget_per_day`, default 5000) and byte total (`unanchored_token_bytes_per_day`, default 16 MiB) — with the same outcomes as the identity budget (publisher quarantined, responder throttled). Anchored issuers are not charged: someone with a chain to a root signs for them and a catch-up batch is almost entirely anchored material. `unanchored_since` now starts at the identity's *first* own token (or the later loss of its last vouch), so issuing more tokens cannot postpone pruning. Tests: `token_and_byte_quotas_bound_volume_per_source_and_window`, `known_unanchored_identity_cannot_flood_tokens`, `continuous_issuance_does_not_postpone_pruning`. |
| F4 | Medium | **Rejected duplicates can poison onward sync.** Two tokens sharing one op id (same JTI, different bytes): the accepted one entered the store, but the sync-cache repopulation matched `merged_op_ids` back against the whole batch, so the rejected twin overwrote the accepted entry and was served onward. | Confirmed. `SyncResult` now reports `merged_payloads`, the batch indexes of exactly the payloads whose op newly merged, and the node caches only those bytes. Tests: `merged_payloads_names_the_accepted_payload_not_its_duplicate_jti_twin` (dds-net), `sync_cache_serves_the_accepted_payload_not_its_duplicate_jti_twin` (node). |

What stays as designed: anchored identities are not subject to the token quota (their
volume is bounded by the per-peer gossip rate limit and accountable through revocation
of their vouch), and a sync responder over any budget is throttled rather than
disconnected.

### Second round (2026-10-14): two further findings

A re-review of v1.8.1 (`bcdddc4`) confirmed the four fixes above with independent
regressions and reproduced two remaining issues. Both were confirmed against the
source and fixed in v1.8.2.

| # | Severity | Finding (as reported) | Verdict and fix |
|---|---|---|---|
| G1 | High | **Revocation gossip bypasses the quotas.** After a publisher's one-token quota was spent, 16 further encrypted revocation messages were delivered and stored without quarantine; `ingest_revocation` skipped the new accounting. | Confirmed. The revocations topic (plaintext and enc-v3 alike, both dispatch to `ingest_revocation`) now runs the same per-publisher charge as the ops and burns topics before anything is persisted, quarantines the publisher on refusal, and returns an `IngestOutcome` so a refused revocation is not relayed. Revocations from trusted roots and anchored issuers stay free, so offboarding is never throttled. The anti-entropy path already charged revocations. Test: `revocation_gossip_is_charged_against_the_unanchored_token_quota`. |
| G2 | High | **Delegated-admin revocation does not cascade.** With `root → A → B`, revoking A's promotion removed A but left B in the swarm's root set, even after the periodic reconcile; B could then grant a publisher capability. | Confirmed. The token-driven path demoted only the revoked vouch's subject. That erased the evidence the periodic pass needs: it treats a root as demotable only when a current or start-of-pass root vouched for it, and A was already gone, so B looked config-anchored. On a revoked `dds:admin` vouch whose subject is a current root, the token path now runs the shared `reconcile_roots_against_graph` on the root set as it stood before any demotion, which demotes A and every sub-admin A promoted in the same call and keeps the F2 rule from the first follow-up round (a root nobody authorised ever vouched is never demoted). The revocations topic now triggers the same update, instead of waiting for the next guard tick. Test: `revoking_a_delegated_admin_cascades_through_its_sub_admins` (three-level chain, delivered by sync and by revocation gossip). |

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
