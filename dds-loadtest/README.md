# dds-loadtest

Long-running multinode load/soak harness for DDS. Spins up N in-process
`DdsNode`s wired into a libp2p full-mesh, drives a realistic mixed
workload against per-node `LocalService` instances, and emits KPI
verdicts aligned with the §10 performance budgets in
[`STATUS.md`](../STATUS.md).

This is a *measurement tool*, not production code. It deliberately uses
the in-process Rust API (`LocalService` / `DdsNode`) rather than the
HTTP server — an HTTP-API soak run is a future follow-up.

## Workload

Per-tick (100 ms) ops are distributed round-robin across N nodes:

| Op             | Default rate          | API path |
|---|---|---|
| `enroll_user`  | 500 / hour            | `LocalService::enroll_user` (FIDO2 `none` attestation) |
| `enroll_device`| 1,000 / hour          | `LocalService::enroll_device` |
| `issue_session`| 50 / sec              | `LocalService::issue_session` (300 s exp) |
| `evaluate_policy` | 200 / sec          | `LocalService::evaluate_policy` |
| `revocations`  | 5 / hour              | `MemoryBackend::revoke` |
| `crdt_merge`   | 10 / sec (sampled)    | `LwwRegister::merge` |
| `ed25519_verify` | batched 4096 / 100 ms | `ed25519_dalek::VerifyingKey::verify` |
| `gossip_propagation` probe | 1 / 2 s   | publish a synthetic `Operation` from node 0, time the receive on the rest |
| `revocation_propagation` probe | 1 / 10 s | analogous on the revocations topic |

Synthetic users / devices use a small fixed corpus of names, OS variants,
org-units and tags so the workload looks plausible without leaking real
data.

### Soak hygiene

* Sessions issued during the soak have a 5-minute expiry and the
  `dds-node` expiry sweep runs every 30 s, so the trust graph stays
  bounded over 24 h instead of growing without bound.
* The user pool is capped at 2,000 entries on each node — beyond that
  the harness cycles enrollments through a ring buffer.
* Every op is wrapped in `Result` handling and recorded as `err` in the
  per-op histogram instead of crashing the harness.

## Metrics

* **Per-op latency histograms** via `hdrhistogram` (1 ns – 60 s, 3 sig
  figs). Recorded in nanoseconds.
* **Gauge samples** every 30 s: process RSS (via `sysinfo`),
  trust-graph token count per node, store token count per node, and an
  RSS-delta proxy for "idle gossip bandwidth" (libp2p does not directly
  expose per-second TX/RX byte counters; see *Known limitations*).
* **Counters** per op type: ok / err.

## KPI mapping (§10)

| §10 KPI | How it's measured |
|---|---|
| Local auth decision ≤ 1 ms | max p99 of `evaluate_policy` and `session_validate` |
| Ed25519 verify ≥ 50K ops/s | 1 / p50(`ed25519_verify` per-op) — batched (4096 / sample) so per-op cost dominates over `Instant::now` overhead |
| CRDT merge ≤ 0.05 ms p99 | p99 of `crdt_merge` (`LwwRegister::merge`) |
| Peak heap ≤ 5 MB / 1K entries | max(RSS) / max(Σ trust-graph tokens) × 1000 — coarse, includes the libp2p baseline; reported as **WARN** if exceeded because the per-process floor is unrelated to per-token cost |
| Idle gossip bandwidth ≤ 2 KB/s | RSS-delta proxy from the 30 s gauge; reported with a "see README" note |
| Enrollment latency | informational: `enroll_user` p99 |
| Gossip propagation | publish-to-receive wall-clock for synthetic op probes |
| Revocation propagation | analogous on the revocations topic |

## Output

* Live: `tracing` log at info level emits a rolling stats line every
  60 s (`elapsed`, total `ops`, `op_per_s`, `sess_p99_us`, `eval_p99_us`,
  `rss_mb`).
* Snapshots: every 15 min the harness writes
  `snapshot-NNNN.json` to `--output-dir` so a 24 h run isn't lost if
  the host is killed.
* On exit (SIGINT or duration elapsed): `summary.json` and `summary.md`
  in `--output-dir`. The Markdown contains the KPI verdict table, the
  full per-op histogram table, and the gauge sample series.

## Smoke mode

```bash
cargo run -p dds-loadtest --release -- --smoke --output-dir /tmp/dds-smoke
```

`--smoke` overrides duration to 60 s and node count to 3. The process
exits with status `2` if any KPI verdict is `FAIL` or any op-type error
rate exceeds 1 % — intended as a CI gate once `.github/workflows/loadtest-smoke.yml`
is added; currently run manually.
A `WARN` verdict (e.g. ed25519 throughput within 20 % of target on a
noisy CI runner) does not fail the gate.

## 24 h soak run

```bash
cargo run --release -p dds-loadtest -- \
    --duration 24h \
    --output-dir results/$(date +%Y%m%d)
```

Tune workload knobs as needed:

```bash
cargo run --release -p dds-loadtest -- \
    --duration 24h \
    --nodes 10 \
    --users-per-hour 1000 \
    --devices-per-hour 5000 \
    --sessions-per-second 100 \
    --policy-evals-per-second 500 \
    --revocations-per-hour 20 \
    --output-dir results/$(date +%Y%m%d)
```

### Interpreting `summary.md`

* **PASS** ✅ — measured value meets the §10 budget.
* **WARN** ⚠️ — measured value is close to but does not meet the budget,
  *or* the measurement is process-level (RSS, RSS-delta) where the
  per-process floor confounds the per-entry budget. Inspect the gauge
  series before concluding the implementation regressed.
* **FAIL** ❌ — measured value clearly violates the budget. Investigate.
* **SKIP** ⚪ — not enough samples to render a verdict (e.g. revocation
  propagation in a 60 s smoke run, where only 5–6 probes fire and a
  fresh gossipsub mesh on the revocations topic may not have formed).

## Known limitations

* **Idle gossip bandwidth** uses an RSS-delta proxy because libp2p does
  not expose a per-direction byte counter on `Swarm`. A real network
  byte counter would require either patching `libp2p-tcp` to thread
  through `tokio::net::TcpStream` byte counters or running each node in
  a separate process and sampling `/proc/<pid>/net/dev`. Out of scope
  for this harness — the criterion benches and a future netem-based
  test should give a sharper number.
* **Heap-per-1K-entries** is RSS-based and therefore includes the
  libp2p / tokio runtime baseline. A `dhat` profile (or
  `--features=dhat-heap`) would give a clean per-allocation accounting,
  also out of scope here.
* **HTTP-API soak** (driving `/v1/*` over reqwest) is a future
  follow-up — the current harness exercises the in-process API.
