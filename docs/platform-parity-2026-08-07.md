# DDS Platform Parity — Linux/macOS vs Windows (2026-08-07)

**Goal:** make DDS on Linux and macOS at least as usable as on Windows —
more solid setup wizards, clearer mesh monitoring — and fix issues found
along the way. **CI must stay green.**

**Method:** a six-lens parallel map of the three platforms (Windows
console + onboarding, macOS scripts, Linux scripts, mesh-monitoring
surface, policy-agent parity, and re-verification of the prior
`docs/code-analysis-2026-07-06.md` findings), then first-hand
verification of every finding acted on before changing code.

**The core gap.** Windows ships one guided WPF console (`DdsConsole.ps1`,
~3,300 lines) with onboarding-state detection, live-progress wizards,
flow journaling, and a 2-second-refresh **Health** tab. Linux/macOS ship
a set of shell wizards that are individually solid but had (a) no unified
health/mesh view equivalent to the Health tab, and (b) several
correctness/security defects that made a bootstrapped node fragile. The
Rust observability core (`dds stats`, `dds health`, `/readyz`, `/metrics`)
is already cross-platform and strong; the gap was in the platform layer.

---

## Fixed in this pass

### Setup-wizard solidity

| # | Sev | Platform | Fix |
|---|-----|----------|-----|
| 1 | **High** | Linux | `dds-bootstrap-domain` now `systemctl enable`s `dds-node` **and** `dds-policy-agent`, not just `restart`. The units carry `WantedBy=multi-user.target`, so without `enable` the node **did not come back after a reboot** (macOS already does the equivalent `launchctl enable`). |
| 2 | **High** | macOS + Linux | `dds-bootstrap-domain` now copies the domain's `pq_pubkey` from `domain.toml` into `dds.toml`'s `[domain]` block. `init-domain` **defaults to hybrid** (Ed25519 + ML-DSA-65); a missing `[domain].pq_pubkey` makes dds-node treat a hybrid domain as **legacy Ed25519-only** and silently skip ML-DSA verification of admission certs/revocations — a PQ downgrade (`dds-node/src/node.rs:703-706,897`). |
| 3 | **High** | Linux | The `.deb` now `Depends:` on `curl` and `python3`. Every operator script and the watchdog shell out to both; on a minimal server install they were missing and the wizards died with "command not found". Also corrected the stale "no-op policy agent" package description (real enforcers ship). |

### Mesh monitoring — the Health-tab equivalent

| # | Platform | Fix |
|---|----------|-----|
| 4 | macOS + Linux | **New `dds-status` command** — the cross-platform answer to the Windows Health tab. One glance shows: service states (node/policy-agent/watchdog), API-socket state, node URN + peer id, **peers (connected / admitted, with a "connected but NOT admitted" flag)**, trusted-root count, token counts, uptime, last-admission-failure, `/readyz` readiness, on-disk state inventory, and a recent error-loop log signal. `--watch [secs]` refreshes live (Windows' 2 s auto-refresh); `--json` for scripting. Packaged in the `.deb` and the macOS `.pkg`, surfaced in the bootstrap "next steps", and referenced from `dds-domain`'s status menu and `SECOND-NODE.md`. |
| 5 | all | Added a real version probe: **`dds-node version`** and **`dds --version`**. Neither binary had one; `dds-verify-replication` was running *bare* `dds-node` to read a version, which defaults to the `run` subcommand and **starts a node** — hanging the script or fighting the live node for its socket. Both verify-replication scripts now call `dds-node version`. |

### Security / correctness in the platform scripts

| # | Sev | Platform | Fix |
|---|-----|----------|-----|
| 6 | **Medium** | macOS + Linux | `dds-enroll-admin` no longer round-trips the admin URN through a fixed, world-writable `/tmp/dds-enroll-admin.log` (root writer → symlink-clobber; injected `urn:` line → poisoned `ADMIN_URN` that flows into `bootstrap.env`, which other root scripts `source`). Now a private `mktemp` file under the 0700 node dir, removed on exit, plus a strict `^urn:vouchsafe:[A-Za-z0-9._:-]+$` check before use. (Prior review's M-1; the python-injection half was already gone, the `/tmp` half was not.) |
| 7 | **Medium** | macOS + Linux | `dds-account` `mktemp` used a non-trailing-X template (`dds-account-XXXXXX.json`): **unsubstituted (fixed, predictable name) on BSD**, **rejected on busybox/Alpine**, safe only on GNU. Now `…/dds-account.XXXXXX` (trailing X's) — randomizes on all three. Also moved the version-lookup `POLICY_ID` from string-interpolation-into-python to an env var (quote/`'` → broken or injected code). |
| 8 | **Medium** | macOS + Linux | `dds-domain`'s status view no longer writes a fixed `/tmp/dds-domain-status.json` (root writer, symlink-clobber); it pipes the API response straight to `python3` over stdin. |
| 9 | **High** | macOS | (covered by #5) the bare-`dds-node` version probe in `dds-verify-replication`. |

### Policy-agent parity (Linux)

| # | Sev | Fix |
|---|-----|-----|
| 10 | **Critical** | Linux `Worker.cs` reported status `"error"` on an enforcer exception. The node's `AppliedStatus` is only `ok`/`failed`/`skipped` (`dds-node/src/service.rs:535`), so the POST was **rejected (422)**; `ReportAppliedAsync` calls `EnsureSuccessStatusCode()` (throws) with no isolation, so **one errored policy aborted the entire poll cycle — reconciliation included — on every future cycle.** Now reports `"failed"` (matching macOS/Windows). |
| 11 | **High** | Added `SafeReportAsync` around every report send (mirroring the macOS agent's `ReportAsync`) so a transient node error logs and continues instead of aborting the cycle. |

Both are locked in by new tests (`EnforcerException_ReportsFailedStatus_NotError`,
`RejectedReport_DoesNotAbortPollCycle`) — Linux agent suite: 371 passing (2 new).

### Docs

- `SECOND-NODE.md` Verify section no longer tells operators to
  `curl http://127.0.0.1:5551` (no such listener on a packaged UDS/pipe
  node) — points at `dds-status` / the Windows Health tab, with the
  loopback-TCP caveat scoped to the manual-config path.
- Fixed the stray `. ` that broke the macOS `README.md` H1.

### CI

- New **`shell-lint`** job: syntax-checks every `platform/**/*.sh` with the
  interpreter its shebang names (zsh for macOS, bash for Linux) and runs
  an advisory `shellcheck` pass on the bash scripts. The operator wizards
  and the new monitoring command had **zero** CI coverage before this.

---

## Verified but deliberately deferred

These are real (verified first-hand) but were left out of this pass
because they change subtle cross-platform enforcement semantics that need
integration testing on real hosts (which CI cannot provide), or are
out of the Linux/macOS scope, or belong to a separate security pass.

### Policy-agent enforcement semantics (needs real-host integration tests)

- **Audit-mode reconcile still mutates managed state** — macOS
  (`Worker.cs:281`) drops stale items from the managed inventory during an
  *audit* reconcile (orphaning them), and Linux (`Worker.cs:362`) removes
  managed-resource entries during an `AuditOnly` reconcile — and
  `AuditOnly=true` is the shipped Linux default. Windows
  (`Worker.cs:182`) reconciliation ignores document-level `Audit` and can
  delete host state DDS never wrote.
- **Per-document `enforcement` ignored on Linux** (`Worker.cs:117`): Linux
  enforcers are wired to the agent-global `AuditOnly` and ignore a
  policy's own `Audit`/`Enforce` field; macOS/Windows honor it per
  document.
- **Linux command runner argument splitting** (`Runtime/CommandRunner.cs:22`):
  passes a single joined argument string, defeating `UserEnforcer`'s POSIX
  single-quote escaping — a `full_name` could inject `useradd`/`usermod`
  flags. Needs the runner to take `argv` as a list.
- **Windows software installs are version-blind** (`SoftwareInstaller.cs:131`):
  a version bump on an already-installed package is a permanent no-op.
- `applied-state.json` written without permission hardening on macOS/Linux
  (`State/AppliedStateStore.cs:176`).

### Out of Linux/macOS scope (flagged, not changed here)

- **Windows bootstrap has the same `pq_pubkey` omission** (#2) —
  `Bootstrap-DdsDomain.ps1` writes only `pubkey`. Same silent PQ
  downgrade; unfixed here because it is a PowerShell change untestable
  from this environment.
- **`pam_dds` is implemented (~950 lines) but packaged nowhere** — no
  Linux login path ships, unlike the Windows Credential Provider. The
  Linux plan (`platform/linux/README.md` L-5) explicitly defers PAM, so
  this is WIP, not a regression; packaging it needs real PAM testing.
- **RPM packaging** is planned (`README.md`) but absent; only `.deb` +
  Alpine/OpenRC exist.

### Prior Rust-core security findings (cross-platform; separate pass)

Re-verified against HEAD — status unchanged from
`docs/code-analysis-2026-07-06.md`: **M-2 OPEN** (no `CAPABILITY_ENC_V3`
plaintext-downgrade guard on the sync-ingest path —
`dds-node/src/node.rs:4703`), **L-1 OPEN** (sync-ingest emits no
audit-chain entries), **L-3/L-4/I-1/I-2 OPEN**, **I-3 PARTIAL**. These are
core-security, not platform-usability, and are best handled in a focused
security pass on both ingest paths (cf. the "sync path historically lags"
class).

---

## Verification

- `cargo build --workspace` — clean; `cargo test --workspace --all-features` — pass (exit 0).
- `cargo clippy` (dds-node, dds-cli) — clean under `-D warnings`; `cargo fmt --check` — clean.
- Linux policy-agent suite — 371 pass (2 new).
- Every changed/added shell script syntax-checks under its shebang interpreter.
- `dds-status` (human + `--json`) was run against a live throwaway
  **hybrid** node — confirming both the status rendering and that the new
  `pq_pubkey` config line produces a config dds-node accepts and starts
  from (`/readyz` READY).
