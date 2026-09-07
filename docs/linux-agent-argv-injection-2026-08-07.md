# Linux Agent argv-Injection Parity Fix — 2026-08-07

**Scope:** Bring the Linux policy agent's command-execution layer to parity with the
macOS agent's `ArgumentList`-based model, closing an argument-injection hole in
`DdsPolicyAgent` (Linux). Sibling of the macOS finding **H9** ("macOS password on
argv") tracked in `ship-readiness-audit-2026-06-12.md`.

**Build health:** `dotnet test` (Linux) — **371 passed, 0 failed** (2 new regression
cases). macOS and Windows managed projects unaffected (Linux-only change).

---

## The defect

`Runtime/CommandRunner.cs`'s `ProcessCommandRunner.RunAsync(string fileName, string
arguments)` passed the arguments as a single string to the
`ProcessStartInfo(fileName, arguments)` constructor. That constructor **re-tokenises
the string on whitespace** to build the child process's argv. The Linux enforcers
built those argument strings by interpolation (e.g. `$"-c {ShellEscape(fullName)}"`,
`$"-aG {group} {user}"`), and `UserEnforcer` even applied POSIX single-quote escaping
to the GECOS field.

That escaping was **ineffective**: single quotes are a *shell* quoting mechanism, and
no shell is involved here — `ProcessStartInfo`'s own splitter ignores them. A
DDS-managed user's attacker-influenceable `full_name` (or any interpolated value that
slipped past a validator) was therefore re-split into multiple argv elements. A
crafted `full_name` such as `Ada -G sudo -u 0` injected extra `useradd`/`usermod`
flags — adding the account to group `sudo`, or forcing uid `0`.

The `Is*` validators (`IsSafeShellPath`, `IsValidGroupName`, …) reject spaces/dashes
and were the *only* thing standing between policy input and flag injection; the GECOS
field had no such guard because free-form names legitimately contain spaces. Defence
belonged at the exec boundary, not in per-field allowlists.

## The fix

Modelled on the macOS agent (`platform/macos/.../Runtime/CommandRunner.cs`, which
already builds `ProcessStartInfo.ArgumentList` with `UseShellExecute = false`):

- **`ICommandRunner.RunAsync`** now takes `IReadOnlyList<string> arguments` (an
  explicit argv vector) instead of a single joined string.
- **`ProcessCommandRunner`** populates `ProcessStartInfo.ArgumentList`, which passes
  each element to the child verbatim and does **not** re-tokenise on whitespace. A
  value containing spaces or leading dashes stays exactly one argument.
- **`UserEnforcer`**: `full_name` / shell / uid / groups are now separate argv
  elements. The now-pointless `ShellEscape` helper is **removed** — the GECOS value is
  handed over raw and cannot be reinterpreted as flags.
- **All seven Linux enforcers** updated to build argv lists: `UserEnforcer`,
  `SudoersEnforcer`, `FileEnforcer`, `SystemdEnforcer`, `PackageEnforcer`,
  `SysctlEnforcer`, `SshdEnforcer`.
- **`NullCommandRunner`** (test double) records the true argv (`RecordedCommand.Argv`)
  and exposes a lossy space-joined `Arguments` view purely for backward-compatible
  substring/equality assertions. Argument-boundary assertions must use `Argv`.

The existing `Is*` validators are retained as defence-in-depth (and to keep obviously
malformed values out of commands), but correctness no longer depends on them.

## Verification

`WorkerTests.UserFullName_WithEmbeddedFlags_ReachesRunnerAsSingleArgvElement`
(`[Theory]` over the `Create`→`useradd` and `Modify`→`usermod` paths) drives a
`full_name` of `Ada -G sudo -u 0` through `UserEnforcer` and asserts:

- the value arrives as a **single** argv element immediately after `-c`, and
- none of `-G`, `-u`, `sudo`, `0` appears as its own argv element.

Under the old whitespace-splitting path those tokens would have been standalone argv
elements (and real flags), so the test fails against the pre-fix behaviour.
