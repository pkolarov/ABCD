// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Enforcement mode, mirroring the Rust <c>Enforcement</c> enum.
/// </summary>
public enum EnforcementMode
{
    /// <summary>Log what would change but don't apply.</summary>
    Audit,
    /// <summary>Apply the change.</summary>
    Enforce,
}

/// <summary>
/// Outcome of a single directive application.
/// </summary>
public sealed record EnforcementOutcome(
    EnforcementStatus Status,
    string? Error = null,
    IReadOnlyList<string>? Changes = null);

public enum EnforcementStatus
{
    Ok,
    Failed,
    Skipped,
}

/// <summary>
/// A pluggable enforcer that knows how to apply one category of
/// Windows policy directives (registry, accounts, password policy,
/// services, or software installation). Each enforcer is
/// <b>idempotent</b>: it reads current state first and only writes
/// deltas.
/// <para>
/// Phase C ships all enforcers as <b>log-only stubs</b> — they
/// report what they <em>would</em> do, regardless of
/// <paramref name="mode"/>. Real Win32 implementations land in
/// Phases D–F.
/// </para>
/// </summary>
public interface IEnforcer
{
    /// <summary>
    /// Human-readable name (e.g. "Registry", "Account").
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Apply a JSON element representing the directive payload.
    /// The element is one member of the <c>WindowsSettings</c>
    /// bundle (e.g. the <c>registry</c> array or the
    /// <c>password_policy</c> object).
    /// </summary>
    Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive,
        EnforcementMode mode,
        CancellationToken ct = default);
}
