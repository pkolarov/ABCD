// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.State;

/// <summary>
/// Reason-code constants reported on every <see cref="Client.AppliedReport"/>
/// and recorded on every <see cref="ManagedItemRecord.LastReason"/> entry.
/// See <c>docs/windows-ad-coexistence-spec.md §7.2</c> for the canonical
/// taxonomy.
///
/// Primary reasons are mutually exclusive at the report level. Sub-reasons
/// (the <c>Would*</c> values) are concatenated to the primary reason with a
/// colon, e.g. <c>audit_due_to_ad_coexistence:would_correct_drift</c>, when
/// extra context about an audit-mode skip is useful for operators.
/// </summary>
public static class AppliedReason
{
    /// <summary>
    /// Effective mode forced to Audit because the host is AD-joined or
    /// hybrid AD+Entra. Surfaces on every applied-report and on every
    /// <see cref="ManagedItemRecord"/> written while the join state is
    /// <see cref="HostState.JoinState.AdJoined"/> or
    /// <see cref="HostState.JoinState.HybridJoined"/>.
    /// </summary>
    public const string AuditDueToAdCoexistence = "audit_due_to_ad_coexistence";

    /// <summary>
    /// Effective mode forced to Audit because the JoinState probe failed
    /// (returned <see cref="HostState.JoinState.Unknown"/>). Fail-closed
    /// fallback so a transient probe failure cannot let the agent mutate
    /// host state with the wrong assumption.
    /// </summary>
    public const string AuditDueToUnknownHostState = "audit_due_to_unknown_host_state";

    /// <summary>
    /// Heartbeat report emitted once per poll cycle on Entra-only hosts.
    /// The worker short-circuits before any directive evaluation —
    /// applied-state contains a single <c>_host_state</c> record per cycle
    /// with this reason so operators can see clear evidence the agent is
    /// alive and refusing.
    /// </summary>
    public const string UnsupportedEntra = "unsupported_entra";

    /// <summary>
    /// Re-probe at the top of <see cref="Worker.PollAndApplyAsync"/>
    /// observed a JoinState change since the previous cycle. Forces a
    /// one-time audit evaluation/report for every previously-applied
    /// document even when its content hash is unchanged, so the audit
    /// trail proves DDS reacted to the transition.
    /// </summary>
    public const string HostStateTransitionDetected = "host_state_transition_detected";

    /// <summary>
    /// Sub-reason for an audit record: enforcement would have applied a
    /// previously-unmanaged item in workgroup mode.
    /// </summary>
    public const string WouldApply = "would_apply";

    /// <summary>
    /// Sub-reason for an audit record: enforcement would have corrected
    /// observed drift on an already-managed item.
    /// </summary>
    public const string WouldCorrectDrift = "would_correct_drift";

    /// <summary>
    /// Sub-reason for an audit record: reconciliation would have unwound
    /// a stranded item that has dropped out of policy. In audit mode the
    /// item stays in the inventory with <see cref="ManagedItemRecord.AuditFrozen"/>
    /// set so a future workgroup transition can resume cleanup.
    /// </summary>
    public const string WouldCleanStale = "would_clean_stale";

    /// <summary>
    /// Combine a primary reason with an optional sub-reason. Returns just
    /// the primary if the sub-reason is null or empty.
    /// </summary>
    public static string Combine(string primary, string? sub)
        => string.IsNullOrEmpty(sub) ? primary : $"{primary}:{sub}";
}
