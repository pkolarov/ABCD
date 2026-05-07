// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent.Client;
using DDS.PolicyAgent.HostState;
using DDS.PolicyAgent.State;

namespace DDS.PolicyAgent.Tests;

/// <summary>
/// In-memory IAppliedStateStore for Worker-level reconciliation tests.
/// Pre-seed ManagedItems to simulate items managed in a prior cycle;
/// inspect RecordCalls after running a poll cycle to verify the Worker
/// updated the tracked set correctly.
/// </summary>
internal sealed class TrackingAppliedStateStore : IAppliedStateStore
{
    private readonly Dictionary<string, HashSet<string>> _managed;

    public Dictionary<string, HashSet<string>> RecordCalls { get; } = new(StringComparer.Ordinal);

    public TrackingAppliedStateStore(Dictionary<string, HashSet<string>>? initial = null)
        => _managed = initial ?? [];

    public AppliedState Load() => new();
    public void Save(AppliedState state) { }
    public bool HasChanged(string targetId, string contentHash) => false;
    public void RecordApplied(string targetId, string version, string contentHash, string status, bool isSoftware) { }
    public void RecordApplied(string targetId, string version, string contentHash, string status, bool isSoftware, JoinState? hostState) { }

    public IReadOnlySet<string> GetManagedItems(string category)
        => _managed.TryGetValue(category, out var set) ? set : new HashSet<string>();

    public void RecordManagedItems(string category, IReadOnlySet<string> desired, JoinState joinState, bool auditMode, string? reason)
    {
        var newSet = new HashSet<string>(desired, StringComparer.OrdinalIgnoreCase);
        RecordCalls[category] = newSet;
        _managed[category] = newSet;
    }

    public JoinState? GetHostStateAtApply(string targetId, bool isSoftware) => null;
}

/// <summary>
/// Controllable IDdsNodeClient for Worker-level tests.
/// Collects all ReportAppliedAsync calls in ReceivedReports for assertion.
/// </summary>
internal sealed class TestWindowsDdsNodeClient : IDdsNodeClient
{
    public List<ApplicableWindowsPolicy> NextPolicies { get; set; } = [];
    public List<ApplicableSoftware> NextSoftware { get; set; } = [];
    public List<AppliedReport> ReceivedReports { get; } = [];

    public Task<List<ApplicableWindowsPolicy>> GetPoliciesAsync(string deviceUrn, CancellationToken ct = default)
        => Task.FromResult(NextPolicies);

    public Task<List<ApplicableSoftware>> GetSoftwareAsync(string deviceUrn, CancellationToken ct = default)
        => Task.FromResult(NextSoftware);

    public Task ReportAppliedAsync(AppliedReport report, CancellationToken ct = default)
    {
        ReceivedReports.Add(report);
        return Task.CompletedTask;
    }
}
