// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.HostState;
using DDS.PolicyAgent.State;

namespace DDS.PolicyAgent.Tests;

public class AppliedStateStoreTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly AppliedStateStore _store;

    public AppliedStateStoreTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), $"dds-test-{Guid.NewGuid():N}");
        _store = new AppliedStateStore(_tmpDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); }
        catch { /* best-effort cleanup */ }
    }

    [Fact]
    public void Fresh_store_returns_empty_state()
    {
        var state = _store.Load();
        Assert.Empty(state.Policies);
        Assert.Empty(state.Software);
    }

    [Fact]
    public void HasChanged_returns_true_for_unseen_target()
    {
        Assert.True(_store.HasChanged("p:new", "sha256:aaa"));
    }

    [Fact]
    public void RecordApplied_then_HasChanged_returns_false_for_same_hash()
    {
        _store.RecordApplied("p:test", "1", "sha256:abc", "ok", isSoftware: false);
        Assert.False(_store.HasChanged("p:test", "sha256:abc"));
    }

    [Fact]
    public void HasChanged_returns_true_when_hash_differs()
    {
        _store.RecordApplied("p:test", "1", "sha256:old", "ok", isSoftware: false);
        Assert.True(_store.HasChanged("p:test", "sha256:new"));
    }

    // B-3 (security review): a previously failed apply must remain
    // re-eligible on the next poll, even when the content hash matches.
    // Without this, a transient enforcer failure latches forever and
    // the document is never re-tried.
    [Fact]
    public void HasChanged_returns_true_when_last_status_is_failed_policy()
    {
        _store.RecordApplied("p:test", "1", "sha256:abc", "failed", isSoftware: false);
        Assert.True(_store.HasChanged("p:test", "sha256:abc"));
    }

    [Fact]
    public void HasChanged_returns_true_when_last_status_is_failed_software()
    {
        _store.RecordApplied("com.example.app", "1.0", "sha256:sw", "failed", isSoftware: true);
        Assert.True(_store.HasChanged("com.example.app", "sha256:sw"));
    }

    [Fact]
    public void HasChanged_returns_false_when_last_status_is_skipped_unchanged_content()
    {
        // "skipped" means the doc had nothing applicable on this host;
        // re-running unchanged content cannot change that outcome.
        _store.RecordApplied("p:other", "1", "sha256:s", "skipped", isSoftware: false);
        Assert.False(_store.HasChanged("p:other", "sha256:s"));
    }

    [Fact]
    public void Software_entries_are_stored_separately()
    {
        _store.RecordApplied("com.example.editor", "1.0", "sha256:sw", "ok", isSoftware: true);
        var state = _store.Load();
        Assert.Empty(state.Policies);
        Assert.Single(state.Software);
        Assert.Equal("sha256:sw", state.Software["com.example.editor"].ContentHash);
    }

    [Fact]
    public void State_persists_across_instances()
    {
        _store.RecordApplied("p:persist", "2", "sha256:xyz", "ok", isSoftware: false);

        // New instance reads from disk
        var store2 = new AppliedStateStore(_tmpDir);
        Assert.False(store2.HasChanged("p:persist", "sha256:xyz"));
    }

    [Fact]
    public void Save_and_reload_preserves_state()
    {
        var state = new AppliedState();
        state.Policies["p:manual"] = new AppliedEntry
        {
            Version = "3",
            ContentHash = "sha256:manual",
            AppliedAt = 123456,
            Status = "ok",
        };
        _store.Save(state);

        var reloaded = new AppliedStateStore(_tmpDir).Load();
        Assert.Single(reloaded.Policies);
        Assert.Equal("sha256:manual", reloaded.Policies["p:manual"].ContentHash);
    }

    // --- AD-04: ManagedItems schema migration & audit-frozen lifecycle --

    [Fact]
    public void Legacy_managed_items_array_is_migrated_to_records_on_load()
    {
        // Hand-craft a pre-AD-04 state file with managed_items as
        // arrays of strings (the old shape).
        var legacyJson = """
        {
          "policies": {},
          "software": {},
          "managed_items": {
            "registry": ["HKLM\\Software\\Foo", "HKLM\\Software\\Bar"],
            "accounts": ["alice"]
          }
        }
        """;
        File.WriteAllText(Path.Combine(_tmpDir, "applied-state.json"), legacyJson);

        var migrated = new AppliedStateStore(_tmpDir);
        var registry = migrated.Load().ManagedItems["registry"];
        Assert.Equal(2, registry.Count);
        Assert.True(registry.ContainsKey("HKLM\\Software\\Foo"));
        Assert.Equal("legacy", registry["HKLM\\Software\\Foo"].LastOutcome);
        Assert.Equal(nameof(JoinState.Unknown), registry["HKLM\\Software\\Foo"].HostStateAtApply);
        Assert.False(registry["HKLM\\Software\\Foo"].AuditFrozen);

        // The legacy keys are still surfaced through GetManagedItems.
        var keys = migrated.GetManagedItems("registry");
        Assert.Contains("HKLM\\Software\\Foo", keys);
        Assert.Contains("HKLM\\Software\\Bar", keys);
    }

    [Fact]
    public void RecordManagedItems_in_workgroup_mode_removes_stale_items()
    {
        _store.RecordManagedItems(
            "registry",
            new HashSet<string> { "a", "b", "c" },
            JoinState.Workgroup, auditMode: false, reason: null);
        Assert.Equal(3, _store.GetManagedItems("registry").Count);

        // Drop "c" from the next desired set in workgroup mode.
        _store.RecordManagedItems(
            "registry",
            new HashSet<string> { "a", "b" },
            JoinState.Workgroup, auditMode: false, reason: null);
        var keys = _store.GetManagedItems("registry");
        Assert.Equal(2, keys.Count);
        Assert.DoesNotContain("c", keys);
    }

    [Fact]
    public void RecordManagedItems_in_audit_mode_freezes_stale_items_with_combined_reason()
    {
        _store.RecordManagedItems(
            "registry",
            new HashSet<string> { "a", "b" },
            JoinState.Workgroup, auditMode: false, reason: null);

        // Now under AD-coexistence audit: the desired set drops "b".
        _store.RecordManagedItems(
            "registry",
            new HashSet<string> { "a" },
            JoinState.AdJoined, auditMode: true,
            reason: AppliedReason.AuditDueToAdCoexistence);

        var state = _store.Load();
        // "b" must still be present and audit-frozen.
        Assert.True(state.ManagedItems["registry"].ContainsKey("b"));
        var record = state.ManagedItems["registry"]["b"];
        Assert.True(record.AuditFrozen);
        Assert.Equal(nameof(JoinState.AdJoined), record.HostStateAtApply);
        Assert.NotNull(record.LastReason);
        // The combined reason carries both the primary AD-coexistence
        // code and the would_clean_stale sub-reason.
        Assert.Contains(AppliedReason.AuditDueToAdCoexistence, record.LastReason);
        Assert.Contains(AppliedReason.WouldCleanStale, record.LastReason);
    }

    [Fact]
    public void Workgroup_transition_clears_audit_frozen_when_item_returns_to_desired_set()
    {
        // Seed: workgroup managed.
        _store.RecordManagedItems(
            "registry",
            new HashSet<string> { "a" },
            JoinState.Workgroup, auditMode: false, reason: null);

        // AD-joined audit pass marks the item frozen because policy dropped it.
        _store.RecordManagedItems(
            "registry",
            new HashSet<string>(),
            JoinState.AdJoined, auditMode: true,
            reason: AppliedReason.AuditDueToAdCoexistence);
        Assert.True(_store.Load().ManagedItems["registry"]["a"].AuditFrozen);

        // Host transitions back to workgroup AND policy re-includes "a".
        _store.RecordManagedItems(
            "registry",
            new HashSet<string> { "a" },
            JoinState.Workgroup, auditMode: false, reason: null);

        var record = _store.Load().ManagedItems["registry"]["a"];
        Assert.False(record.AuditFrozen);
        Assert.Equal("applied", record.LastOutcome);
        Assert.Equal(nameof(JoinState.Workgroup), record.HostStateAtApply);
    }

    [Fact]
    public void RecordApplied_with_host_state_round_trips_via_GetHostStateAtApply()
    {
        _store.RecordApplied(
            "p:test", "1", "sha256:abc", "ok",
            isSoftware: false, hostState: JoinState.AdJoined);
        var prior = _store.GetHostStateAtApply("p:test", isSoftware: false);
        Assert.Equal(JoinState.AdJoined, prior);
    }

    [Fact]
    public void GetHostStateAtApply_returns_null_for_legacy_entries_without_stamp()
    {
        // The 5-arg overload writes an empty HostStateAtApply.
        _store.RecordApplied("p:legacy", "1", "sha256:abc", "ok", isSoftware: false);
        Assert.Null(_store.GetHostStateAtApply("p:legacy", isSoftware: false));
    }

    [Fact]
    public void ManagedItems_round_trip_preserves_records_across_instances()
    {
        _store.RecordManagedItems(
            "accounts",
            new HashSet<string> { "alice", "bob" },
            JoinState.AdJoined, auditMode: true,
            reason: AppliedReason.AuditDueToAdCoexistence);

        var rehydrated = new AppliedStateStore(_tmpDir).Load();
        var record = rehydrated.ManagedItems["accounts"]["alice"];
        Assert.Equal("audit", record.LastOutcome);
        Assert.Equal(AppliedReason.AuditDueToAdCoexistence, record.LastReason);
        Assert.Equal(nameof(JoinState.AdJoined), record.HostStateAtApply);
    }
}
