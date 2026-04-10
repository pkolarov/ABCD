// SPDX-License-Identifier: MIT OR Apache-2.0

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
}
