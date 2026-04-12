// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent.MacOS.State;

namespace DDS.PolicyAgent.MacOS.Tests;

public class AppliedStateStoreTests : IDisposable
{
    private readonly string _tmpDir;
    private readonly AppliedStateStore _store;

    public AppliedStateStoreTests()
    {
        _tmpDir = Path.Combine(Path.GetTempPath(), $"dds-macos-test-{Guid.NewGuid():N}");
        _store = new AppliedStateStore(_tmpDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tmpDir, recursive: true); }
        catch { }
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
        => Assert.True(_store.HasChanged("p:new", "sha256:aaa"));

    [Fact]
    public void RecordApplied_then_HasChanged_returns_false_for_same_hash()
    {
        _store.RecordApplied("p:test", "1", "sha256:abc", "ok", isSoftware: false);
        Assert.False(_store.HasChanged("p:test", "sha256:abc"));
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
        var store2 = new AppliedStateStore(_tmpDir);
        Assert.False(store2.HasChanged("p:persist", "sha256:xyz"));
    }
}
