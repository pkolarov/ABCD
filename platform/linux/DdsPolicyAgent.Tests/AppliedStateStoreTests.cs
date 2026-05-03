using DDS.PolicyAgent.Linux.State;

namespace DDS.PolicyAgent.Linux.Tests;

public sealed class AppliedStateStoreTests
{
    [Fact]
    public void CreatesStateDirectoryAndRecordsTerminalStatus()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            Assert.True(Directory.Exists(dir));

            Assert.True(store.HasChanged("policy-a", "abc"));
            store.RecordApplied("policy-a", "1", "abc", "ok");
            Assert.False(store.HasChanged("policy-a", "abc"));
            Assert.True(File.Exists(Path.Combine(dir, "applied-state.json")));
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SkippedStatusIsTerminalAndUnchanged()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.RecordApplied("policy-b", "1", "xyz", "skipped");
            Assert.False(store.HasChanged("policy-b", "xyz"));
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RetriesFailedStatus()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.RecordApplied("policy-a", "1", "abc", "failed");
            Assert.True(store.HasChanged("policy-a", "abc"));
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RemoveManagedUsername_RemovesFromSet()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.RecordManagedUsername("alice");
            Assert.Contains("alice", store.Load().ManagedUsernames);

            store.RemoveManagedUsername("alice");
            Assert.DoesNotContain("alice", store.Load().ManagedUsernames);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RemoveManagedPath_RemovesFromSet()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.RecordManagedPath("/etc/dds/policy.conf");
            Assert.Contains("/etc/dds/policy.conf", store.Load().ManagedPaths);

            store.RemoveManagedPath("/etc/dds/policy.conf");
            Assert.DoesNotContain("/etc/dds/policy.conf", store.Load().ManagedPaths);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RemoveManagedPackage_RemovesFromSet()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.RecordManagedPackage("curl");
            Assert.Contains("curl", store.Load().ManagedPackages);

            store.RemoveManagedPackage("curl");
            Assert.DoesNotContain("curl", store.Load().ManagedPackages);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Remove_OnAbsentEntry_IsNoOp()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            // Remove on an entry that was never added must not throw.
            store.RemoveManagedUsername("nobody");
            store.RemoveManagedPath("/nonexistent");
            store.RemoveManagedPackage("missing-pkg");
            Assert.Empty(store.Load().ManagedUsernames);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }
}
