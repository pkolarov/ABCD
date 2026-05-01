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
}
