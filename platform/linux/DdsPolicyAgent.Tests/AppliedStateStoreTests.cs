// SPDX-License-Identifier: MIT OR Apache-2.0

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
    public void HasChanged_returns_true_when_hash_differs()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.RecordApplied("policy-a", "1", "sha256:old", "ok");
            Assert.True(store.HasChanged("policy-a", "sha256:new"));
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
            store.RemoveManagedSudoersFilename("missing-drop");
            store.RemoveManagedSystemdDropin("sshd.service/missing");
            Assert.Empty(store.Load().ManagedUsernames);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RemoveManagedSudoersFilename_RemovesFromSet()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.RecordManagedSudoersFilename("dds-ops");
            Assert.Contains("dds-ops", store.Load().ManagedSudoersFilenames);

            store.RemoveManagedSudoersFilename("dds-ops");
            Assert.DoesNotContain("dds-ops", store.Load().ManagedSudoersFilenames);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RemoveManagedSystemdDropin_RemovesFromSet()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.RecordManagedSystemdDropin("sshd.service/dds-limits");
            Assert.Contains("sshd.service/dds-limits", store.Load().ManagedSystemdDropins);

            store.RemoveManagedSystemdDropin("sshd.service/dds-limits");
            Assert.DoesNotContain("sshd.service/dds-limits", store.Load().ManagedSystemdDropins);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RecordManagedSudoersFilename_PersistedToDiskAndReloadedCorrectly()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.RecordManagedSudoersFilename("dds-ops");
            store.RecordManagedSudoersFilename("dds-readonly");

            var store2 = new AppliedStateStore(dir);
            var reloaded = store2.Load();
            Assert.Contains("dds-ops", reloaded.ManagedSudoersFilenames);
            Assert.Contains("dds-readonly", reloaded.ManagedSudoersFilenames);
            Assert.Equal(2, reloaded.ManagedSudoersFilenames.Count);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void RecordManagedSystemdDropin_PersistedToDiskAndReloadedCorrectly()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.RecordManagedSystemdDropin("sshd.service/dds-limits");
            store.RecordManagedSystemdDropin("dds-agent.service/hardening");

            var store2 = new AppliedStateStore(dir);
            var reloaded = store2.Load();
            Assert.Contains("sshd.service/dds-limits", reloaded.ManagedSystemdDropins);
            Assert.Contains("dds-agent.service/hardening", reloaded.ManagedSystemdDropins);
            Assert.Equal(2, reloaded.ManagedSystemdDropins.Count);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SetManagedGroups_StoresAndReplacesGroupSet()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);

            store.SetManagedGroups(["alice:sudo", "bob:docker"]);
            var state = store.Load();
            Assert.Contains("alice:sudo", state.ManagedGroups);
            Assert.Contains("bob:docker", state.ManagedGroups);
            Assert.Equal(2, state.ManagedGroups.Count);

            // Replace with a smaller set — bob:docker must be dropped.
            store.SetManagedGroups(["alice:sudo"]);
            state = store.Load();
            Assert.Contains("alice:sudo", state.ManagedGroups);
            Assert.DoesNotContain("bob:docker", state.ManagedGroups);
            Assert.Single(state.ManagedGroups);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SetManagedGroups_EmptySet_ClearsAllGroups()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.SetManagedGroups(["alice:sudo"]);
            Assert.NotEmpty(store.Load().ManagedGroups);

            store.SetManagedGroups([]);
            Assert.Empty(store.Load().ManagedGroups);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SetManagedGroups_PersistedToDiskAndReloadedCorrectly()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dds-linux-state-" + Guid.NewGuid());
        try
        {
            var store = new AppliedStateStore(dir);
            store.SetManagedGroups(["alice:sudo", "alice:adm"]);

            // Reload from disk via a second store instance pointing at the same directory.
            var store2 = new AppliedStateStore(dir);
            var reloaded = store2.Load();
            Assert.Contains("alice:sudo", reloaded.ManagedGroups);
            Assert.Contains("alice:adm", reloaded.ManagedGroups);
            Assert.Equal(2, reloaded.ManagedGroups.Count);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, recursive: true);
        }
    }
}
