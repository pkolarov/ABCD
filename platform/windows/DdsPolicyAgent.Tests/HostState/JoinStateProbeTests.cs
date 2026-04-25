// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent.HostState;

namespace DDS.PolicyAgent.Tests.HostState;

/// <summary>
/// Tests for the JoinState seam. The production probe is exercised
/// in <see cref="Integration.AccountEnforcerIntegrationTests"/>;
/// these tests cover the in-memory probe and enum invariants that
/// the rest of the codebase depends on.
/// </summary>
public class JoinStateProbeTests
{
    [Fact]
    public void JoinState_Numeric_Values_Are_Locked()
    {
        // Cross-IPC and cross-language stable contract — see
        // docs/windows-ad-coexistence-spec.md §2.1 and the matching
        // native enum in DdsAuthBridge/JoinState.h.
        Assert.Equal(0, (int)JoinState.Workgroup);
        Assert.Equal(1, (int)JoinState.AdJoined);
        Assert.Equal(2, (int)JoinState.HybridJoined);
        Assert.Equal(3, (int)JoinState.EntraOnlyJoined);
        Assert.Equal(4, (int)JoinState.Unknown);
    }

    [Fact]
    public void InMemoryProbe_Returns_Initial_Value()
    {
        var probe = new InMemoryJoinStateProbe(JoinState.AdJoined);
        Assert.Equal(JoinState.AdJoined, probe.Detect());
    }

    [Theory]
    [InlineData(JoinState.Workgroup)]
    [InlineData(JoinState.AdJoined)]
    [InlineData(JoinState.HybridJoined)]
    [InlineData(JoinState.EntraOnlyJoined)]
    [InlineData(JoinState.Unknown)]
    public void InMemoryProbe_Reflects_Current_Setter(JoinState s)
    {
        var probe = new InMemoryJoinStateProbe();
        probe.Current = s;
        Assert.Equal(s, probe.Detect());
    }

    [Fact]
    public void InMemoryProbe_Refresh_Is_NoOp()
    {
        var probe = new InMemoryJoinStateProbe(JoinState.HybridJoined);
        probe.Refresh();
        Assert.Equal(JoinState.HybridJoined, probe.Detect());
    }

    [Fact]
    public void InMemoryProbe_Default_Is_Workgroup()
    {
        // Phase 1 default — preserves existing "not domain-joined"
        // semantics for tests that don't care about the new probe.
        Assert.Equal(JoinState.Workgroup, new InMemoryJoinStateProbe().Detect());
    }
}
