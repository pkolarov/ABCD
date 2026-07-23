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

/// <summary>
/// Spec §2.2 classification contract for the
/// <c>NetGetAadJoinInformation</c> result, exercised through the pure
/// <see cref="WindowsJoinStateProbe.ClassifyAadJoinResult"/> seam. The
/// native probe (DdsAuthBridge/JoinState.cpp) mirrors this table and must
/// be kept in lockstep.
/// </summary>
#pragma warning disable CA1416 // ClassifyAadJoinResult is a pure static; no Windows API is touched.
public class AadJoinResultClassificationTests
{
    private const int S_OK = 0;
    private const int S_FALSE = 1;
    private const int E_FAIL = unchecked((int)0x80004005);
    private const int E_ACCESSDENIED = unchecked((int)0x80070005);

    [Theory]
    // Success + no join info = "device has no Entra record". S_FALSE is
    // the shape observed in the field on a never-Entra-registered
    // workgroup machine (spec §2.2 edge case 2).
    [InlineData(S_OK)]
    [InlineData(S_FALSE)]
    public void Success_with_null_info_is_no_signal(int hr)
    {
        Assert.Equal(
            WindowsJoinStateProbe.EntraSignal.None,
            WindowsJoinStateProbe.ClassifyAadJoinResult(hr, joinType: null));
    }

    [Fact]
    public void Device_not_joined_hresult_is_no_signal()
    {
        // Spec §2.2 edge case 6.
        Assert.Equal(
            WindowsJoinStateProbe.EntraSignal.None,
            WindowsJoinStateProbe.ClassifyAadJoinResult(
                WindowsJoinStateProbe.DsregEDeviceNotJoined, joinType: null));
    }

    [Theory]
    // Spec §2.2 edge case 7: unexpected failures stay fail-closed.
    [InlineData(E_FAIL)]
    [InlineData(E_ACCESSDENIED)]
    public void Unexpected_failure_hresult_is_probe_failed(int hr)
    {
        Assert.Equal(
            WindowsJoinStateProbe.EntraSignal.ProbeFailed,
            WindowsJoinStateProbe.ClassifyAadJoinResult(hr, joinType: null));
    }

    [Theory]
    // Any success code with join info honors joinType — including
    // S_FALSE, deliberately: a probe that produced a join record has
    // not failed, whatever its success code (spec §2.2 signal rows).
    [InlineData(S_OK)]
    [InlineData(S_FALSE)]
    public void Device_join_type_is_device_joined(int hr)
    {
        Assert.Equal(
            WindowsJoinStateProbe.EntraSignal.DeviceJoined,
            WindowsJoinStateProbe.ClassifyAadJoinResult(
                hr, WindowsJoinStateProbe.DSREG_JOIN_TYPE.DSREG_DEVICE_JOIN));
    }

    [Fact]
    public void Workplace_join_type_is_workplace_joined()
    {
        Assert.Equal(
            WindowsJoinStateProbe.EntraSignal.WorkplaceJoined,
            WindowsJoinStateProbe.ClassifyAadJoinResult(
                S_OK, WindowsJoinStateProbe.DSREG_JOIN_TYPE.DSREG_WORKPLACE_JOIN));
    }

    [Fact]
    public void Unknown_join_type_is_probe_failed()
    {
        // Spec §2.2 edge case 4.
        Assert.Equal(
            WindowsJoinStateProbe.EntraSignal.ProbeFailed,
            WindowsJoinStateProbe.ClassifyAadJoinResult(
                S_OK, WindowsJoinStateProbe.DSREG_JOIN_TYPE.DSREG_UNKNOWN_JOIN));
    }

    [Fact]
    public void Unrecognized_join_type_is_no_signal()
    {
        // Forward-compatible: a new DSREG_JOIN_TYPE value must not brick
        // the host into Unknown.
        Assert.Equal(
            WindowsJoinStateProbe.EntraSignal.None,
            WindowsJoinStateProbe.ClassifyAadJoinResult(
                S_OK, (WindowsJoinStateProbe.DSREG_JOIN_TYPE)99));
    }
}
