// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.HostState;

/// <summary>
/// Five-state classification of the Windows host's directory join.
///
/// Numeric values are explicit and must match the native
/// <c>JoinState</c> enum in <c>DdsAuthBridge/JoinState.h</c>.
/// Do not rely on implicit ordering — these values cross IPC and
/// persisted-state boundaries.
///
/// See <c>docs/windows-ad-coexistence-spec.md §2</c> for the
/// classification contract.
/// </summary>
public enum JoinState
{
    Workgroup = 0,
    AdJoined = 1,
    HybridJoined = 2,
    EntraOnlyJoined = 3,
    Unknown = 4,
}
