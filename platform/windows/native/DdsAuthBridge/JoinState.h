// JoinState.h
// Five-state classification of the Windows host's directory join.
//
// Numeric values must match the managed
// DDS.PolicyAgent.HostState.JoinState enum
// (DdsPolicyAgent/HostState/JoinState.cs). The contract is in
// docs/windows-ad-coexistence-spec.md §2.

#pragma once

#include <cstdint>
#include <windows.h>

namespace dds {

enum class JoinState : uint32_t
{
    Workgroup       = 0,
    AdJoined        = 1,
    HybridJoined    = 2,
    EntraOnlyJoined = 3,
    Unknown         = 4,
};

// Human-readable name for logs / diagnostics.
const wchar_t* JoinStateName(JoinState state);

// Run a fresh probe (no caching). Used by GetCachedJoinState() the
// first time and by RefreshJoinState() to invalidate the cache.
JoinState DetectJoinState();

// Return the cached JoinState. Probes once on first call; subsequent
// calls are O(1) until RefreshJoinState() is invoked.
JoinState GetCachedJoinState();

// Drop the cached value. The next GetCachedJoinState() call probes
// fresh. Used by the periodic refresh path (wired in AD-04) and by
// tests that need to re-probe between cases.
void RefreshJoinState();

#ifdef DDS_TESTING
// Test seam — overrides the cache with a fixed value. Compiled in
// only under -DDDS_TESTING so production binaries cannot be coerced
// into a wrong join classification.
void SetJoinStateForTest(JoinState state);
#endif

} // namespace dds
