// test_join_state.cpp
// Standalone tests for the dds::JoinState seam.
//
// Included by test_main.cpp -- do NOT compile separately.
//
// Phase 1 scope: enum-value invariants + opportunistic logging of
// the real probe on the test host. The probe's actual return value
// depends on host configuration so we log it for the developer's
// benefit but don't assert it (CI runs on workgroup boxes; the
// probe might return Workgroup, AdJoined, etc. depending on lab
// fixtures).

#include "../DdsAuthBridge/JoinState.h"

#include <cstdio>

DDS_TEST(JoinState_Numeric_Values_Are_Locked)
{
    // Cross-language stable contract — the managed enum in
    // DdsPolicyAgent/HostState/JoinState.cs uses the same numeric
    // values. Both must be updated together.
    DDS_ASSERT(static_cast<uint32_t>(dds::JoinState::Workgroup)       == 0u, "Workgroup == 0");
    DDS_ASSERT(static_cast<uint32_t>(dds::JoinState::AdJoined)        == 1u, "AdJoined == 1");
    DDS_ASSERT(static_cast<uint32_t>(dds::JoinState::HybridJoined)    == 2u, "HybridJoined == 2");
    DDS_ASSERT(static_cast<uint32_t>(dds::JoinState::EntraOnlyJoined) == 3u, "EntraOnlyJoined == 3");
    DDS_ASSERT(static_cast<uint32_t>(dds::JoinState::Unknown)         == 4u, "Unknown == 4");
}

DDS_TEST(JoinState_Name_Is_Defined_For_All)
{
    const dds::JoinState all[] = {
        dds::JoinState::Workgroup,
        dds::JoinState::AdJoined,
        dds::JoinState::HybridJoined,
        dds::JoinState::EntraOnlyJoined,
        dds::JoinState::Unknown,
    };
    for (auto s : all)
    {
        const wchar_t* name = dds::JoinStateName(s);
        DDS_ASSERT(name != nullptr, "JoinStateName returned nullptr");
        DDS_ASSERT(name[0] != L'\0', "JoinStateName returned empty string");
    }
}

DDS_TEST(JoinState_Probe_Runs_Without_Throwing)
{
    // The probe is allowed to return any of the five well-known
    // states. We exercise it once and log the result so a developer
    // running tests on their box can see the classification, but we
    // do not assert a specific value here — the spec covers that in
    // the integration / E2E layers.
    dds::JoinState s = dds::DetectJoinState();
    wprintf(L"  [info] DetectJoinState() => %s\n", dds::JoinStateName(s));

    // Either the value is one of the five known states, or the
    // contract is broken.
    bool known =
        s == dds::JoinState::Workgroup ||
        s == dds::JoinState::AdJoined ||
        s == dds::JoinState::HybridJoined ||
        s == dds::JoinState::EntraOnlyJoined ||
        s == dds::JoinState::Unknown;
    DDS_ASSERT(known, "DetectJoinState returned an out-of-enum value");
}

DDS_TEST(JoinState_Cached_Is_Stable_Across_Calls)
{
    dds::JoinState a = dds::GetCachedJoinState();
    dds::JoinState b = dds::GetCachedJoinState();
    DDS_ASSERT(a == b, "GetCachedJoinState returned inconsistent values");
}
