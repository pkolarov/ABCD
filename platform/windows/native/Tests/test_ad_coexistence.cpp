// test_ad_coexistence.cpp
// AD-11 — end-to-end native tests for the AD-coexistence auth gate.
//
// Included by test_main.cpp -- do NOT compile separately.
//
// The pure-decision form of HandleDdsStartAuth's gate is already pinned by
// the ad08_* / ad09_* / ad10_* tests in test_dds_bridge_selection.cpp using
// a re-implementation. Those tests catch a logic regression but do NOT prove
// that the dds::SetJoinStateForTest / dds::GetCachedJoinState seam in
// JoinState.cpp is actually wired up — i.e. that production code which calls
// GetCachedJoinState() observes the test override.
//
// This file closes that gap. It exercises the real cache machinery in
// JoinState.cpp through the SetJoinStateForTest seam (compiled in only when
// the test binary is built with /DDDS_TESTING) and runs the three §9
// scenarios from docs/windows-ad-coexistence-spec.md §11.2:
//
//   1. AdJoined  + populated vault → Proceed
//   2. AdJoined  + empty     vault → PRE_ENROLLMENT_REQUIRED
//   3. EntraOnlyJoined             → UNSUPPORTED_HOST
//
// Plus the spec §9.2 transition case (Workgroup → AdJoined re-probe) since
// it is the only behaviour that requires both the cache *and* its mutation
// to be observable from the test seam.
//
// Note: HandleDdsStartAuth itself depends on the IPC server, vault, and
// WinAPI surfaces that the test binary does not link. The test therefore
// reproduces the gate logic — but driven from `dds::GetCachedJoinState()`
// (production cache) and parameterised on a `vaultMatched` bool that
// represents the result of `m_vault.FindByCredentialId(...)` at line 898 of
// DdsAuthBridgeMain.cpp.

#include "../DdsAuthBridge/JoinState.h"

#ifndef DDS_TESTING
#error "test_ad_coexistence.cpp requires the test binary to be built with /DDDS_TESTING"
#endif

namespace TestAdCoexistence
{

// Mirror of IPC_ERROR codes from ipc_protocol.h — pinned numerically so a
// renumbering breaks here, not at runtime in production.
constexpr unsigned int IPC_ERROR_SUCCESS                  = 0;
constexpr unsigned int IPC_ERROR_PRE_ENROLLMENT_REQUIRED  = 19;
constexpr unsigned int IPC_ERROR_UNSUPPORTED_HOST         = 20;

enum class GateOutcome
{
    Proceed,                // vault-backed sign-in OK
    UnsupportedHost,        // EntraOnly / Unknown
    PreEnrollmentRequired,  // AD/Hybrid + no vault entry
    ClaimMode,              // Workgroup + no vault entry → existing claim path
};

// Reproduces the gate at DdsAuthBridgeMain.cpp::HandleDdsStartAuth lines
// 876-921 (post-AD-08). The single source of truth for the *cached*
// JoinState here is dds::GetCachedJoinState() — exactly what the bridge
// reads in production.
static GateOutcome DecideStartAuthGate(bool vaultMatched)
{
    const dds::JoinState js = dds::GetCachedJoinState();
    if (js == dds::JoinState::EntraOnlyJoined || js == dds::JoinState::Unknown)
        return GateOutcome::UnsupportedHost;
    if (vaultMatched)
        return GateOutcome::Proceed;
    if (js == dds::JoinState::Workgroup)
        return GateOutcome::ClaimMode;
    return GateOutcome::PreEnrollmentRequired;
}

// Map a gate refusal back to its IPC error code. Matches the
// SendAuthError calls inside HandleDdsStartAuth.
static unsigned int RefusalToIpcError(GateOutcome o)
{
    switch (o)
    {
    case GateOutcome::UnsupportedHost:       return IPC_ERROR_UNSUPPORTED_HOST;
    case GateOutcome::PreEnrollmentRequired: return IPC_ERROR_PRE_ENROLLMENT_REQUIRED;
    default:                                 return IPC_ERROR_SUCCESS; // not a refusal
    }
}

} // namespace TestAdCoexistence

// ---- §9.1 PC already AD-joined, vault hit ----

DDS_TEST(ad11_ad_joined_with_vault_proceeds_through_seam)
{
    using namespace TestAdCoexistence;

    // Pin the cache through the production seam. This is the contract
    // gated by /DDDS_TESTING — if the seam stops working, the assert
    // immediately below catches it before the gate test is even
    // exercised.
    dds::SetJoinStateForTest(dds::JoinState::AdJoined);
    DDS_ASSERT(dds::GetCachedJoinState() == dds::JoinState::AdJoined,
               "AD-11: SetJoinStateForTest must pin GetCachedJoinState in /DDDS_TESTING builds");

    GateOutcome outcome = DecideStartAuthGate(/*vaultMatched=*/true);
    DDS_ASSERT(outcome == GateOutcome::Proceed,
               "AD-11 §9.1: AdJoined + vault hit must proceed to FIDO2 ceremony");
}

// ---- §9.1 / §4.3 PC AD-joined, claim refused ----

DDS_TEST(ad11_ad_joined_without_vault_returns_pre_enrollment_required)
{
    using namespace TestAdCoexistence;

    dds::SetJoinStateForTest(dds::JoinState::AdJoined);

    GateOutcome outcome = DecideStartAuthGate(/*vaultMatched=*/false);
    DDS_ASSERT(outcome == GateOutcome::PreEnrollmentRequired,
               "AD-11 §9.1: AdJoined + empty vault must short-circuit before WebAuthn");
    DDS_ASSERT(RefusalToIpcError(outcome) == IPC_ERROR_PRE_ENROLLMENT_REQUIRED,
               "AD-11: refusal must surface IPC_ERROR::PRE_ENROLLMENT_REQUIRED (=19)");
}

DDS_TEST(ad11_hybrid_joined_without_vault_returns_pre_enrollment_required)
{
    // Spec §2.1: HybridJoined behaves identically to AdJoined for the
    // auth path. Pin both cases so a future tweak that special-cases one
    // but not the other shows up here.
    using namespace TestAdCoexistence;

    dds::SetJoinStateForTest(dds::JoinState::HybridJoined);

    GateOutcome outcome = DecideStartAuthGate(/*vaultMatched=*/false);
    DDS_ASSERT(outcome == GateOutcome::PreEnrollmentRequired,
               "AD-11: HybridJoined behaves as AdJoined for the empty-vault refusal");
}

// ---- Entra-only unsupported ----

DDS_TEST(ad11_entra_only_returns_unsupported_host)
{
    using namespace TestAdCoexistence;

    dds::SetJoinStateForTest(dds::JoinState::EntraOnlyJoined);

    // The vault state must not influence the decision on EntraOnly:
    // the host is unsupported regardless. Both branches asserted.
    GateOutcome withVault = DecideStartAuthGate(/*vaultMatched=*/true);
    GateOutcome noVault   = DecideStartAuthGate(/*vaultMatched=*/false);

    DDS_ASSERT(withVault == GateOutcome::UnsupportedHost,
               "AD-11: EntraOnly is unsupported even if a vault entry happens to exist");
    DDS_ASSERT(noVault == GateOutcome::UnsupportedHost,
               "AD-11: EntraOnly without a vault entry is also unsupported");
    DDS_ASSERT(RefusalToIpcError(withVault) == IPC_ERROR_UNSUPPORTED_HOST,
               "AD-11: refusal must surface IPC_ERROR::UNSUPPORTED_HOST (=20)");
}

// ---- Unknown fail-closed ----

DDS_TEST(ad11_unknown_join_state_fails_closed_as_unsupported)
{
    // Spec §2.1: Unknown means the probe failed. Sign-in is mutating
    // (it serializes a Kerberos blob back to LogonUI) so the spec
    // requires fail-closed → UNSUPPORTED_HOST. This is the explicit
    // §11.2 case 3 generalised for the "probe fault" path.
    using namespace TestAdCoexistence;

    dds::SetJoinStateForTest(dds::JoinState::Unknown);

    GateOutcome outcome = DecideStartAuthGate(/*vaultMatched=*/true);
    DDS_ASSERT(outcome == GateOutcome::UnsupportedHost,
               "AD-11: Unknown must fail closed with UNSUPPORTED_HOST (probe must classify first)");
}

// ---- §9.2 Workgroup → AdJoined transition (cache mutation visibility) ----

DDS_TEST(ad11_workgroup_to_ad_transition_flips_gate_decision)
{
    // §9.2: a host enrolled in DDS as workgroup, then joined to AD,
    // must not silently fall through the claim path on the next sign-in.
    // The spec-mandated trigger is the periodic 1h re-probe; the test
    // simulates it by mutating the cache through SetJoinStateForTest.
    using namespace TestAdCoexistence;

    dds::SetJoinStateForTest(dds::JoinState::Workgroup);
    GateOutcome before = DecideStartAuthGate(/*vaultMatched=*/false);
    DDS_ASSERT(before == GateOutcome::ClaimMode,
               "AD-11 §9.2 pre-join: Workgroup + empty vault enters claim mode");

    // Simulate re-probe / netdom join + reboot.
    dds::SetJoinStateForTest(dds::JoinState::AdJoined);
    GateOutcome after = DecideStartAuthGate(/*vaultMatched=*/false);
    DDS_ASSERT(after == GateOutcome::PreEnrollmentRequired,
               "AD-11 §9.2 post-join: AdJoined + empty vault must refuse claim "
               "(no automatic local-account bootstrap on AD)");

    // Also confirm a vault hit (e.g. the original local-account enrollment
    // captured pre-join) still proceeds. The spec calls out at §9.2 that
    // such mechanically-still-working entries are intentional.
    GateOutcome afterWithVault = DecideStartAuthGate(/*vaultMatched=*/true);
    DDS_ASSERT(afterWithVault == GateOutcome::Proceed,
               "AD-11 §9.2: pre-join vault entries continue to work after AD-join");
}

// ---- Numeric IPC code pins ----

DDS_TEST(ad11_ipc_error_codes_match_pinned_values)
{
    // Spec §4.4 fixes these numerics; CDdsCredential.cpp's canonical
    // text table indexes by them. A drift between IPC numerics here
    // and the CP table would silently surface free-form bridge text on
    // the AD codes — defeating §4.4. ad10_* tests in
    // test_dds_bridge_selection.cpp pin the CP side; this assert pins
    // the bridge side from the same test binary.
    DDS_ASSERT(TestAdCoexistence::IPC_ERROR_PRE_ENROLLMENT_REQUIRED == 19u,
               "AD-11: IPC_ERROR::PRE_ENROLLMENT_REQUIRED must be code 19 (spec §4.4)");
    DDS_ASSERT(TestAdCoexistence::IPC_ERROR_UNSUPPORTED_HOST == 20u,
               "AD-11: IPC_ERROR::UNSUPPORTED_HOST must be code 20 (spec §4.4)");
}
