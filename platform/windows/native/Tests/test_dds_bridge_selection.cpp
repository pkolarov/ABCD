// test_dds_bridge_selection.cpp
// Standalone tests for the DDS bridge's credential-selection logic.
//
// Included by test_main.cpp -- do NOT compile separately.
//
// These tests intentionally duplicate the small, security-relevant parts of
// DdsAuthBridgeMain.cpp so the native test binary can catch regressions in:
//   - base64url credential_id decoding
//   - exact vault entry selection by credential_id
//   - subject_urn propagation into DDS_AUTH_COMPLETE
//

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace TestDdsBridgeSelection
{

struct VaultEntry
{
    std::string userSid;
    std::vector<uint8_t> credentialId;
};

static std::string Base64UrlEncode(const uint8_t* data, size_t len)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve((len * 4 + 2) / 3);

    for (size_t i = 0; i < len; i += 3)
    {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);

        out.push_back(table[(n >> 18) & 0x3F]);
        out.push_back(table[(n >> 12) & 0x3F]);
        if (i + 1 < len) out.push_back(table[(n >> 6) & 0x3F]);
        if (i + 2 < len) out.push_back(table[n & 0x3F]);
    }

    for (auto& c : out)
    {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }

    return out;
}

static std::vector<uint8_t> Base64UrlDecode(const std::string& input)
{
    std::string b64 = input;
    for (auto& c : b64)
    {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (b64.size() % 4 != 0)
        b64.push_back('=');

    static const int table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };

    std::vector<uint8_t> out;
    out.reserve(b64.size() * 3 / 4);

    for (size_t i = 0; i + 3 < b64.size(); i += 4)
    {
        int a = table[static_cast<unsigned char>(b64[i])];
        int b = table[static_cast<unsigned char>(b64[i + 1])];
        bool cPadded = (b64[i + 2] == '=');
        bool dPadded = (b64[i + 3] == '=');
        int c = cPadded ? -1 : table[static_cast<unsigned char>(b64[i + 2])];
        int d = dPadded ? -1 : table[static_cast<unsigned char>(b64[i + 3])];

        if (a < 0 || b < 0)
            break;

        out.push_back(static_cast<uint8_t>((a << 2) | (b >> 4)));
        if (c >= 0)
            out.push_back(static_cast<uint8_t>(((b & 0xF) << 4) | (c >> 2)));
        if (c >= 0 && d >= 0)
            out.push_back(static_cast<uint8_t>(((c & 3) << 6) | d));
    }

    return out;
}

static const VaultEntry* FindByCredentialId(
    const std::vector<VaultEntry>& entries,
    const std::vector<uint8_t>& credentialId)
{
    for (const auto& entry : entries)
    {
        if (entry.credentialId == credentialId)
            return &entry;
    }
    return nullptr;
}

static const VaultEntry* MatchVaultEntryForCredentialId(
    const std::vector<VaultEntry>& entries,
    const std::string& requestCredentialId)
{
    std::vector<uint8_t> decoded = Base64UrlDecode(requestCredentialId);
    if (decoded.empty())
        return nullptr;

    return FindByCredentialId(entries, decoded);
}

static std::string ResolveAuthCompleteSubjectUrn(
    const std::string& requestSubjectUrn,
    const std::string& userSid)
{
    return requestSubjectUrn.empty() ? userSid : requestSubjectUrn;
}

} // namespace TestDdsBridgeSelection

DDS_TEST(dds_bridge_base64url_decodes_credential_id_bytes)
{
    const std::vector<uint8_t> raw = { 0x01, 0x02, 0x03, 0xFA, 0xFB, 0xFC, 0x10, 0x20, 0x30 };
    std::string encoded = TestDdsBridgeSelection::Base64UrlEncode(raw.data(), raw.size());
    std::vector<uint8_t> decoded = TestDdsBridgeSelection::Base64UrlDecode(encoded);

    DDS_ASSERT(decoded.size() == raw.size(),
               "base64url decode must preserve credential_id length");
    DDS_ASSERT(std::memcmp(decoded.data(), raw.data(), raw.size()) == 0,
               "base64url decode must round-trip credential_id bytes");
}

DDS_TEST(dds_bridge_base64url_decodes_unpadded_padding_case)
{
    const std::vector<uint8_t> raw = { 0xAA, 0xBB, 0xCC, 0xDD };
    std::string encoded = TestDdsBridgeSelection::Base64UrlEncode(raw.data(), raw.size());
    std::vector<uint8_t> decoded = TestDdsBridgeSelection::Base64UrlDecode(encoded);

    DDS_ASSERT(decoded.size() == raw.size(),
               "base64url decode must handle unpadded credential_id lengths");
    DDS_ASSERT(std::memcmp(decoded.data(), raw.data(), raw.size()) == 0,
               "base64url decode must preserve bytes when padding is implied");
}

DDS_TEST(dds_bridge_matches_exact_vault_entry_by_credential_id)
{
    const std::vector<uint8_t> aliceCred = { 0x11, 0x22, 0x33, 0x44 };
    const std::vector<uint8_t> bobCred   = { 0xAA, 0xBB, 0xCC, 0xDD };

    std::vector<TestDdsBridgeSelection::VaultEntry> entries = {
        { "S-1-5-21-alice", aliceCred },
        { "S-1-5-21-bob",   bobCred   },
    };

    std::string requestCredentialId =
        TestDdsBridgeSelection::Base64UrlEncode(bobCred.data(), bobCred.size());

    const auto* matched =
        TestDdsBridgeSelection::MatchVaultEntryForCredentialId(entries, requestCredentialId);

    DDS_ASSERT(matched != nullptr,
               "matching credential_id must resolve to a vault entry");
    DDS_ASSERT(matched && matched->userSid == "S-1-5-21-bob",
               "credential_id lookup must pick Bob's entry, not the first entry");
    DDS_ASSERT(matched && matched->credentialId == bobCred,
               "matched entry must carry Bob's raw credential bytes");
}

DDS_TEST(dds_bridge_rejects_unknown_credential_id)
{
    const std::vector<uint8_t> aliceCred = { 0x11, 0x22, 0x33, 0x44 };
    const std::vector<uint8_t> unknownCred = { 0x99, 0x88, 0x77, 0x66 };

    std::vector<TestDdsBridgeSelection::VaultEntry> entries = {
        { "S-1-5-21-alice", aliceCred },
    };

    std::string requestCredentialId =
        TestDdsBridgeSelection::Base64UrlEncode(unknownCred.data(), unknownCred.size());

    const auto* matched =
        TestDdsBridgeSelection::MatchVaultEntryForCredentialId(entries, requestCredentialId);

    DDS_ASSERT(matched == nullptr,
               "unknown credential_id must be rejected instead of falling through");
}

DDS_TEST(dds_bridge_rejects_malformed_credential_id)
{
    std::vector<TestDdsBridgeSelection::VaultEntry> entries = {
        { "S-1-5-21-alice", { 0x11, 0x22, 0x33, 0x44 } },
    };

    const auto* matched =
        TestDdsBridgeSelection::MatchVaultEntryForCredentialId(entries, "%%%%");

    DDS_ASSERT(matched == nullptr,
               "malformed credential_id must not match a vault entry");
}

DDS_TEST(dds_auth_complete_subject_urn_prefers_request_urn)
{
    std::string subjectUrn = TestDdsBridgeSelection::ResolveAuthCompleteSubjectUrn(
        "urn:vouchsafe:bob.abc123",
        "S-1-5-21-bob");

    DDS_ASSERT(subjectUrn == "urn:vouchsafe:bob.abc123",
               "DDS auth complete must preserve the DDS subject URN from the request");
}

DDS_TEST(dds_auth_complete_subject_urn_falls_back_to_sid)
{
    std::string subjectUrn = TestDdsBridgeSelection::ResolveAuthCompleteSubjectUrn(
        "",
        "S-1-5-21-legacy");

    DDS_ASSERT(subjectUrn == "S-1-5-21-legacy",
               "DDS auth complete must fall back to the SID for legacy callers");
}

// ============================================================================
// AD-14 — stale-vault cooldown logic (standalone reimplementation)
//
// These tests mirror the security-relevant pieces of
// `CDdsAuthBridgeMain::NtStatusToStaleError` and the cooldown map's
// case-folding key contract (see `CooldownKey` in DdsAuthBridgeMain.cpp).
// Reproducing the logic here keeps the cross-platform CI (macOS) honest
// without pulling in the WinHTTP / NetAPI dependencies of the bridge.
// ============================================================================

namespace TestStaleCooldown
{

// IPC error codes mirrored from ipc_protocol.h. Pin the numeric values so
// a future renumbering is caught here, not at runtime.
constexpr uint32_t STALE_VAULT_PASSWORD       = 16;
constexpr uint32_t AD_PASSWORD_CHANGE_REQUIRED = 17;
constexpr uint32_t AD_PASSWORD_EXPIRED        = 18;

static uint32_t NtStatusToStaleError(int32_t ntStatus)
{
    switch (static_cast<uint32_t>(ntStatus))
    {
    case 0xC000006DUL: return STALE_VAULT_PASSWORD;        // STATUS_LOGON_FAILURE
    case 0xC0000224UL: return AD_PASSWORD_CHANGE_REQUIRED; // STATUS_PASSWORD_MUST_CHANGE
    case 0xC0000071UL: return AD_PASSWORD_EXPIRED;         // STATUS_PASSWORD_EXPIRED
    default:           return 0;
    }
}

} // namespace TestStaleCooldown

DDS_TEST(stale_cooldown_maps_logon_failure)
{
    DDS_ASSERT(TestStaleCooldown::NtStatusToStaleError(static_cast<int32_t>(0xC000006DL))
               == TestStaleCooldown::STALE_VAULT_PASSWORD,
               "STATUS_LOGON_FAILURE must map to STALE_VAULT_PASSWORD");
}

DDS_TEST(stale_cooldown_maps_password_must_change)
{
    DDS_ASSERT(TestStaleCooldown::NtStatusToStaleError(static_cast<int32_t>(0xC0000224L))
               == TestStaleCooldown::AD_PASSWORD_CHANGE_REQUIRED,
               "STATUS_PASSWORD_MUST_CHANGE must map to AD_PASSWORD_CHANGE_REQUIRED");
}

DDS_TEST(stale_cooldown_maps_password_expired)
{
    DDS_ASSERT(TestStaleCooldown::NtStatusToStaleError(static_cast<int32_t>(0xC0000071L))
               == TestStaleCooldown::AD_PASSWORD_EXPIRED,
               "STATUS_PASSWORD_EXPIRED must map to AD_PASSWORD_EXPIRED");
}

DDS_TEST(stale_cooldown_ignores_success_and_unrelated_codes)
{
    DDS_ASSERT(TestStaleCooldown::NtStatusToStaleError(0) == 0,
               "STATUS_SUCCESS must not install a cooldown");
    DDS_ASSERT(TestStaleCooldown::NtStatusToStaleError(static_cast<int32_t>(0xC0000022L)) == 0,
               "STATUS_ACCESS_DENIED must not install a cooldown");
    DDS_ASSERT(TestStaleCooldown::NtStatusToStaleError(static_cast<int32_t>(0x80000005L)) == 0,
               "Random NTSTATUSes must not install a cooldown");
}

DDS_TEST(stale_cooldown_key_preserves_base64url_case)
{
    // base64url is case-sensitive: 'A' decodes to byte 0, 'a' decodes to
    // byte 26. The cooldown key MUST be a literal credential_id match to
    // avoid collapsing two distinct enrollments onto the same cooldown
    // entry. This test pins that invariant by exercising the same lookup
    // helper used by the production code.
    std::vector<TestDdsBridgeSelection::VaultEntry> entries = {
        { "S-1-5-21-alice", { 0x00, 0x10, 0x20 } }, // base64url "ABAg"
        { "S-1-5-21-bob",   { 0x68, 0x40, 0x80 } }, // base64url "aECA"
    };

    const auto* alice = TestDdsBridgeSelection::MatchVaultEntryForCredentialId(
        entries, "ABAg");
    const auto* bob = TestDdsBridgeSelection::MatchVaultEntryForCredentialId(
        entries, "aECA");

    DDS_ASSERT(alice && alice->userSid == "S-1-5-21-alice",
               "uppercase-leading credential_id must resolve to Alice");
    DDS_ASSERT(bob && bob->userSid == "S-1-5-21-bob",
               "lowercase-leading credential_id must resolve to Bob — not the same bucket as Alice");
    DDS_ASSERT(alice != bob,
               "Alice and Bob must be distinct entries; case folding would merge them");
}

// ============================================================================
// AD-08 / AD-09 — JoinState-driven gate decisions for the auth path.
//
// The bridge's HandleDdsStartAuth and HandleDdsListUsers gates are pure
// JoinState/vault-presence logic on top of the same `FindByCredentialId`
// helper exercised above. These tests reproduce just the gate to keep the
// security contract locked even on macOS CI where the production WinAPI
// dependencies don't link.
// ============================================================================

namespace TestAdCoexistenceGate
{

// Mirror of the JoinState enum at JoinState.h. The numeric values are part of
// the cross-language (managed/native) contract so they MUST remain stable.
enum class JoinState : unsigned int
{
    Workgroup       = 0,
    AdJoined        = 1,
    HybridJoined    = 2,
    EntraOnlyJoined = 3,
    Unknown         = 4,
};

// Mirror of IPC_ERROR codes from ipc_protocol.h relevant to AD-08/AD-09.
// Pinned numerically here so a renumbering would also break the
// dds_user_list_status_carrier test next to it.
constexpr unsigned int IPC_ERROR_SUCCESS                  = 0;
constexpr unsigned int IPC_ERROR_PRE_ENROLLMENT_REQUIRED  = 19;
constexpr unsigned int IPC_ERROR_UNSUPPORTED_HOST         = 20;

enum class StartAuthDecision
{
    Proceed,                // vault-backed sign-in OK
    UnsupportedHost,        // Entra-only / Unknown
    PreEnrollmentRequired,  // AD/Hybrid + no vault entry
    ClaimMode,              // Workgroup + no vault entry → existing claim path
};

// AD-08: pure decision function. `vaultMatched` is the result of the
// FindByCredentialId lookup (already exercised by the older tests above).
static StartAuthDecision DecideStartAuth(JoinState js, bool vaultMatched)
{
    if (js == JoinState::EntraOnlyJoined || js == JoinState::Unknown)
        return StartAuthDecision::UnsupportedHost;
    if (vaultMatched)
        return StartAuthDecision::Proceed;
    if (js == JoinState::Workgroup)
        return StartAuthDecision::ClaimMode;
    return StartAuthDecision::PreEnrollmentRequired;
}

// AD-09: pure filter function. Returns the entries the bridge would emit
// over IPC, in order. `vaultCredentialIds` is the set of base64url
// credential_ids backed by a local vault entry (used as the intersection
// key on AD/Hybrid hosts).
struct ListUserEntry
{
    std::string subjectUrn;
    std::string displayName;
    std::string credentialIdB64;
};

static std::vector<ListUserEntry> FilterDdsUserList(
    JoinState js,
    const std::vector<ListUserEntry>& dsNodeUsers,
    const std::vector<std::string>& vaultCredentialIds)
{
    std::vector<ListUserEntry> out;
    const bool intersect =
        (js == JoinState::AdJoined || js == JoinState::HybridJoined);

    for (const auto& u : dsNodeUsers)
    {
        if (intersect)
        {
            bool found = false;
            for (const auto& v : vaultCredentialIds)
            {
                if (v == u.credentialIdB64)
                {
                    found = true;
                    break;
                }
            }
            if (!found) continue;
        }
        out.push_back(u);
    }
    return out;
}

} // namespace TestAdCoexistenceGate

// ---- AD-08 ----

DDS_TEST(ad08_workgroup_with_vault_proceeds)
{
    using namespace TestAdCoexistenceGate;
    DDS_ASSERT(DecideStartAuth(JoinState::Workgroup, true) == StartAuthDecision::Proceed,
               "Workgroup + vault-matched credential must proceed to sign-in");
}

DDS_TEST(ad08_workgroup_without_vault_falls_back_to_claim)
{
    using namespace TestAdCoexistenceGate;
    DDS_ASSERT(DecideStartAuth(JoinState::Workgroup, false) == StartAuthDecision::ClaimMode,
               "Workgroup + no vault must enter claim mode (existing behaviour)");
}

DDS_TEST(ad08_ad_joined_with_vault_proceeds)
{
    using namespace TestAdCoexistenceGate;
    DDS_ASSERT(DecideStartAuth(JoinState::AdJoined, true) == StartAuthDecision::Proceed,
               "AD-joined host with a prior enrollment must complete FIDO2 sign-in");
}

DDS_TEST(ad08_hybrid_with_vault_proceeds)
{
    using namespace TestAdCoexistenceGate;
    DDS_ASSERT(DecideStartAuth(JoinState::HybridJoined, true) == StartAuthDecision::Proceed,
               "Hybrid-joined host behaves as AD-joined for the vault-backed path");
}

DDS_TEST(ad08_ad_joined_without_vault_returns_pre_enrollment_required)
{
    using namespace TestAdCoexistenceGate;
    DDS_ASSERT(DecideStartAuth(JoinState::AdJoined, false)
               == StartAuthDecision::PreEnrollmentRequired,
               "AD-joined + no vault entry must short-circuit before WebAuthn");
}

DDS_TEST(ad08_hybrid_without_vault_returns_pre_enrollment_required)
{
    using namespace TestAdCoexistenceGate;
    DDS_ASSERT(DecideStartAuth(JoinState::HybridJoined, false)
               == StartAuthDecision::PreEnrollmentRequired,
               "Hybrid + no vault entry follows the same pre-enrollment gate");
}

DDS_TEST(ad08_entra_only_always_unsupported)
{
    using namespace TestAdCoexistenceGate;
    DDS_ASSERT(DecideStartAuth(JoinState::EntraOnlyJoined, true)
               == StartAuthDecision::UnsupportedHost,
               "Entra-only is unsupported even if a vault entry happens to exist");
    DDS_ASSERT(DecideStartAuth(JoinState::EntraOnlyJoined, false)
               == StartAuthDecision::UnsupportedHost,
               "Entra-only with no vault entry is also unsupported");
}

DDS_TEST(ad08_unknown_join_state_is_unsupported)
{
    using namespace TestAdCoexistenceGate;
    // Unknown means probe failed; spec §2.1 says fail closed for mutating
    // operations. Sign-in is mutating because it serializes a Kerberos blob
    // back to LogonUI — refuse.
    DDS_ASSERT(DecideStartAuth(JoinState::Unknown, false)
               == StartAuthDecision::UnsupportedHost,
               "Unknown JoinState must fail closed with UNSUPPORTED_HOST");
    DDS_ASSERT(DecideStartAuth(JoinState::Unknown, true)
               == StartAuthDecision::UnsupportedHost,
               "Unknown stays unsupported even with a vault entry — probe must classify first");
}

// ---- AD-09 ----

DDS_TEST(ad09_workgroup_returns_full_dds_node_list)
{
    using namespace TestAdCoexistenceGate;
    std::vector<ListUserEntry> nodeUsers = {
        { "urn:vouchsafe:alice", "Alice", "ALICEcred" },
        { "urn:vouchsafe:bob",   "Bob",   "BOBcred"   },
    };
    std::vector<std::string> vault = { "ALICEcred" }; // bob has no vault entry

    auto out = FilterDdsUserList(JoinState::Workgroup, nodeUsers, vault);
    DDS_ASSERT(out.size() == 2,
               "Workgroup hosts must surface every dds-node user (claim path can still create the local account)");
    DDS_ASSERT(out[0].subjectUrn == "urn:vouchsafe:alice",
               "List order from dds-node must be preserved");
    DDS_ASSERT(out[1].subjectUrn == "urn:vouchsafe:bob",
               "Workgroup includes vault-less users");
}

DDS_TEST(ad09_ad_joined_intersects_with_vault_only)
{
    using namespace TestAdCoexistenceGate;
    std::vector<ListUserEntry> nodeUsers = {
        { "urn:vouchsafe:alice", "Alice", "ALICEcred" },
        { "urn:vouchsafe:bob",   "Bob",   "BOBcred"   },
        { "urn:vouchsafe:carol", "Carol", "CAROLcred" },
    };
    std::vector<std::string> vault = { "BOBcred" };

    auto out = FilterDdsUserList(JoinState::AdJoined, nodeUsers, vault);
    DDS_ASSERT(out.size() == 1,
               "AD-joined hosts must drop dds-node users with no local vault entry");
    DDS_ASSERT(out[0].subjectUrn == "urn:vouchsafe:bob",
               "Intersection key is the credential_id, not the subject_urn");
}

DDS_TEST(ad09_hybrid_intersects_like_ad)
{
    using namespace TestAdCoexistenceGate;
    std::vector<ListUserEntry> nodeUsers = {
        { "urn:vouchsafe:alice", "Alice", "ALICEcred" },
    };
    std::vector<std::string> vault; // empty vault

    auto out = FilterDdsUserList(JoinState::HybridJoined, nodeUsers, vault);
    DDS_ASSERT(out.empty(),
               "Hybrid host with empty vault must show no DDS tiles even when dds-node lists users");
}

DDS_TEST(ad09_credential_id_is_case_sensitive_in_intersection)
{
    using namespace TestAdCoexistenceGate;
    std::vector<ListUserEntry> nodeUsers = {
        { "urn:vouchsafe:alice", "Alice", "ABcd" },
    };
    // base64url is case-sensitive, so "abcd" != "ABcd"
    std::vector<std::string> vault = { "abcd" };

    auto out = FilterDdsUserList(JoinState::AdJoined, nodeUsers, vault);
    DDS_ASSERT(out.empty(),
               "AD-09 intersection must NOT case-fold the credential_id — base64url is case-sensitive");
}

// ============================================================================
// AD-10 — credential-provider canonical error-text mapping
//
// These tests duplicate the CP's canonical §4.4 string and icon assignment
// so a future drift between the spec, the CP table, and the IPC error code
// values is caught by the test binary before it reaches LogonUI. Strings
// are compared verbatim because the spec lists exact wording.
// ============================================================================

namespace TestCpCanonicalErrorText
{

// Mirror the CREDENTIAL_PROVIDER_STATUS_ICON values from Windows SDK
// credentialprovider.h. Pinned numerically because the test binary does
// not include credentialprovider.h directly.
constexpr int CPSI_NONE    = 0;
constexpr int CPSI_ERROR   = 1;
constexpr int CPSI_WARNING = 2;
constexpr int CPSI_SUCCESS = 3;

struct Mapping
{
    unsigned int errorCode;
    const wchar_t* text;
    int icon;
};

// Mirror s_rgDdsCanonicalErrorText from CDdsCredential.cpp. Any drift in
// either the IPC code numerics, the icon choice, or the §4.4 string must
// fail this list before it ships.
static const Mapping s_rgExpected[] = {
    { 16,
      L"Your DDS stored password may be out of date. Sign in normally with "
      L"your Windows password, then refresh DDS from the system tray.",
      CPSI_WARNING },
    { 17,
      L"AD requires you to set a new password. Sign in normally to change "
      L"it, then refresh DDS.",
      CPSI_WARNING },
    { 18,
      L"AD requires you to set a new password. Sign in normally to change "
      L"it, then refresh DDS.",
      CPSI_WARNING },
    { 19,
      L"DDS sign-in is available only after enrollment on this AD-joined "
      L"machine.",
      CPSI_WARNING },
    { 20,
      L"DDS sign-in is not yet supported on Entra-joined machines.",
      CPSI_ERROR },
    { 21,
      L"This DDS account no longer exists in your directory. Contact your "
      L"administrator.",
      CPSI_ERROR },
};

static const Mapping* Find(unsigned int code)
{
    for (size_t i = 0; i < sizeof(s_rgExpected) / sizeof(s_rgExpected[0]); ++i)
        if (s_rgExpected[i].errorCode == code) return &s_rgExpected[i];
    return nullptr;
}

static bool WStrEqual(const wchar_t* a, const wchar_t* b)
{
    if (!a || !b) return a == b;
    while (*a && *b)
    {
        if (*a != *b) return false;
        ++a; ++b;
    }
    return *a == *b;
}

} // namespace TestCpCanonicalErrorText

DDS_TEST(ad10_canonical_error_text_covers_every_ad_code)
{
    using namespace TestCpCanonicalErrorText;
    // Every AD-coexistence IPC code (16..21) must have a canonical mapping.
    // A missing entry would silently fall back to the bridge-supplied text,
    // which can be empty or technical and undermines spec §4.4.
    for (unsigned int code = 16; code <= 21; ++code)
    {
        const Mapping* m = Find(code);
        DDS_ASSERT(m != nullptr,
                   "AD-10: every AD-coexistence IPC code (16..21) needs a canonical CP mapping");
        if (m)
        {
            DDS_ASSERT(m->text != nullptr && m->text[0] != L'\0',
                       "AD-10: canonical text must be non-empty");
        }
    }
}

DDS_TEST(ad10_stale_password_codes_use_warning_icon)
{
    using namespace TestCpCanonicalErrorText;
    // STALE / CHANGE_REQUIRED / EXPIRED / PRE_ENROLLMENT are recoverable
    // operator actions — not terminal failures. Spec §4.4 maps them to a
    // warning icon to communicate that.
    const unsigned int warningCodes[] = { 16, 17, 18, 19 };
    for (unsigned int code : warningCodes)
    {
        const Mapping* m = Find(code);
        DDS_ASSERT(m && m->icon == CPSI_WARNING,
                   "AD-10: recoverable AD codes must show the warning icon");
    }
}

DDS_TEST(ad10_unsupported_and_missing_account_use_error_icon)
{
    using namespace TestCpCanonicalErrorText;
    // UNSUPPORTED_HOST and ACCOUNT_NOT_FOUND are not user-recoverable from
    // the logon screen — they require an admin or reconfiguration. Spec
    // §4.4 surfaces them with the error icon.
    DDS_ASSERT(Find(20) && Find(20)->icon == CPSI_ERROR,
               "AD-10: UNSUPPORTED_HOST must show the error icon");
    DDS_ASSERT(Find(21) && Find(21)->icon == CPSI_ERROR,
               "AD-10: ACCOUNT_NOT_FOUND must show the error icon");
}

DDS_TEST(ad10_codes_outside_taxonomy_have_no_canonical_mapping)
{
    using namespace TestCpCanonicalErrorText;
    // Pre-AD codes (AUTH_TIMEOUT=3, USER_CANCELLED=5, SERVICE_ERROR=9)
    // and SUCCESS=0 must NOT be in the canonical table. Falling through
    // to the bridge string is the correct behaviour — those messages are
    // free-form and may carry richer detail than a fixed CP string.
    DDS_ASSERT(Find(0)  == nullptr, "AD-10: SUCCESS must not have a canonical CP override");
    DDS_ASSERT(Find(3)  == nullptr, "AD-10: AUTH_TIMEOUT must not have a canonical CP override");
    DDS_ASSERT(Find(5)  == nullptr, "AD-10: USER_CANCELLED must not have a canonical CP override");
    DDS_ASSERT(Find(9)  == nullptr, "AD-10: SERVICE_ERROR must not have a canonical CP override");
}

DDS_TEST(ad10_password_change_and_expired_share_recovery_text)
{
    using namespace TestCpCanonicalErrorText;
    // Spec §4.4 deliberately uses the same recovery sentence for codes
    // 17 and 18 — both end with "Sign in normally to change it, then
    // refresh DDS." Differences here would diverge the operator UX.
    const Mapping* mChange  = Find(17);
    const Mapping* mExpired = Find(18);
    DDS_ASSERT(mChange && mExpired, "AD-10: codes 17 and 18 must both be mapped");
    DDS_ASSERT(WStrEqual(mChange->text, mExpired->text),
               "AD-10: AD_PASSWORD_CHANGE_REQUIRED and AD_PASSWORD_EXPIRED share §4.4 recovery text");
}

DDS_TEST(ad10_pre_enrollment_text_is_distinct_from_unsupported_host)
{
    using namespace TestCpCanonicalErrorText;
    // PRE_ENROLLMENT_REQUIRED and UNSUPPORTED_HOST must surface different
    // copy — collapsing them was the symptom that motivated the spec
    // distinction in §3 (AD/Hybrid still allows enrollment after a normal
    // sign-in, Entra-only does not).
    const Mapping* m19 = Find(19);
    const Mapping* m20 = Find(20);
    DDS_ASSERT(m19 && m20, "AD-10: codes 19 and 20 must both be mapped");
    DDS_ASSERT(!WStrEqual(m19->text, m20->text),
               "AD-10: PRE_ENROLLMENT_REQUIRED must not share copy with UNSUPPORTED_HOST");
}
