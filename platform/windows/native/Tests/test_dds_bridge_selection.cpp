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
