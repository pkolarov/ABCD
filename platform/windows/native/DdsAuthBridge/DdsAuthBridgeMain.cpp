// DdsAuthBridgeMain.cpp
// Main coordinator for the DDS Auth Bridge Service.
//
// Implements the DDS authentication flow:
//   CP request -> platform WebAuthn getAssertion -> POST to dds-node
//   -> hmac-secret -> vault decrypt -> credential
//
// Forked from Crayonic BridgeServiceMain.cpp with BLE removed and
// dds-node HTTP integration added.
//

#include "DdsAuthBridgeMain.h"
#include "EventLogger.h"
#include "FileLog.h"
#include <algorithm>
#include <ctime>
#include <string.h>
#include <lm.h>          // NetGetJoinInformation
#include <sddl.h>        // ConvertStringSidToSidW
#include <bcrypt.h>       // BCryptGenRandom for challenge
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

// Base64url encode (no padding) for dds-node JSON
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
    // Convert to base64url: '+' -> '-', '/' -> '_', strip '='
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
    for (auto& c : b64) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
    while (b64.size() % 4 != 0) b64.push_back('=');
    static const int T[256] = {
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
        int a = T[(unsigned char)b64[i]];
        int b = T[(unsigned char)b64[i+1]];
        bool cPadded = (b64[i + 2] == '=');
        bool dPadded = (b64[i + 3] == '=');
        int c = cPadded ? -1 : T[(unsigned char)b64[i+2]];
        int d = dPadded ? -1 : T[(unsigned char)b64[i+3]];
        if (a < 0 || b < 0) break;
        out.push_back((uint8_t)((a << 2) | (b >> 4)));
        if (c >= 0) out.push_back((uint8_t)(((b & 0xF) << 4) | (c >> 2)));
        if (c >= 0 && d >= 0) out.push_back((uint8_t)(((c & 3) << 6) | d));
    }
    return out;
}

static void SecureZeroWString(std::wstring& value)
{
    if (!value.empty())
        SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
    value.clear();
}

static bool Utf8ToWideString(const std::string& value, std::wstring& outWide)
{
    outWide.clear();
    int needed = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, NULL, 0);
    if (needed <= 0)
        return false;

    std::vector<WCHAR> buffer(static_cast<size_t>(needed));
    if (MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, buffer.data(), needed) <= 0)
        return false;

    outWide.assign(buffer.data());
    return true;
}

static bool GenerateClaimPassword(std::wstring& outPassword)
{
    // Guarantee complexity with a fixed prefix and random alnum suffix.
    static const wchar_t alphabet[] =
        L"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

    uint8_t randomBytes[20]{};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, randomBytes, sizeof(randomBytes),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    {
        return false;
    }

    outPassword = L"Aa1!";
    for (uint8_t b : randomBytes)
        outPassword.push_back(alphabet[b % (ARRAYSIZE(alphabet) - 1)]);
    return true;
}

static bool LocalUserExists(PCWSTR pszUsername)
{
    LPBYTE pBuf = nullptr;
    NET_API_STATUS status = NetUserGetInfo(NULL, pszUsername, 1, &pBuf);
    if (pBuf)
        NetApiBufferFree(pBuf);
    return status == NERR_Success;
}

static bool ResolveLocalUserSid(PCWSTR pszUsername, std::wstring& outSid, std::wstring& outError)
{
    DWORD sidSize = 0, domainSize = 0;
    SID_NAME_USE sidUse = SidTypeUnknown;
    LookupAccountNameW(NULL, pszUsername, NULL, &sidSize, NULL, &domainSize, &sidUse);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || sidSize == 0)
    {
        outError = L"Failed to resolve local account SID";
        return false;
    }

    std::vector<BYTE> sidBuf(sidSize);
    std::vector<WCHAR> domainBuf(domainSize ? domainSize : 1);
    if (!LookupAccountNameW(NULL, pszUsername, sidBuf.data(), &sidSize,
                            domainBuf.data(), &domainSize, &sidUse))
    {
        outError = L"LookupAccountNameW failed for claimed account";
        return false;
    }

    LPWSTR pSidText = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<PSID>(sidBuf.data()), &pSidText))
    {
        outError = L"ConvertSidToStringSidW failed for claimed account";
        return false;
    }

    outSid = pSidText;
    LocalFree(pSidText);
    return true;
}

static bool ApplyLocalGroups(PCWSTR pszUsername, const std::vector<std::string>& groups, std::wstring& outError)
{
    for (const auto& groupUtf8 : groups)
    {
        if (groupUtf8.empty())
            continue;

        std::wstring groupName;
        if (!Utf8ToWideString(groupUtf8, groupName))
        {
            outError = L"Invalid UTF-8 group name in claim response";
            return false;
        }

        LOCALGROUP_MEMBERS_INFO_3 member = {};
        member.lgrmi3_domainandname = const_cast<LPWSTR>(pszUsername);
        NET_API_STATUS status = NetLocalGroupAddMembers(
            NULL, groupName.c_str(), 3, reinterpret_cast<LPBYTE>(&member), 1);
        if (status != NERR_Success && status != ERROR_MEMBER_IN_ALIAS)
        {
            wchar_t msg[256]{};
            swprintf_s(msg, L"Failed to add claimed account to local group '%ls' (status=%lu)",
                       groupName.c_str(), static_cast<unsigned long>(status));
            outError = msg;
            return false;
        }
    }
    return true;
}

static bool SetPasswordNeverExpiresFlag(PCWSTR pszUsername, bool neverExpires, std::wstring& outError)
{
    LPBYTE pBuf = nullptr;
    NET_API_STATUS status = NetUserGetInfo(NULL, pszUsername, 1, &pBuf);
    if (status != NERR_Success || pBuf == nullptr)
    {
        outError = L"Failed to read local account flags";
        return false;
    }

    USER_INFO_1* pInfo = reinterpret_cast<USER_INFO_1*>(pBuf);
    DWORD flags = pInfo->usri1_flags;
    NetApiBufferFree(pBuf);

    if (neverExpires)
        flags |= UF_DONT_EXPIRE_PASSWD;
    else
        flags &= ~UF_DONT_EXPIRE_PASSWD;

    USER_INFO_1008 info1008 = {};
    info1008.usri1008_flags = flags;
    status = NetUserSetInfo(NULL, pszUsername, 1008, reinterpret_cast<LPBYTE>(&info1008), NULL);
    if (status != NERR_Success)
    {
        outError = L"Failed to update password expiry flags on claimed account";
        return false;
    }
    return true;
}

static bool UpsertClaimedLocalAccount(
    const DdsWindowsClaimResult& claim,
    const std::wstring& password,
    std::wstring& outSid,
    std::wstring& outError)
{
    std::wstring username;
    if (!Utf8ToWideString(claim.username, username))
    {
        outError = L"Invalid UTF-8 username in claim response";
        return false;
    }

    if (username.empty())
    {
        outError = L"Claim response did not include a username";
        return false;
    }

    if (!LocalUserExists(username.c_str()))
    {
        USER_INFO_1 info = {};
        info.usri1_name = const_cast<LPWSTR>(username.c_str());
        info.usri1_password = const_cast<LPWSTR>(password.c_str());
        info.usri1_priv = USER_PRIV_USER;
        info.usri1_flags = UF_SCRIPT;
        if (claim.hasPasswordNeverExpires && claim.passwordNeverExpires)
            info.usri1_flags |= UF_DONT_EXPIRE_PASSWD;

        DWORD parmErr = 0;
        NET_API_STATUS status = NetUserAdd(NULL, 1, reinterpret_cast<LPBYTE>(&info), &parmErr);
        if (status != NERR_Success)
        {
            wchar_t msg[256]{};
            swprintf_s(msg, L"NetUserAdd failed while claiming account '%ls' (status=%lu parm=%lu)",
                       username.c_str(), static_cast<unsigned long>(status),
                       static_cast<unsigned long>(parmErr));
            outError = msg;
            return false;
        }
    }
    else
    {
        USER_INFO_1003 pw = {};
        pw.usri1003_password = const_cast<LPWSTR>(password.c_str());
        NET_API_STATUS status =
            NetUserSetInfo(NULL, username.c_str(), 1003, reinterpret_cast<LPBYTE>(&pw), NULL);
        if (status != NERR_Success)
        {
            wchar_t msg[256]{};
            swprintf_s(msg, L"NetUserSetInfo(1003) failed for claimed account '%ls' (status=%lu)",
                       username.c_str(), static_cast<unsigned long>(status));
            outError = msg;
            return false;
        }
    }

    if (!claim.fullName.empty())
    {
        std::wstring fullName;
        if (Utf8ToWideString(claim.fullName, fullName))
        {
            USER_INFO_1011 info = {};
            info.usri1011_full_name = const_cast<LPWSTR>(fullName.c_str());
            NetUserSetInfo(NULL, username.c_str(), 1011, reinterpret_cast<LPBYTE>(&info), NULL);
        }
    }

    if (!claim.description.empty())
    {
        std::wstring comment;
        if (Utf8ToWideString(claim.description, comment))
        {
            USER_INFO_1007 info = {};
            info.usri1007_comment = const_cast<LPWSTR>(comment.c_str());
            NetUserSetInfo(NULL, username.c_str(), 1007, reinterpret_cast<LPBYTE>(&info), NULL);
        }
    }

    if (!ApplyLocalGroups(username.c_str(), claim.groups, outError))
        return false;

    if (claim.hasPasswordNeverExpires &&
        !SetPasswordNeverExpiresFlag(username.c_str(), claim.passwordNeverExpires, outError))
    {
        return false;
    }

    if (!ResolveLocalUserSid(username.c_str(), outSid, outError))
        return false;

    return true;
}

static void ResetAuthOperation(AuthOperation& op, HANDLE hResponseEvent)
{
    SecureZeroMemory(&op.responseData, sizeof(op.responseData));
    op = AuthOperation{};
    op.hResponseEvent = hResponseEvent;
}

CDdsAuthBridgeMain::CDdsAuthBridgeMain()
    : m_hStopEvent(NULL)
    , m_bInitialized(FALSE)
    , m_staleCooldownMs(STALE_COOLDOWN_DEFAULT_MS)
{
    m_activeAuth = AuthOperation{};
    m_activeAuth.hResponseEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    InitializeCriticalSection(&m_csAuth);
    InitializeCriticalSection(&m_csCooldown);
}

CDdsAuthBridgeMain::~CDdsAuthBridgeMain()
{
    Shutdown();
    if (m_activeAuth.hResponseEvent)
        CloseHandle(m_activeAuth.hResponseEvent);
    DeleteCriticalSection(&m_csAuth);
    DeleteCriticalSection(&m_csCooldown);
}

BOOL CDdsAuthBridgeMain::Initialize(_In_ HANDLE hStopEvent)
{
    if (hStopEvent == NULL)
    {
        return FALSE;
    }

    m_hStopEvent = hStopEvent;

    // Initialise the persistent file logger first thing -- every other
    // subsystem routes its diagnostics through it.
    FileLog::Init();
    FileLog::Write("DdsAuthBridge: Initialize() begin\n");

    // Load configuration from registry
    m_config.Load();

    // Configure dds-node HTTP client.
    // **A-2 (security review)**: prefer ApiAddr (which carries the
    // `pipe:<name>` scheme for H-7 step-2b's named-pipe transport).
    // Fall back to the legacy DdsNodePort path so installs that
    // pre-date this field still work against the loopback TCP
    // listener.
    if (!m_config.ApiAddr().empty())
    {
        FileLog::Writef("DdsAuthBridge: ApiAddr=%s\n", m_config.ApiAddr().c_str());
        m_httpClient.SetBaseUrl(m_config.ApiAddr());
    }
    else
    {
        m_httpClient.SetPort(m_config.DdsNodePort());
    }

    // **H-6 step-2 / A-3 (security review)**: load the per-install
    // HMAC secret. Every response from dds-node is verified against
    // HMAC-SHA256(key, method||0||path||0||body); mismatched / missing
    // MAC = refused response.
    //
    // A-3 makes this fail-closed by default: a production build with
    // `HmacSecretPath` empty refuses to start, so an installer that
    // skipped the `CA_GenHmacSecret` custom action (or an operator
    // who hand-deleted the registry value) cannot silently downgrade
    // to unsigned responses. Dev/test builds may opt into the legacy
    // behaviour via `DDS_DEV_ALLOW_NO_MAC` (build-time only — the
    // production MSI never defines this).
    {
        const std::wstring& hmacPath = m_config.HmacSecretPath();
        if (hmacPath.empty())
        {
#ifdef DDS_DEV_ALLOW_NO_MAC
            FileLog::Write(
                "DdsAuthBridge: HmacSecretPath not configured — H-6 MAC "
                "verification disabled (DDS_DEV_ALLOW_NO_MAC dev build)\n");
            CEventLogger::LogWarning(
                EVENT_ID::SERVICE_START_FAILED,
                L"HmacSecretPath not configured — response-body MAC "
                L"verification is disabled. This build was compiled with "
                L"DDS_DEV_ALLOW_NO_MAC; do not ship.");
#else
            FileLog::Write(
                "DdsAuthBridge: HmacSecretPath not configured — refusing to "
                "start (A-3: production builds require a per-install HMAC "
                "secret). Run `dds-node gen-hmac-secret` and set "
                "HKLM\\SOFTWARE\\DDS\\AuthBridge\\HmacSecretPath.\n");
            CEventLogger::LogError(
                EVENT_ID::SERVICE_START_FAILED,
                L"HmacSecretPath not configured — refusing to start the "
                L"Auth Bridge. Run `dds-node gen-hmac-secret` and set "
                L"HKLM\\SOFTWARE\\DDS\\AuthBridge\\HmacSecretPath.");
            return FALSE;
#endif
        }
        else if (!m_httpClient.LoadHmacSecret(hmacPath))
        {
            CEventLogger::LogError(
                EVENT_ID::SERVICE_START_FAILED,
                L"Failed to load HMAC secret — refusing to start the Auth Bridge");
            return FALSE;
        }
        else
        {
            FileLog::Write(
                "DdsAuthBridge: HMAC secret loaded — response-body MAC "
                "verification enabled\n");
        }
    }

    // Load credential vault
    if (!m_vault.Load())
    {
        CEventLogger::LogWarning(EVENT_ID::SERVICE_START_FAILED,
            L"Credential vault failed to load -- starting with empty vault");
    }

    // AD-14: load configurable stale-vault cooldown (default 15 min).
    // Spec §4.5: cooldown duration MUST remain ≤ AD lockout reset window.
    {
        DWORD configured = m_config.GetDword(L"StaleVaultCooldownMs",
            static_cast<DWORD>(STALE_COOLDOWN_DEFAULT_MS));
        if (configured == 0)
            configured = static_cast<DWORD>(STALE_COOLDOWN_DEFAULT_MS);
        m_staleCooldownMs = static_cast<ULONGLONG>(configured);
        FileLog::Writef("DdsAuthBridge: stale-vault cooldown = %llu ms\n",
                        static_cast<unsigned long long>(m_staleCooldownMs));
    }

    // Initialize IPC pipe server
    if (!m_pipeServer.Initialize(OnIpcRequest, this))
    {
        CEventLogger::LogError(EVENT_ID::SERVICE_START_FAILED, L"Failed to initialize IPC pipe server");
        return FALSE;
    }

    m_bInitialized = TRUE;
    FileLog::Write("DdsAuthBridge: Initialize() complete\n");
    return TRUE;
}

BOOL CDdsAuthBridgeMain::Start()
{
    if (!m_bInitialized)
    {
        return FALSE;
    }

    // Start the IPC pipe server
    if (!m_pipeServer.Start())
    {
        CEventLogger::LogError(EVENT_ID::SERVICE_START_FAILED, L"Failed to start IPC pipe server");
        return FALSE;
    }

    FileLog::Write("DdsAuthBridge: IPC pipe server started\n");
    return TRUE;
}

void CDdsAuthBridgeMain::Shutdown()
{
    if (!m_bInitialized)
    {
        return;
    }

    // Cancel any active auth operation
    EnterCriticalSection(&m_csAuth);
    if (m_activeAuth.hThread != NULL)
    {
        m_activeAuth.cancelled = TRUE;
        WaitForSingleObject(m_activeAuth.hThread, 5000);
        CloseHandle(m_activeAuth.hThread);
        m_activeAuth.hThread = NULL;
    }
    LeaveCriticalSection(&m_csAuth);

    m_pipeServer.Stop();

    m_bInitialized = FALSE;
    FileLog::Write("DdsAuthBridge: Shutdown complete\n");
}

// ============================================================================
// Helpers
// ============================================================================

void CDdsAuthBridgeMain::SendAuthProgress(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId,
    _In_ UINT32 state, _In_ PCWSTR message)
{
    IPC_RESP_DDS_AUTH_PROGRESS progress = {};
    progress.state = state;
    wcscpy_s(progress.message, message);

    m_pipeServer.SendNotification(pClientCtx, IPC_MSG::DDS_AUTH_PROGRESS, seqId,
        reinterpret_cast<const BYTE*>(&progress), sizeof(progress));
}

void CDdsAuthBridgeMain::SendAuthError(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId,
    _In_ UINT32 errorCode, _In_ PCWSTR message)
{
    IPC_RESP_DDS_AUTH_ERROR errResp = {};
    errResp.error_code = errorCode;
    wcscpy_s(errResp.message, message);

    m_pipeServer.SendResponse(pClientCtx, IPC_MSG::DDS_AUTH_ERROR, seqId,
        reinterpret_cast<const BYTE*>(&errResp), sizeof(errResp));
}

dds::JoinState CDdsAuthBridgeMain::GetJoinState()
{
    return dds::GetCachedJoinState();
}

// ============================================================================
// AD-14 — Stale-vault cooldown
// ============================================================================
//
// The cooldown map is keyed on the FIDO2 credential_id (base64url, exact
// case). base64url is case-sensitive ('A' = byte 0, 'a' = byte 26 in the
// decode table), so the bridge MUST NOT case-fold the key — doing so would
// collide truly-different credentials. The CP and bridge always exchange
// the same exact string for a given enrollment (CP echoes back the same
// `_pszCredentialId` it received from the tile enumeration), so a literal
// match is sufficient.
//
// One credential_id maps to one vault entry to one SID, so we don't need
// the SID in the key — the bridge can still resolve the affected SID via
// the vault if needed.
//
// Lifetime: in-memory, lost on service restart (intentional — a restart is
// itself a reasonable retry boundary and the goal is rate-limiting, not
// audit). Configurable via HKLM\SOFTWARE\DDS\AuthBridge\StaleVaultCooldownMs.

void CDdsAuthBridgeMain::MarkStaleCooldown(_In_ const std::wstring& credentialId)
{
    if (credentialId.empty())
        return;

    ULONGLONG expiry = GetTickCount64() + m_staleCooldownMs;

    EnterCriticalSection(&m_csCooldown);
    m_staleCooldown[credentialId] = expiry;
    LeaveCriticalSection(&m_csCooldown);

    FileLog::Writef("StaleCooldown: marked credId-prefix='%.16ls' expiry+=%llums\n",
                    credentialId.c_str(),
                    static_cast<unsigned long long>(m_staleCooldownMs));
}

BOOL CDdsAuthBridgeMain::IsStaleCooldownActive(_In_ const std::wstring& credentialId)
{
    if (credentialId.empty())
        return FALSE;

    ULONGLONG now = GetTickCount64();
    BOOL active = FALSE;

    EnterCriticalSection(&m_csCooldown);
    auto it = m_staleCooldown.find(credentialId);
    if (it != m_staleCooldown.end())
    {
        if (it->second > now)
        {
            active = TRUE;
        }
        else
        {
            // Expired — prune so the map stays bounded.
            m_staleCooldown.erase(it);
        }
    }
    LeaveCriticalSection(&m_csCooldown);

    return active;
}

void CDdsAuthBridgeMain::ClearStaleCooldown(_In_ const std::wstring& credentialId)
{
    if (credentialId.empty())
        return;

    EnterCriticalSection(&m_csCooldown);
    m_staleCooldown.erase(credentialId);
    LeaveCriticalSection(&m_csCooldown);

    FileLog::Writef("StaleCooldown: cleared credId-prefix='%.16ls'\n",
                    credentialId.c_str());
}

UINT32 CDdsAuthBridgeMain::NtStatusToStaleError(_In_ INT32 ntStatus)
{
    // Spec §4.4 mapping. The CP only sends a report for these three NTSTATUSes
    // (any other failure is either non-DDS or not stale-password-related), but
    // the bridge tolerates anything and silently no-ops on unknown codes.
    switch (static_cast<UINT32>(ntStatus))
    {
    case 0xC000006DUL: // STATUS_LOGON_FAILURE
        return IPC_ERROR::STALE_VAULT_PASSWORD;
    case 0xC0000224UL: // STATUS_PASSWORD_MUST_CHANGE
        return IPC_ERROR::AD_PASSWORD_CHANGE_REQUIRED;
    case 0xC0000071UL: // STATUS_PASSWORD_EXPIRED
        return IPC_ERROR::AD_PASSWORD_EXPIRED;
    default:
        return 0;
    }
}

BOOL CDdsAuthBridgeMain::HandleDdsReportLogonResult(
    _In_ const BYTE* pPayload,
    _In_ DWORD payloadLen)
{
    if (pPayload == nullptr || payloadLen < sizeof(IPC_REQ_DDS_REPORT_LOGON_RESULT))
    {
        FileLog::Writef("ReportLogonResult: ignoring malformed payload (len=%lu)\n",
                        payloadLen);
        return TRUE; // fire-and-forget — no error response
    }

    const IPC_REQ_DDS_REPORT_LOGON_RESULT* pReq =
        reinterpret_cast<const IPC_REQ_DDS_REPORT_LOGON_RESULT*>(pPayload);

    UINT32 mapped = NtStatusToStaleError(pReq->ntStatus);
    if (mapped == 0)
    {
        FileLog::Writef("ReportLogonResult: NTSTATUS=0x%08lX is not a stale-password code; ignoring\n",
                        static_cast<unsigned long>(static_cast<UINT32>(pReq->ntStatus)));
        return TRUE;
    }

    // Defensive: ensure the credential_id field is null-terminated within bounds.
    WCHAR credIdBuf[IPC_MAX_CREDENTIAL_ID_LEN]{};
    wcsncpy_s(credIdBuf, pReq->credential_id, _TRUNCATE);
    std::wstring credentialId(credIdBuf);

    if (credentialId.empty())
    {
        FileLog::Write("ReportLogonResult: empty credential_id; ignoring\n");
        return TRUE;
    }

    MarkStaleCooldown(credentialId);
    FileLog::Writef("ReportLogonResult: cooldown installed (NTSTATUS=0x%08lX -> error=%lu)\n",
                    static_cast<unsigned long>(static_cast<UINT32>(pReq->ntStatus)),
                    static_cast<unsigned long>(mapped));
    return TRUE;
}

BOOL CDdsAuthBridgeMain::HandleDdsClearStale(
    _In_ const BYTE* pPayload,
    _In_ DWORD payloadLen)
{
    if (pPayload == nullptr || payloadLen < sizeof(IPC_REQ_DDS_CLEAR_STALE))
    {
        FileLog::Writef("ClearStale: ignoring malformed payload (len=%lu)\n",
                        payloadLen);
        return TRUE;
    }

    const IPC_REQ_DDS_CLEAR_STALE* pReq =
        reinterpret_cast<const IPC_REQ_DDS_CLEAR_STALE*>(pPayload);

    WCHAR credIdBuf[IPC_MAX_CREDENTIAL_ID_LEN]{};
    wcsncpy_s(credIdBuf, pReq->credential_id, _TRUNCATE);
    std::wstring credentialId(credIdBuf);

    ClearStaleCooldown(credentialId);
    return TRUE;
}

// ============================================================================
// IPC Request Handler (static dispatch)
// ============================================================================

BOOL CALLBACK CDdsAuthBridgeMain::OnIpcRequest(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ const IPC_MESSAGE_HEADER* pHeader,
    _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
    _In_ DWORD payloadLen,
    _In_opt_ void* pUserContext)
{
    CDdsAuthBridgeMain* pSelf = static_cast<CDdsAuthBridgeMain*>(pUserContext);
    if (pSelf == nullptr || pHeader == nullptr)
    {
        return FALSE;
    }

    switch (pHeader->msgType)
    {
    // --- DDS-specific messages ---

    case IPC_MSG::DDS_START_AUTH:
        if (pPayload != nullptr && payloadLen > 0)
        {
            return pSelf->HandleDdsStartAuth(pClientCtx, pHeader->seqId,
                pPayload, payloadLen);
        }
        break;

    case IPC_MSG::DDS_AUTH_RESPONSE:
        if (pPayload != nullptr && payloadLen > 0)
        {
            return pSelf->HandleDdsAuthResponse(pClientCtx, pHeader->seqId,
                pPayload, payloadLen);
        }
        break;

    case IPC_MSG::DDS_LIST_USERS:
        return pSelf->HandleDdsListUsers(pClientCtx, pHeader->seqId);

    case IPC_MSG::DDS_REPORT_LOGON_RESULT:
        // AD-14: fire-and-forget; never replies, even on error.
        return pSelf->HandleDdsReportLogonResult(pPayload, payloadLen);

    case IPC_MSG::DDS_CLEAR_STALE:
        // AD-13: fire-and-forget; never replies.
        return pSelf->HandleDdsClearStale(pPayload, payloadLen);

    // --- Legacy Crayonic messages (backwards compat) ---

    case IPC_MSG::GET_STATUS:
        return pSelf->HandleGetStatus(pClientCtx, pHeader->seqId);

    case IPC_MSG::LIST_USERS:
        return pSelf->HandleListUsers(pClientCtx, pHeader->seqId);

    case IPC_MSG::START_AUTH_FIDO:
        if (pPayload != nullptr && payloadLen >= sizeof(IPC_REQ_START_AUTH_FIDO))
        {
            return pSelf->HandleStartAuthFido(pClientCtx, pHeader->seqId,
                reinterpret_cast<const IPC_REQ_START_AUTH_FIDO*>(pPayload));
        }
        break;

    case IPC_MSG::CANCEL_AUTH:
        if (pPayload != nullptr && payloadLen >= sizeof(IPC_REQ_CANCEL_AUTH))
        {
            return pSelf->HandleCancelAuth(pClientCtx, pHeader->seqId,
                reinterpret_cast<const IPC_REQ_CANCEL_AUTH*>(pPayload));
        }
        break;

    case IPC_MSG::ENROLL_USER:
        if (pPayload != nullptr && payloadLen >= sizeof(IPC_REQ_ENROLL_USER))
        {
            return pSelf->HandleEnrollUser(pClientCtx, pHeader->seqId,
                reinterpret_cast<const IPC_REQ_ENROLL_USER*>(pPayload));
        }
        break;

    case IPC_MSG::UNENROLL_USER:
        if (pPayload != nullptr && payloadLen >= sizeof(IPC_REQ_UNENROLL_USER))
        {
            return pSelf->HandleUnenrollUser(pClientCtx, pHeader->seqId,
                reinterpret_cast<const IPC_REQ_UNENROLL_USER*>(pPayload));
        }
        break;
    }

    // Unknown or malformed
    IPC_RESP_AUTH_ERROR errResp = {};
    errResp.errorCode = IPC_ERROR::SERVICE_ERROR;
    wcscpy_s(errResp.message, L"Unknown or malformed request");
    pSelf->m_pipeServer.SendResponse(pClientCtx, IPC_MSG::AUTH_ERROR, pHeader->seqId,
        reinterpret_cast<const BYTE*>(&errResp), sizeof(errResp));

    return TRUE;
}

// ============================================================================
// DDS_START_AUTH handler
//
// DDS authentication flow:
//   1. Call platform WebAuthn API for getAssertion (TODO: stub for now)
//   2. POST assertion proof to dds-node /v1/session/assert
//   3. Use hmac-secret to decrypt stored password from vault
//   4. Return DDS_AUTH_COMPLETE with password + session token
// ============================================================================

BOOL CDdsAuthBridgeMain::HandleDdsStartAuth(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId,
    _In_ const BYTE* pPayload,
    _In_ DWORD payloadLen)
{
    FileLog::Writef("DdsStartAuth: seqId=%u payloadLen=%lu\n", seqId, payloadLen);

    // Check for existing auth operation
    EnterCriticalSection(&m_csAuth);
    if (m_activeAuth.hThread != NULL)
    {
        LeaveCriticalSection(&m_csAuth);
        SendAuthError(pClientCtx, seqId, IPC_ERROR::DEVICE_BUSY,
            L"Another authentication is in progress");
        return TRUE;
    }

    // Extract DDS-specific fields from the IPC_REQ_DDS_START_AUTH payload.
    const IPC_REQ_DDS_START_AUTH* pReq = nullptr;
    if (payloadLen >= sizeof(IPC_REQ_DDS_START_AUTH))
    {
        pReq = reinterpret_cast<const IPC_REQ_DDS_START_AUTH*>(pPayload);
    }
    else
    {
        LeaveCriticalSection(&m_csAuth);
        SendAuthError(pClientCtx, seqId, IPC_ERROR::SERVICE_ERROR,
            L"Invalid DDS_START_AUTH payload");
        return TRUE;
    }

    // Historical note: the IPC field is named `device_urn`, but the
    // credential provider currently fills it with the DDS subject URN.
    // The actual endpoint device URN comes from the bridge service config.
    std::wstring subjectUrn(pReq->device_urn);
    std::wstring credentialId(pReq->credential_id);
    std::wstring rpIdW(pReq->rp_id);

    // Reload vault from disk — it may have been updated by the tray agent
    m_vault.Load();

    // Convert RP ID to narrow string for HTTP and vault use.
    char rpIdA[256]{};
    WideCharToMultiByte(CP_UTF8, 0, rpIdW.c_str(), -1, rpIdA, sizeof(rpIdA), nullptr, nullptr);

    {
        char urnA[160]{}, credA[160]{};
        WideCharToMultiByte(CP_UTF8, 0, subjectUrn.c_str(), -1, urnA, sizeof(urnA), nullptr, nullptr);
        WideCharToMultiByte(CP_UTF8, 0, credentialId.c_str(), -1, credA, sizeof(credA), nullptr, nullptr);
        FileLog::Writef("DdsStartAuth: subject='%s' device='%s' credId='%s' rp='%s'\n",
                        urnA, m_config.DeviceUrn().c_str(), credA, rpIdA);
    }

    // AD-14: bail out before WebAuthn / Kerberos serialization if a stale
    // cooldown is active for this credential. Spec §4.5: short-circuit
    // STALE_VAULT_PASSWORD before any auth ceremony to avoid AD lockout.
    if (IsStaleCooldownActive(credentialId))
    {
        LeaveCriticalSection(&m_csAuth);
        SendAuthError(pClientCtx, seqId, IPC_ERROR::STALE_VAULT_PASSWORD,
            L"Your DDS stored password may be out of date. Sign in normally "
            L"with your Windows password, then refresh DDS from the system tray.");
        return TRUE;
    }

    // Look up vault entry by the credential_id from the request.
    // The credential_id is base64url-encoded; the vault stores raw bytes.
    const VaultEntry* pMatchedEntry = nullptr;
    {
        // Convert wide credential_id to narrow UTF-8 for base64url decode
        char credIdNarrow[256]{};
        WideCharToMultiByte(CP_UTF8, 0, credentialId.c_str(), -1,
                            credIdNarrow, sizeof(credIdNarrow), nullptr, nullptr);
        std::vector<uint8_t> credIdBytes = Base64UrlDecode(std::string(credIdNarrow));
        if (!credIdBytes.empty())
            pMatchedEntry = m_vault.FindByCredentialId(credIdBytes);
    }

    if (pMatchedEntry)
    {
        FileLog::Writef("DdsStartAuth: matched vault entry sid='%ls' credIdLen=%zu\n",
                        pMatchedEntry->userSid.c_str(), pMatchedEntry->credentialId.size());
    }
    else
    {
        FileLog::Write("DdsStartAuth: no vault entry yet -- entering first-claim mode\n");
        if (m_config.DeviceUrn().empty())
        {
            LeaveCriticalSection(&m_csAuth);
            SendAuthError(pClientCtx, seqId, IPC_ERROR::SERVICE_ERROR,
                L"Device URN is not configured for first-account claim");
            return TRUE;
        }
    }

    // Set up auth operation using the matched vault entry
    m_activeAuth.pClientCtx = pClientCtx;
    m_activeAuth.seqId = seqId;
    m_activeAuth.authMethod = IPC_AUTH_METHOD::FIDO2;
    m_activeAuth.deviceUrn = m_config.DeviceUrn();
    m_activeAuth.userSid = pMatchedEntry ? pMatchedEntry->userSid : L"";
    m_activeAuth.subjectUrn = subjectUrn;
    m_activeAuth.credentialId = credentialId;
    m_activeAuth.rpId = rpIdA[0] ? std::string(rpIdA) : m_config.RpId();
    m_activeAuth.claimMode = pMatchedEntry ? FALSE : TRUE;
    m_activeAuth.claimSaltLen = 0;
    ZeroMemory(m_activeAuth.claimSalt, sizeof(m_activeAuth.claimSalt));
    if (!pMatchedEntry)
    {
        m_activeAuth.claimSaltLen = 32;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, m_activeAuth.claimSalt, m_activeAuth.claimSaltLen,
                                            BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        {
            HANDLE hEvt = m_activeAuth.hResponseEvent;
            ResetAuthOperation(m_activeAuth, hEvt);
            LeaveCriticalSection(&m_csAuth);
            SendAuthError(pClientCtx, seqId, IPC_ERROR::SERVICE_ERROR,
                L"Failed to generate claim salt");
            return TRUE;
        }
    }
    m_activeAuth.cancelled = FALSE;
    m_activeAuth.responseReceived = FALSE;
    ResetEvent(m_activeAuth.hResponseEvent);
    ZeroMemory(&m_activeAuth.responseData, sizeof(m_activeAuth.responseData));

    // Spawn worker thread
    m_activeAuth.hThread = CreateThread(NULL, 0, DdsAuthWorkerThread, this, 0, NULL);
    if (m_activeAuth.hThread == NULL)
    {
        HANDLE hEvt = m_activeAuth.hResponseEvent; // preserve event handle
        ResetAuthOperation(m_activeAuth, hEvt);
        LeaveCriticalSection(&m_csAuth);
        SendAuthError(pClientCtx, seqId, IPC_ERROR::SERVICE_ERROR,
            L"Failed to start authentication thread");
        return TRUE;
    }

    LeaveCriticalSection(&m_csAuth);
    return TRUE;
}

// ============================================================================
// DDS_AUTH_RESPONSE handler — CP sends WebAuthn assertion result
// ============================================================================

BOOL CDdsAuthBridgeMain::HandleDdsAuthResponse(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId,
    _In_ const BYTE* pPayload,
    _In_ DWORD payloadLen)
{
    FileLog::Writef("DdsAuthResponse: seqId=%u payloadLen=%lu\n", seqId, payloadLen);

    if (payloadLen < sizeof(IPC_REQ_DDS_AUTH_RESPONSE))
    {
        SendAuthError(pClientCtx, seqId, IPC_ERROR::SERVICE_ERROR,
            L"Invalid DDS_AUTH_RESPONSE payload");
        return TRUE;
    }

    EnterCriticalSection(&m_csAuth);
    if (m_activeAuth.hThread == NULL)
    {
        LeaveCriticalSection(&m_csAuth);
        SendAuthError(pClientCtx, seqId, IPC_ERROR::SERVICE_ERROR,
            L"No active auth operation to receive response");
        return TRUE;
    }

    // Copy response data and signal the worker thread
    memcpy(&m_activeAuth.responseData, pPayload, sizeof(IPC_REQ_DDS_AUTH_RESPONSE));
    m_activeAuth.responseReceived = TRUE;
    SetEvent(m_activeAuth.hResponseEvent);

    LeaveCriticalSection(&m_csAuth);
    return TRUE;
}

// ============================================================================
// DDS Auth Worker Thread
// ============================================================================

DWORD WINAPI CDdsAuthBridgeMain::DdsAuthWorkerThread(_In_ LPVOID pParam)
{
    CDdsAuthBridgeMain* pSelf = static_cast<CDdsAuthBridgeMain*>(pParam);

    EnterCriticalSection(&pSelf->m_csAuth);
    AuthOperation op = pSelf->m_activeAuth; // Copy operation params
    LeaveCriticalSection(&pSelf->m_csAuth);

    pSelf->ExecuteDdsAuth(&op);

    // Clean up — preserve the response event handle across operations
    EnterCriticalSection(&pSelf->m_csAuth);
    HANDLE hEvt = pSelf->m_activeAuth.hResponseEvent;
    if (pSelf->m_activeAuth.hThread != NULL)
    {
        CloseHandle(pSelf->m_activeAuth.hThread);
    }
    ResetAuthOperation(pSelf->m_activeAuth, hEvt);
    LeaveCriticalSection(&pSelf->m_csAuth);

    return 0;
}

void CDdsAuthBridgeMain::ExecuteDdsAuth(_In_ AuthOperation* pOp)
{
    // ================================================================
    // DDS Two-Phase Authentication Flow
    //
    // Phase 1 (Bridge → CP):
    //   1. Find vault entry for the user
    //   2. Generate a random clientDataHash (challenge)
    //   3. Send DDS_AUTH_CHALLENGE with credential ID, RP ID, salt, challenge
    //
    // Phase 2 (CP → Bridge, after CP calls WebAuthNAuthenticatorGetAssertion):
    //   4. Wait for DDS_AUTH_RESPONSE with assertion + hmac-secret
    //   5. POST assertion proof to dds-node /v1/session/assert
    //   6. Use hmac-secret to decrypt password from vault
    //   7. Return DDS_AUTH_COMPLETE with password + session token
    // ================================================================

    FileLog::Writef("DdsAuth.worker: seqId=%u begin (rpId='%s')\n",
                    pOp->seqId, pOp->rpId.c_str());

    // Step 1: Find an existing vault entry for this credential, if any.
    const VaultEntry* pVaultEntry = nullptr;
    std::vector<uint8_t> requestedCredIdBytes;
    {
        char credIdNarrow[256]{};
        WideCharToMultiByte(CP_UTF8, 0, pOp->credentialId.c_str(), -1,
                            credIdNarrow, sizeof(credIdNarrow), nullptr, nullptr);
        requestedCredIdBytes = Base64UrlDecode(std::string(credIdNarrow));
        if (!requestedCredIdBytes.empty())
            pVaultEntry = m_vault.FindByCredentialId(requestedCredIdBytes);
    }

    if (requestedCredIdBytes.empty())
    {
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::SERVICE_ERROR,
            L"Credential ID could not be decoded");
        return;
    }

    if (pVaultEntry)
    {
        FileLog::Writef("DdsAuth.worker: using vault entry (credIdLen=%zu rp='%s' sid='%ls')\n",
                        pVaultEntry->credentialId.size(), pVaultEntry->rpId.c_str(),
                        pVaultEntry->userSid.c_str());
    }
    else if (pOp->claimMode)
    {
        FileLog::Write("DdsAuth.worker: first-claim path — no vault entry exists yet\n");
    }
    else
    {
        FileLog::Write("DdsAuth.worker: vault lookup failed -- no matching credential\n");
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::NO_CREDENTIAL,
            L"No credential found for user");
        return;
    }

    // Step 2a: Fetch a server-issued FIDO2 challenge from dds-node.
    //          This ensures the assertion binds to a server-issued nonce that
    //          can only be used once, preventing replay attacks.
    DdsChallengeResult serverChallenge = m_httpClient.GetSessionChallenge();
    if (!serverChallenge.success)
    {
        FileLog::Writef("DdsAuth.worker: failed to fetch server challenge: %s\n",
                        serverChallenge.errorMessage.c_str());
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::SERVICE_ERROR,
            L"Could not obtain authentication challenge from DDS node");
        return;
    }
    FileLog::Writef("DdsAuth.worker: obtained challenge '%s'\n",
                    serverChallenge.challengeId.c_str());

    // Step 2b: Build and send DDS_AUTH_CHALLENGE to CP (includes server challenge).
    IPC_RESP_DDS_AUTH_CHALLENGE challenge = {};

    // Copy credential ID
    DWORD credIdLen = static_cast<DWORD>((std::min)(requestedCredIdBytes.size(),
                                             sizeof(challenge.credential_id)));
    memcpy(challenge.credential_id, requestedCredIdBytes.data(), credIdLen);
    challenge.credential_id_len = credIdLen;

    // RP ID comes from the existing vault entry or the configured/requested value.
    strncpy_s(challenge.rp_id,
              pVaultEntry ? pVaultEntry->rpId.c_str() : pOp->rpId.c_str(),
              _TRUNCATE);

    // Existing accounts reuse the persisted hmac-secret salt. First claim
    // uses the temporary salt generated in HandleDdsStartAuth and carried in
    // the active auth operation.
    DWORD saltLen = 0;
    if (pVaultEntry)
    {
        saltLen = static_cast<DWORD>((std::min)(pVaultEntry->salt.size(),
                                         sizeof(challenge.salt)));
        if (saltLen > 0)
            memcpy(challenge.salt, pVaultEntry->salt.data(), saltLen);
    }
    else
    {
        saltLen = static_cast<DWORD>((std::min<size_t>)(pOp->claimSaltLen, sizeof(challenge.salt)));
        if (saltLen > 0)
            memcpy(challenge.salt, pOp->claimSalt, saltLen);
    }
    challenge.salt_len = saltLen;

    // Populate server challenge fields so the CP uses the server nonce in WebAuthn.
    strncpy_s(challenge.challenge_id, serverChallenge.challengeId.c_str(), _TRUNCATE);
    strncpy_s(challenge.challenge_b64url, serverChallenge.challengeB64url.c_str(), _TRUNCATE);

    FileLog::Writef("DdsAuth.worker: sending AUTH_CHALLENGE (credIdLen=%u saltLen=%u challengeId='%s')\n",
                    credIdLen, saltLen, challenge.challenge_id);

    m_pipeServer.SendNotification(pOp->pClientCtx, IPC_MSG::DDS_AUTH_CHALLENGE, pOp->seqId,
        reinterpret_cast<const BYTE*>(&challenge), sizeof(challenge));

    SendAuthProgress(pOp->pClientCtx, pOp->seqId,
        IPC_AUTH_STATE::USER_PRESENCE, L"Touch your security key or use Windows Hello...");

    // Step 4: Wait for DDS_AUTH_RESPONSE from CP (up to 60 seconds)
    DWORD waitResult = WaitForSingleObject(pOp->hResponseEvent, IPC_PIPE::AUTH_TIMEOUT_MS);

    // After the event fires, copy response data from m_activeAuth (the original)
    // into our local copy. HandleDdsAuthResponse writes to m_activeAuth, not our
    // local pOp, so we must read it back under the lock.
    EnterCriticalSection(&m_csAuth);
    pOp->cancelled        = m_activeAuth.cancelled;
    pOp->responseReceived = m_activeAuth.responseReceived;
    if (m_activeAuth.responseReceived)
        memcpy(&pOp->responseData, &m_activeAuth.responseData, sizeof(pOp->responseData));
    LeaveCriticalSection(&m_csAuth);

    if (pOp->cancelled)
    {
        FileLog::Write("DdsAuth.worker: cancelled by client\n");
        return;
    }

    if (waitResult == WAIT_TIMEOUT)
    {
        FileLog::Write("DdsAuth.worker: timed out waiting for WebAuthn response from CP\n");
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::AUTH_TIMEOUT,
            L"Authentication timed out waiting for authenticator");
        return;
    }

    if (!pOp->responseReceived)
    {
        FileLog::Write("DdsAuth.worker: response event signaled but no data\n");
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::SERVICE_ERROR,
            L"Internal error: no response data");
        return;
    }

    const IPC_REQ_DDS_AUTH_RESPONSE* pResp = &pOp->responseData;
    FileLog::Writef("DdsAuth.worker: got AUTH_RESPONSE (authDataLen=%u sigLen=%u hmacLen=%u)\n",
                    pResp->authenticator_data_len, pResp->signature_len, pResp->hmac_secret_len);

    // Step 5: Build assertion JSON and POST to dds-node /v1/session/assert
    SendAuthProgress(pOp->pClientCtx, pOp->seqId,
        IPC_AUTH_STATE::PROCESSING, L"Verifying assertion with DDS node...");

    std::string credIdB64 = Base64UrlEncode(pResp->credential_id, pResp->credential_id_len);
    std::string authDataB64 = Base64UrlEncode(pResp->authenticator_data, pResp->authenticator_data_len);
    std::string sigB64 = Base64UrlEncode(pResp->signature, pResp->signature_len);
    std::string cdhB64 = Base64UrlEncode(pResp->client_data_hash, 32);

    // CP echoes back the challenge_id from the IPC challenge; use it in the POST.
    std::string challengeIdStr(pResp->challenge_id, strnlen(pResp->challenge_id, sizeof(pResp->challenge_id)));
    if (challengeIdStr.empty())
    {
        // Fallback: use the server challenge we fetched (should not normally happen).
        challengeIdStr = serverChallenge.challengeId;
        FileLog::Write("DdsAuth.worker: CP did not echo challenge_id — using server copy\n");
    }

    // Build the JSON expected by dds-node's AssertionSessionRequestJson
    std::string assertionJson = "{";
    assertionJson += "\"credential_id\":\"" + credIdB64 + "\",";
    assertionJson += "\"challenge_id\":\"" + challengeIdStr + "\",";
    assertionJson += "\"client_data_hash\":\"" + cdhB64 + "\",";
    assertionJson += "\"authenticator_data\":\"" + authDataB64 + "\",";
    assertionJson += "\"signature\":\"" + sigB64 + "\"";
    assertionJson += "}";

    DdsAssertResult assertResult = m_httpClient.PostSessionAssert(assertionJson);

    if (!assertResult.success)
    {
        FileLog::Writef("DdsAuth.worker: dds-node assert failed: %s\n",
                        assertResult.errorMessage.c_str());
        wchar_t errMsg[256];
        swprintf_s(errMsg, L"DDS node verification failed: %hs",
                   assertResult.errorMessage.c_str());
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::AUTH_FAILED, errMsg);
        return;
    }

    FileLog::Writef("DdsAuth.worker: dds-node assert OK (tokenLen=%zu)\n",
                    assertResult.tokenCborB64.size());

    if (pOp->cancelled)
    {
        FileLog::Write("DdsAuth.worker: cancelled by client\n");
        return;
    }

    if (pResp->hmac_secret_len != 32)
    {
        FileLog::Writef("DdsAuth.worker: invalid hmac-secret length: %u (expected 32)\n",
                        pResp->hmac_secret_len);
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::AUTH_FAILED,
            L"Authenticator did not return hmac-secret output");
        return;
    }

    std::wstring password;
    std::wstring resolvedSid = pOp->userSid;
    std::string claimedUsernameUtf8;
    std::string claimedSubjectUrnUtf8;
    if (!pOp->claimMode)
    {
        if (!CCredentialVault::DecryptPassword(pResp->hmac_secret, pResp->hmac_secret_len,
                                               *pVaultEntry, password))
        {
            FileLog::Write("DdsAuth.worker: password decryption failed (wrong key or corrupt vault)\n");
            SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::VAULT_ERROR,
                L"Failed to decrypt stored password — re-enrollment may be required");
            return;
        }

        FileLog::Write("DdsAuth.worker: password decrypted successfully\n");
    }
    else
    {
        SendAuthProgress(pOp->pClientCtx, pOp->seqId,
            IPC_AUTH_STATE::PROCESSING, L"Claiming local Windows account...");

        if (GetJoinState() != dds::JoinState::Workgroup)
        {
            // Phase 1 preserves the previous "block claim on domain-joined"
            // behavior. AD-08 (Phase 3) will split this into more specific
            // PRE_ENROLLMENT_REQUIRED / UNSUPPORTED_HOST IPC errors per
            // JoinState. For now we keep the broader-than-AD-only gate so
            // Hybrid / EntraOnly / Unknown hosts also fail safe.
            SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::AUTH_FAILED,
                L"Account claim is disabled on domain-joined machines");
            return;
        }

        std::string claimJson = "{";
        claimJson += "\"device_urn\":\"" + pOp->deviceUrn + "\",";
        claimJson += "\"session_token_cbor_b64\":\"" + assertResult.tokenCborB64 + "\"";
        claimJson += "}";

        DdsWindowsClaimResult claimResult = m_httpClient.PostWindowsClaim(claimJson);
        if (!claimResult.success)
        {
            wchar_t errMsg[384];
            swprintf_s(errMsg, L"DDS node claim authorization failed: %hs",
                       claimResult.errorMessage.c_str());
            SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::AUTH_FAILED, errMsg);
            return;
        }

        if (!GenerateClaimPassword(password))
        {
            SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::SERVICE_ERROR,
                L"Failed to generate a local account password");
            return;
        }

        std::wstring accountError;
        if (!UpsertClaimedLocalAccount(claimResult, password, resolvedSid, accountError))
        {
            SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::AUTH_FAILED,
                accountError.empty() ? L"Failed to create or update the claimed local account"
                                     : accountError.c_str());
            SecureZeroWString(password);
            return;
        }
        claimedUsernameUtf8 = claimResult.username;
        claimedSubjectUrnUtf8 = claimResult.subjectUrn;

        VaultEntry entry = {};
        entry.userSid = resolvedSid;
        if (!claimResult.fullName.empty())
        {
            if (!Utf8ToWideString(claimResult.fullName, entry.displayName))
                entry.displayName = L"";
        }
        if (entry.displayName.empty() && !Utf8ToWideString(claimResult.username, entry.displayName))
            entry.displayName = L"Claimed User";
        entry.credentialId = requestedCredIdBytes;
        entry.rpId = pOp->rpId;
        entry.salt.assign(pOp->claimSalt, pOp->claimSalt + pOp->claimSaltLen);
        entry.authMethod = IPC_AUTH_METHOD::FIDO2;

        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        entry.enrollmentTime =
            (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

        if (!CCredentialVault::EncryptPassword(
                pResp->hmac_secret, pResp->hmac_secret_len, password.c_str(), entry))
        {
            SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::VAULT_ERROR,
                L"Failed to wrap the claimed account password with hmac-secret");
            SecureZeroWString(password);
            return;
        }

        m_vault.Load();
        if (!m_vault.EnrollUser(entry) || !m_vault.Save())
        {
            SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::VAULT_ERROR,
                L"Claimed account was created but the local vault could not be updated");
            SecureZeroWString(password);
            return;
        }

        FileLog::Writef("DdsAuth.worker: first-claim completed sid='%ls' username='%s'\n",
                        resolvedSid.c_str(), claimedUsernameUtf8.c_str());
    }

    // Step 7: Build and send DDS_AUTH_COMPLETE
    IPC_RESP_DDS_AUTH_COMPLETE result = {};
    result.success = TRUE;

    // Resolve domain + username from the Windows SID
    {
        WCHAR compName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD compLen = ARRAYSIZE(compName);
        if (GetComputerNameW(compName, &compLen))
            wcsncpy_s(result.domain, compName, _TRUNCATE);
        else
            wcscpy_s(result.domain, L".");

        // Look up account name from SID
        PSID pSid = NULL;
        if (ConvertStringSidToSidW(resolvedSid.c_str(), &pSid))
        {
            WCHAR userName[256], domainName[256];
            DWORD userLen = ARRAYSIZE(userName), domLen = ARRAYSIZE(domainName);
            SID_NAME_USE sidUse;
            if (LookupAccountSidW(NULL, pSid, userName, &userLen,
                                  domainName, &domLen, &sidUse))
            {
                wcsncpy_s(result.username, userName, _TRUNCATE);
                // Prefer domain from LookupAccountSid if available
                if (domainName[0] != L'\0')
                    wcsncpy_s(result.domain, domainName, _TRUNCATE);
            }
            LocalFree(pSid);
        }
    }

    if (pOp->claimMode && !claimedUsernameUtf8.empty())
    {
        std::wstring claimedUsernameWide;
        if (Utf8ToWideString(claimedUsernameUtf8, claimedUsernameWide))
            wcsncpy_s(result.username, claimedUsernameWide.c_str(), _TRUNCATE);
    }

    wcsncpy_s(result.password, password.c_str(), _TRUNCATE);

    {
        char domA[64]{}, userA[64]{};
        WideCharToMultiByte(CP_UTF8, 0, result.domain, -1, domA, sizeof(domA), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, result.username, -1, userA, sizeof(userA), NULL, NULL);
        FileLog::Writef("DdsAuth.worker: domain='%s' username='%s' pwdLen=%zu\n",
            domA, userA, password.size());
    }

    // Fill session token (token_cbor_b64 from Rust /v1/session/assert)
    strncpy_s(result.session_token, assertResult.tokenCborB64.c_str(), _TRUNCATE);
    std::wstring resolvedSubjectUrn = pOp->subjectUrn;
    if (!claimedSubjectUrnUtf8.empty())
        Utf8ToWideString(claimedSubjectUrnUtf8, resolvedSubjectUrn);
    wcsncpy_s(result.subject_urn,
              resolvedSubjectUrn.empty() ? resolvedSid.c_str() : resolvedSubjectUrn.c_str(),
              _TRUNCATE);
    result.expires_at = assertResult.expiresAt; // from dds-node response

    m_pipeServer.SendResponse(pOp->pClientCtx, IPC_MSG::DDS_AUTH_COMPLETE, pOp->seqId,
        reinterpret_cast<const BYTE*>(&result), sizeof(result));

    // Secure cleanup
    SecureZeroWString(password);
    SecureZeroMemory(result.password, sizeof(result.password));

    CEventLogger::LogInfo(EVENT_ID::AUTH_SUCCEEDED, L"DDS authentication succeeded");

    FileLog::Writef("DdsAuth.worker: seqId=%u complete OK\n", pOp->seqId);
}

// ============================================================================
// DDS_LIST_USERS handler
// Retrieves enrolled users from dds-node via HTTP GET
// ============================================================================

BOOL CDdsAuthBridgeMain::HandleDdsListUsers(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId)
{
    FileLog::Write("DdsListUsers: fetching from dds-node\n");

    DdsEnrolledUsersResult result = m_httpClient.GetEnrolledUsers(m_config.DeviceUrn());

    if (!result.success)
    {
        FileLog::Writef("DdsListUsers: dds-node request failed: %s\n",
                        result.errorMessage.c_str());

        // Fall back to local vault entries
        FileLog::Write("DdsListUsers: falling back to local vault\n");
        return HandleListUsers(pClientCtx, seqId);
    }

    // Build IPC response from dds-node data using the DDS-specific
    // structs that the credential provider expects.
    BYTE buffer[IPC_PIPE::BUFFER_SIZE];
    IPC_RESP_DDS_USER_LIST* pList = reinterpret_cast<IPC_RESP_DDS_USER_LIST*>(buffer);

    size_t maxUsers = (sizeof(buffer) - sizeof(IPC_RESP_DDS_USER_LIST)) / sizeof(IPC_DDS_USER_ENTRY);
    UINT32 count = static_cast<UINT32>((std::min)(result.users.size(), maxUsers));
    pList->count = count;

    IPC_DDS_USER_ENTRY* pEntries = reinterpret_cast<IPC_DDS_USER_ENTRY*>(buffer + sizeof(IPC_RESP_DDS_USER_LIST));
    for (UINT32 i = 0; i < count; i++)
    {
        ZeroMemory(&pEntries[i], sizeof(IPC_DDS_USER_ENTRY));
        MultiByteToWideChar(CP_UTF8, 0,
            result.users[i].subjectUrn.c_str(), -1,
            pEntries[i].subject_urn, _countof(pEntries[i].subject_urn));
        MultiByteToWideChar(CP_UTF8, 0,
            result.users[i].displayName.c_str(), -1,
            pEntries[i].display_name, _countof(pEntries[i].display_name));
        MultiByteToWideChar(CP_UTF8, 0,
            result.users[i].credentialId.c_str(), -1,
            pEntries[i].credential_id, _countof(pEntries[i].credential_id));
    }

    DWORD totalSize = sizeof(IPC_RESP_DDS_USER_LIST) + count * sizeof(IPC_DDS_USER_ENTRY);

    FileLog::Writef("DdsListUsers: returning %u user(s) from dds-node\n", count);

    return m_pipeServer.SendResponse(pClientCtx, IPC_MSG::DDS_USER_LIST, seqId,
        buffer, totalSize);
}

// ============================================================================
// Legacy handlers (kept for backwards compat with existing Crayonic CP)
// ============================================================================

BOOL CDdsAuthBridgeMain::HandleGetStatus(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId)
{
    IPC_RESP_STATUS resp = {};
    resp.serviceRunning  = TRUE;
    resp.deviceConnected = FALSE; // No BLE device manager
    resp.batteryLevel    = -1;
    resp.transport       = 0; // No hardware transport (DDS is cloud-mediated)

    wcscpy_s(resp.deviceName, L"DDS Auth Bridge (no hardware device)");

    return m_pipeServer.SendResponse(pClientCtx, IPC_MSG::STATUS, seqId,
        reinterpret_cast<const BYTE*>(&resp), sizeof(resp));
}

BOOL CDdsAuthBridgeMain::HandleListUsers(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId)
{
    const auto& entries = m_vault.GetEntries();

    // Build response: header + N user entries
    BYTE buffer[IPC_PIPE::BUFFER_SIZE];
    IPC_RESP_USER_LIST* pList = reinterpret_cast<IPC_RESP_USER_LIST*>(buffer);

    size_t maxUsers = (sizeof(buffer) - sizeof(IPC_RESP_USER_LIST)) / sizeof(IPC_USER_ENTRY);
    UINT32 count = static_cast<UINT32>((std::min)(entries.size(), maxUsers));
    pList->userCount = count;

    IPC_USER_ENTRY* pEntries = reinterpret_cast<IPC_USER_ENTRY*>(buffer + sizeof(IPC_RESP_USER_LIST));
    for (UINT32 i = 0; i < count; i++)
    {
        ZeroMemory(&pEntries[i], sizeof(IPC_USER_ENTRY));
        wcsncpy_s(pEntries[i].sid, entries[i].userSid.c_str(), _TRUNCATE);
        wcsncpy_s(pEntries[i].displayName, entries[i].displayName.c_str(), _TRUNCATE);
        pEntries[i].authMethod = entries[i].authMethod;
    }

    DWORD totalSize = sizeof(IPC_RESP_USER_LIST) + count * sizeof(IPC_USER_ENTRY);
    return m_pipeServer.SendResponse(pClientCtx, IPC_MSG::USER_LIST, seqId,
        buffer, totalSize);
}

BOOL CDdsAuthBridgeMain::HandleStartAuthFido(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId,
    _In_ const IPC_REQ_START_AUTH_FIDO* pReq)
{
    // For backwards compat, redirect to DDS auth flow
    FileLog::Write("StartAuthFido: redirecting to DDS auth flow\n");
    return HandleDdsStartAuth(pClientCtx, seqId,
        reinterpret_cast<const BYTE*>(pReq), sizeof(*pReq));
}

BOOL CDdsAuthBridgeMain::HandleCancelAuth(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId,
    _In_ const IPC_REQ_CANCEL_AUTH* pReq)
{
    EnterCriticalSection(&m_csAuth);

    if (m_activeAuth.hThread != NULL)
    {
        m_activeAuth.cancelled = TRUE;
        FileLog::Write("CancelAuth: cancellation flag set\n");
    }
    else
    {
        FileLog::Write("CancelAuth: no active auth to cancel\n");
    }

    LeaveCriticalSection(&m_csAuth);

    // Send acknowledgment
    IPC_RESP_AUTH_ERROR resp = {};
    resp.errorCode = IPC_ERROR::AUTH_CANCELLED;
    wcscpy_s(resp.message, L"Authentication cancelled");
    return m_pipeServer.SendResponse(pClientCtx, IPC_MSG::AUTH_ERROR, seqId,
        reinterpret_cast<const BYTE*>(&resp), sizeof(resp));
}

BOOL CDdsAuthBridgeMain::HandleEnrollUser(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId,
    _In_ const IPC_REQ_ENROLL_USER* pReq)
{
    // TODO: Enrollment via DDS will be handled differently -- for now
    // return an error indicating it must be done through the DDS enrollment flow.
    FileLog::Write("EnrollUser: DDS enrollment not yet implemented in bridge\n");

    IPC_RESP_ENROLL_RESULT result = {};
    result.success = FALSE;
    wcscpy_s(result.message, L"Enrollment must be performed through the DDS management portal.");

    return m_pipeServer.SendResponse(pClientCtx, IPC_MSG::ENROLL_RESULT, seqId,
        reinterpret_cast<const BYTE*>(&result), sizeof(result));
}

BOOL CDdsAuthBridgeMain::HandleUnenrollUser(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId,
    _In_ const IPC_REQ_UNENROLL_USER* pReq)
{
    std::wstring sid(pReq->sid);
    bool removed = m_vault.UnenrollUser(sid);

    IPC_RESP_ENROLL_RESULT result = {};
    result.success = removed ? TRUE : FALSE;
    wcscpy_s(result.message, removed
        ? L"Enrollment removed successfully."
        : L"No enrollment found for this user.");

    return m_pipeServer.SendResponse(pClientCtx, IPC_MSG::ENROLL_RESULT, seqId,
        reinterpret_cast<const BYTE*>(&result), sizeof(result));
}
