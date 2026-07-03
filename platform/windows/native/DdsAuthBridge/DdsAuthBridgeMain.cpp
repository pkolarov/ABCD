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
#include "ctap2/ctap_authenticator.h"  // raw-CTAP fallback (WebAuthn 0x8000401A)
#include <algorithm>
#include <ctime>
#include <string.h>
#include <lm.h>          // NetGetJoinInformation
#include <sddl.h>        // ConvertStringSidToSidW
#include <bcrypt.h>       // BCryptGenRandom for challenge
#include <winsvc.h>       // OpenSCManager / StartService for NgcSvc kick
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

// Make sure NgcSvc (Microsoft Passport) is running. WebAuthn on the secure
// desktop DCOM-activates a UI broker that depends on this service; with
// NgcSvc stopped, WebAuthNAuthenticatorGetAssertion fails immediately with
// CO_E_RUNAS_LOGON_FAILURE (0x8000401A) and the FIDO2 tile never reaches
// the security key. NgcSvc ships StartType=Manual and is otherwise only
// started on demand once a user session uses Hello — never from LogonUI.
//
// The WiX install also declares NgcSvc as a SCM dependency of this service,
// which handles new installs; this runtime call covers already-installed
// machines and the "service was stopped manually" recovery path.
static void EnsureNgcSvcRunning()
{
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm)
    {
        FileLog::Writef("DdsAuthBridge: EnsureNgcSvcRunning: OpenSCManager "
                        "failed gle=%lu\n", GetLastError());
        return;
    }

    SC_HANDLE hSvc = OpenServiceW(hScm, L"NgcSvc",
                                  SERVICE_QUERY_STATUS | SERVICE_START);
    if (!hSvc)
    {
        FileLog::Writef("DdsAuthBridge: EnsureNgcSvcRunning: OpenService "
                        "NgcSvc failed gle=%lu (service not present?)\n",
                        GetLastError());
        CloseServiceHandle(hScm);
        return;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD cbNeeded = 0;
    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<BYTE*>(&ssp), sizeof(ssp),
                             &cbNeeded))
    {
        if (ssp.dwCurrentState == SERVICE_RUNNING)
        {
            FileLog::Write("DdsAuthBridge: EnsureNgcSvcRunning: NgcSvc "
                           "already running\n");
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hScm);
            return;
        }
        FileLog::Writef("DdsAuthBridge: EnsureNgcSvcRunning: NgcSvc state=%lu "
                        "— starting\n", (unsigned long)ssp.dwCurrentState);
    }

    if (!StartServiceW(hSvc, 0, nullptr))
    {
        DWORD gle = GetLastError();
        // Treat already-running as success — race with another caller.
        if (gle == ERROR_SERVICE_ALREADY_RUNNING)
        {
            FileLog::Write("DdsAuthBridge: EnsureNgcSvcRunning: NgcSvc "
                           "already running (race)\n");
        }
        else
        {
            FileLog::Writef("DdsAuthBridge: EnsureNgcSvcRunning: StartService "
                            "NgcSvc failed gle=%lu\n", gle);
        }
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hScm);
        return;
    }

    // Poll until SERVICE_RUNNING or a short deadline. We don't block the
    // bridge's own startup on this — if NgcSvc takes too long, the WebAuthn
    // call will surface its own error on the next tile click.
    const DWORD start = GetTickCount();
    const DWORD deadline = start + 5000;
    while (GetTickCount() < deadline)
    {
        if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                 reinterpret_cast<BYTE*>(&ssp), sizeof(ssp),
                                 &cbNeeded) &&
            ssp.dwCurrentState == SERVICE_RUNNING)
        {
            FileLog::Writef("DdsAuthBridge: EnsureNgcSvcRunning: NgcSvc "
                            "RUNNING after %lu ms\n",
                            (unsigned long)(GetTickCount() - start));
            break;
        }
        Sleep(100);
    }
    if (ssp.dwCurrentState != SERVICE_RUNNING)
    {
        FileLog::Writef("DdsAuthBridge: EnsureNgcSvcRunning: NgcSvc did not "
                        "reach RUNNING within 5s (state=%lu) — proceeding\n",
                        (unsigned long)ssp.dwCurrentState);
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
}

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
    m_nextOpToken = 0;
    m_hCtapCancel = CreateEvent(NULL, TRUE, FALSE, NULL); // manual-reset
    InitializeCriticalSection(&m_csAuth);
    InitializeCriticalSection(&m_csCooldown);
}

CDdsAuthBridgeMain::~CDdsAuthBridgeMain()
{
    Shutdown();
    if (m_activeAuth.hResponseEvent)
        CloseHandle(m_activeAuth.hResponseEvent);
    if (m_hCtapCancel)
        CloseHandle(m_hCtapCancel);
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

    // Kick NgcSvc before anything else — see EnsureNgcSvcRunning() for the
    // full rationale. The WiX install declares NgcSvc as a SCM dependency
    // so this is a no-op on clean install boots, but the runtime call
    // covers already-installed machines and operator-stopped recovery.
    EnsureNgcSvcRunning();

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

    // Cancel any active auth operation and JOIN it to completion before we tear
    // down (the destructor deletes m_csAuth / closes the events right after). The
    // CTAP call is interruptible via m_hCtapCancel, so a worker blocked on the
    // user's touch aborts promptly. Signal under the lock, then join WITHOUT the
    // lock so the worker's own cleanup (which takes m_csAuth) can run.
    EnterCriticalSection(&m_csAuth);
    HANDLE oldThread = NULL;
    if (m_activeAuth.hThread != NULL)
    {
        m_activeAuth.cancelled = TRUE;
        SetEvent(m_activeAuth.hResponseEvent);
        SetEvent(m_hCtapCancel);
        oldThread = m_activeAuth.hThread;
        m_activeAuth.hThread = NULL;
    }
    LeaveCriticalSection(&m_csAuth);
    if (oldThread != NULL)
    {
        WaitForSingleObject(oldThread, 10000);
        CloseHandle(oldThread);
    }

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

    case IPC_MSG::DDS_CTAP_FALLBACK:
        // No payload — the seqId in the header identifies the in-flight auth.
        return pSelf->HandleDdsCtapFallback(pClientCtx, pHeader->seqId);

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
// Validates the request, selects the vault entry (or enters first-claim mode),
// and spawns a worker thread that runs the two-phase flow in ExecuteDdsAuth:
//
//   Phase 1 (Bridge → CP):
//     1. Fetch a server-issued FIDO2 challenge from dds-node.
//     2. Send DDS_AUTH_CHALLENGE to the CP with credential ID, RP ID,
//        hmac-secret salt, and the server challenge nonce.
//
//   Phase 2 (CP → Bridge, after CP calls WebAuthNAuthenticatorGetAssertion):
//     3. Receive DDS_AUTH_RESPONSE with the WebAuthn assertion + hmac-secret.
//     4. POST assertion proof to dds-node /v1/session/assert.
//     5. Use hmac-secret output to decrypt the stored password from the vault.
//     6. Return DDS_AUTH_COMPLETE with the password and session token.
// ============================================================================

BOOL CDdsAuthBridgeMain::HandleDdsStartAuth(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId,
    _In_ const BYTE* pPayload,
    _In_ DWORD payloadLen)
{
    FileLog::Writef("DdsStartAuth: seqId=%u payloadLen=%lu\n", seqId, payloadLen);

    // Per-challenge NgcSvc revive: the boot-time call in Initialize() only
    // covers the moment the bridge first starts. NgcSvc ships StartType=Manual
    // and on machines that never use Windows Hello it idle-times-out within
    // hours, after which every WebAuthn assertion from LogonUI fails instantly
    // with 0x8000401A. Re-checking here is ~1ms when running and self-heals
    // the operator-stopped/idle-timed-out case the commit log already calls
    // out — done outside m_csAuth so a slow start (≤5s) doesn't block other
    // CP requests. The WiX install also flips NgcSvc to Automatic as belt-
    // and-suspenders, but legacy installs and policy overrides reach here.
    EnsureNgcSvcRunning();

    // Stale-auth supersede: if a previous auth is still in flight (the
    // CP gave up on its short timeout while our worker is still waiting
    // for AUTH_RESPONSE), cancel the old worker so the new request can
    // proceed instead of returning DEVICE_BUSY. Without this, every
    // retry within the bridge's AUTH_TIMEOUT_MS window failed with
    // "Another authentication is in progress" — see DDS-#cp-stuck-auth.
    //
    // Old client context is already gone (its pipe call timed out and
    // disconnected), so we don't need to send an error back to it.
    EnterCriticalSection(&m_csAuth);
    if (m_activeAuth.hThread != NULL)
    {
        FileLog::Write("DdsStartAuth: cancelling stuck previous auth so new request can run\n");
        m_activeAuth.cancelled = TRUE;
        SetEvent(m_activeAuth.hResponseEvent); // wake a worker parked on the event
        SetEvent(m_hCtapCancel);               // abort a worker blocked in raw-CTAP HID I/O
        HANDLE oldThread = m_activeAuth.hThread;
        m_activeAuth.hThread = NULL; // claim the slot; worker will not double-close
        UINT64 oldToken = m_activeAuth.opToken;

        LeaveCriticalSection(&m_csAuth);
        // The CTAP call is now interruptible, so the old worker aborts promptly;
        // wait to completion so its cleanup runs before we reuse the slot. The
        // opToken guard in DdsAuthWorkerThread is the backstop if this ever times
        // out (the abandoned worker then leaves m_activeAuth untouched).
        (void)oldToken;
        WaitForSingleObject(oldThread, 10000);
        CloseHandle(oldThread);
        EnterCriticalSection(&m_csAuth);
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

    // AD-08: gate the auth path by JoinState *before* the WebAuthn ceremony so
    // an unsupported host or a missing vault entry never causes the user to
    // touch their key for a flow that will fail anyway. Spec §4.3 and the
    // PRE_ENROLLMENT_REQUIRED / UNSUPPORTED_HOST IPC errors carry the
    // canonical user-visible strings from §4.4.
    const dds::JoinState joinState = GetJoinState();
    if (joinState == dds::JoinState::EntraOnlyJoined ||
        joinState == dds::JoinState::Unknown)
    {
        LeaveCriticalSection(&m_csAuth);
        FileLog::Writef("DdsStartAuth: refusing — JoinState=%ls\n",
                        dds::JoinStateName(joinState));
        SendAuthError(pClientCtx, seqId, IPC_ERROR::UNSUPPORTED_HOST,
            L"DDS sign-in is not yet supported on Entra-joined machines.");
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
        // AD-08: AD/Hybrid hosts cannot bootstrap a local account, so refuse
        // before the FIDO2 ceremony with a specific PRE_ENROLLMENT_REQUIRED
        // error instead of letting the claim path run and fail later. The
        // generic in-claim domain-join check at the worker level becomes
        // dead code once this gate is in place.
        if (joinState != dds::JoinState::Workgroup)
        {
            LeaveCriticalSection(&m_csAuth);
            FileLog::Writef("DdsStartAuth: refusing claim — JoinState=%ls (no vault entry)\n",
                            dds::JoinStateName(joinState));
            SendAuthError(pClientCtx, seqId, IPC_ERROR::PRE_ENROLLMENT_REQUIRED,
                L"DDS sign-in is available only after enrollment on this AD-joined machine.");
            return TRUE;
        }

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
    // AUDIT-2026-06-11 #17: snapshot the initiating client's unique id so the
    // worker can verify the pipe slot still belongs to this client before
    // sending the decrypted password (the slot may be recycled if the client
    // disconnects during the wait).
    m_activeAuth.clientId = pClientCtx ? pClientCtx->clientId : 0;
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
    m_activeAuth.ctapFallback = FALSE;
    m_activeAuth.opToken = ++m_nextOpToken; // stamp this spawn; teardown checks it
    ResetEvent(m_activeAuth.hResponseEvent);
    ResetEvent(m_hCtapCancel);              // clear any prior cancel for the new op
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
// DDS_CTAP_FALLBACK handler — CP's WebAuthn hit 0x8000401A (pre-first-logon UX
// broker unavailable); ask the worker to perform the getAssertion itself via raw
// CTAP over HID. Just flags the active auth and wakes the worker (which owns the
// challenge details and does the assertion in ExecuteDdsAuth).
// ============================================================================

BOOL CDdsAuthBridgeMain::HandleDdsCtapFallback(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId)
{
    FileLog::Writef("DdsCtapFallback: seqId=%u — CP requested raw-CTAP getAssertion\n", seqId);

    EnterCriticalSection(&m_csAuth);
    // Validate BOTH the seqId and the sender identity: seqId is a per-connection
    // counter (not globally unique), so a stale/other SYSTEM pipe client could
    // otherwise match the active op's seqId and divert it onto the CTAP path.
    // Require the same client slot + clientId that initiated the auth, mirroring
    // the password-delivery identity check.
    if (m_activeAuth.hThread == NULL ||
        m_activeAuth.seqId != seqId ||
        pClientCtx == nullptr ||
        pClientCtx != m_activeAuth.pClientCtx ||
        pClientCtx->clientId != m_activeAuth.clientId)
    {
        LeaveCriticalSection(&m_csAuth);
        SendAuthError(pClientCtx, seqId, IPC_ERROR::SERVICE_ERROR,
            L"No active auth operation for CTAP fallback");
        return TRUE;
    }

    m_activeAuth.ctapFallback = TRUE;
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

    // Clean up — but ONLY if m_activeAuth still identifies THIS worker. If we were
    // superseded (a newer DDS_START_AUTH claimed the slot and already CloseHandle'd
    // our thread handle), m_activeAuth now belongs to the successor: closing its
    // handle or resetting its op would corrupt the in-flight successor. The
    // per-spawn opToken distinguishes us (a reset slot has opToken 0; our op's is
    // always >= 1). Preserve the response event handle across operations.
    EnterCriticalSection(&pSelf->m_csAuth);
    if (pSelf->m_activeAuth.opToken == op.opToken)
    {
        HANDLE hEvt = pSelf->m_activeAuth.hResponseEvent;
        if (pSelf->m_activeAuth.hThread != NULL)
            CloseHandle(pSelf->m_activeAuth.hThread);
        ResetAuthOperation(pSelf->m_activeAuth, hEvt);
    }
    LeaveCriticalSection(&pSelf->m_csAuth);

    // Wipe this thread's local copy of the response (contains the 32-byte
    // hmac-secret that unwraps the vault password) on every exit path.
    SecureZeroMemory(&op.responseData, sizeof(op.responseData));
    return 0;
}

// SHA-256 helper for the CTAP-fallback clientDataHash.
static bool Sha256Bytes(const uint8_t* data, size_t len, uint8_t out[32])
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return false;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0)))
    {
        if (BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0)) &&
            BCRYPT_SUCCESS(BCryptFinishHash(hHash, out, 32, 0)))
            ok = true;
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

bool CDdsAuthBridgeMain::RunCtapFallbackFill(_In_ AuthOperation* pOp,
    _In_ const IPC_RESP_DDS_AUTH_CHALLENGE* pChallenge)
{
    FileLog::Writef("DdsAuth.worker: seqId=%u CTAP fallback — raw getAssertion via HID\n", pOp->seqId);

    // Build clientDataJSON IDENTICALLY to the CP path (DdsBridgeClient.cpp) so the
    // server's assertion verification, which reconstructs it from the challenge +
    // origin, matches byte-for-byte.
    std::string rpId(pChallenge->rp_id, strnlen(pChallenge->rp_id, sizeof(pChallenge->rp_id)));
    std::string challengeB64(pChallenge->challenge_b64url,
        strnlen(pChallenge->challenge_b64url, sizeof(pChallenge->challenge_b64url)));
    if (rpId.empty() || challengeB64.empty())
    {
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::SERVICE_ERROR,
            L"CTAP fallback: missing rpId/challenge");
        return false;
    }
    std::string clientDataJson =
        "{\"type\":\"webauthn.get\",\"challenge\":\"" + challengeB64 +
        "\",\"origin\":\"https://" + rpId + "\"}";

    uint8_t clientDataHash[32];
    if (!Sha256Bytes(reinterpret_cast<const uint8_t*>(clientDataJson.data()),
                     clientDataJson.size(), clientDataHash))
    {
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::SERVICE_ERROR,
            L"CTAP fallback: clientDataHash failed");
        return false;
    }

    // Collect (credentialId, rawSalt) pairs — prefer the multi-credential list,
    // fall back to the legacy single fields.
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> creds;
    if (pChallenge->cred_count > 0)
    {
        DWORD n = pChallenge->cred_count;
        if (n > (DWORD)IPC_MAX_DDS_AUTH_CREDS) n = (DWORD)IPC_MAX_DDS_AUTH_CREDS;
        for (DWORD i = 0; i < n; ++i)
        {
            const IPC_DDS_AUTH_CRED& c = pChallenge->creds[i];
            if (c.credential_id_len == 0 || c.salt_len != 32) continue;
            DWORD idLen = (c.credential_id_len > sizeof(c.credential_id))
                              ? (DWORD)sizeof(c.credential_id) : c.credential_id_len;
            creds.emplace_back(
                std::vector<uint8_t>(c.credential_id, c.credential_id + idLen),
                std::vector<uint8_t>(c.salt, c.salt + 32));
        }
    }
    if (creds.empty())
    {
        DWORD idLen = (pChallenge->credential_id_len > sizeof(pChallenge->credential_id))
                          ? (DWORD)sizeof(pChallenge->credential_id) : pChallenge->credential_id_len;
        if (idLen > 0 && pChallenge->salt_len == 32)
            creds.emplace_back(
                std::vector<uint8_t>(pChallenge->credential_id, pChallenge->credential_id + idLen),
                std::vector<uint8_t>(pChallenge->salt, pChallenge->salt + 32));
    }
    if (creds.empty())
    {
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::NO_CREDENTIAL,
            L"CTAP fallback: no credential with a valid salt");
        return false;
    }

    SendAuthProgress(pOp->pClientCtx, pOp->seqId, IPC_AUTH_STATE::USER_PRESENCE,
        L"Touch your security key...");

    // Use a window strictly shorter than the CP's AUTH_TIMEOUT_MS budget, and make
    // the call interruptible via m_hCtapCancel (signaled by cancel/supersede/
    // shutdown) so it can't block for the full timeout after the user gives up.
    CtapAssertion a = CtapAuthenticator::GetAssertionWithHmac(
        rpId, clientDataHash, creds, IPC_PIPE::CTAP_FALLBACK_TIMEOUT_MS, m_hCtapCancel);
    if (!a.success)
    {
        FileLog::Writef("DdsAuth.worker: CTAP fallback failed: %s\n", a.error.c_str());
        UINT32 ec = IPC_ERROR::AUTH_FAILED;
        const wchar_t* msg = L"Security-key sign-in failed.";
        if (a.cancelled) { ec = IPC_ERROR::USER_CANCELLED; msg = L"Authentication cancelled"; }
        else if (a.timedOut) { ec = IPC_ERROR::AUTH_TIMEOUT; msg = L"Timed out waiting for your security key."; }
        else if (a.noCredentialPresent) { ec = IPC_ERROR::NO_CREDENTIAL; msg = L"Insert the enrolled security key and try again."; }
        SendAuthError(pOp->pClientCtx, pOp->seqId, ec, msg);
        return false;
    }

    // Fill pOp->responseData exactly as the CP's DDS_AUTH_RESPONSE would; the
    // downstream POST + vault-decrypt path is unchanged.
    IPC_REQ_DDS_AUTH_RESPONSE& r = pOp->responseData;
    ZeroMemory(&r, sizeof(r));
    DWORD adLen = (DWORD)(std::min)(a.authenticatorData.size(), sizeof(r.authenticator_data));
    memcpy(r.authenticator_data, a.authenticatorData.data(), adLen);
    r.authenticator_data_len = adLen;
    DWORD sgLen = (DWORD)(std::min)(a.signature.size(), sizeof(r.signature));
    memcpy(r.signature, a.signature.data(), sgLen);
    r.signature_len = sgLen;
    DWORD ciLen = (DWORD)(std::min)(a.credentialId.size(), sizeof(r.credential_id));
    memcpy(r.credential_id, a.credentialId.data(), ciLen);
    r.credential_id_len = ciLen;
    memcpy(r.hmac_secret, a.hmacSecret.data(), 32);
    r.hmac_secret_len = 32;
    memcpy(r.client_data_hash, clientDataHash, 32);
    strncpy_s(r.challenge_id, sizeof(r.challenge_id), pChallenge->challenge_id, _TRUNCATE);

    FileLog::Writef("DdsAuth.worker: CTAP fallback OK (uv=%d authDataLen=%u sigLen=%u)\n",
                    a.uvFlag, r.authenticator_data_len, r.signature_len);
    SecureZeroMemory(a.hmacSecret.data(), a.hmacSecret.size());
    return true;
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

    // Multi-credential auto-select: offer EVERY credential enrolled for this
    // Windows user so the authenticator can use whichever key is physically
    // present. The representative entry resolved above gives us the SID;
    // expand to all of the user's vault entries. Each carries its own
    // hmac-secret salt, which must travel with its credential_id (the password
    // blob is sealed under the hmac output derived from that salt). creds[0]
    // mirrors the legacy single fields. Claim mode (no vault entry) keeps
    // cred_count == 0, so the CP falls back to the single legacy fields.
    challenge.cred_count = 0;
    if (pVaultEntry)
    {
        std::vector<const VaultEntry*> userEntries =
            m_vault.FindByUserSid(pVaultEntry->userSid);
        for (const VaultEntry* e : userEntries)
        {
            if (challenge.cred_count >= IPC_MAX_DDS_AUTH_CREDS)
                break;
            if (!e || e->credentialId.empty())
                continue;
            IPC_DDS_AUTH_CRED& slot = challenge.creds[challenge.cred_count];
            const DWORD cl = static_cast<DWORD>(
                (std::min)(e->credentialId.size(), sizeof(slot.credential_id)));
            memcpy(slot.credential_id, e->credentialId.data(), cl);
            slot.credential_id_len = cl;
            const DWORD sl = static_cast<DWORD>(
                (std::min)(e->salt.size(), sizeof(slot.salt)));
            if (sl > 0)
                memcpy(slot.salt, e->salt.data(), sl);
            slot.salt_len = sl;
            challenge.cred_count++;
        }
        FileLog::Writef("DdsAuth.worker: offering %lu credential(s) for sid='%ls'\n",
                        (unsigned long)challenge.cred_count, pVaultEntry->userSid.c_str());
    }

    // Populate server challenge fields so the CP uses the server nonce in WebAuthn.
    strncpy_s(challenge.challenge_id, serverChallenge.challengeId.c_str(), _TRUNCATE);
    strncpy_s(challenge.challenge_b64url, serverChallenge.challengeB64url.c_str(), _TRUNCATE);

    FileLog::Writef("DdsAuth.worker: sending AUTH_CHALLENGE (credIdLen=%u saltLen=%u credCount=%lu challengeId='%s')\n",
                    credIdLen, saltLen, (unsigned long)challenge.cred_count, challenge.challenge_id);

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
    bool ctapFallback     = m_activeAuth.ctapFallback;
    if (m_activeAuth.responseReceived)
        memcpy(&pOp->responseData, &m_activeAuth.responseData, sizeof(pOp->responseData));
    LeaveCriticalSection(&m_csAuth);

    if (pOp->cancelled)
    {
        FileLog::Write("DdsAuth.worker: cancelled by client\n");
        // Tell the original client (CP) so its blocking AuthenticateDds()
        // call returns immediately. Without this the CP would still wait
        // for DDS_AUTH_COMPLETE for its own timeout, freezing the LogonUI
        // even though the bridge has already given up.
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::USER_CANCELLED,
            L"Authentication cancelled");
        return;
    }

    if (ctapFallback)
    {
        // The CP's WebAuthn call returned 0x8000401A — the Interactive-User UX
        // broker cannot activate before the first interactive logon of a boot.
        // Perform the getAssertion ourselves via raw CTAP over HID: the bridge
        // runs as LocalSystem in session 0 and can open the FIDO HID device
        // directly, with no UI broker. This fills pOp->responseData exactly as a
        // CP DDS_AUTH_RESPONSE would, then falls through to the normal
        // POST-to-node + vault-decrypt path below.
        if (!RunCtapFallbackFill(pOp, &challenge))
            return; // a specific error was already sent to the CP
        pOp->responseReceived = TRUE;
    }
    else
    {
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
    }

    const IPC_REQ_DDS_AUTH_RESPONSE* pResp = &pOp->responseData;
    FileLog::Writef("DdsAuth.worker: got AUTH_RESPONSE (authDataLen=%u sigLen=%u hmacLen=%u)\n",
                    pResp->authenticator_data_len, pResp->signature_len, pResp->hmac_secret_len);

    // AUDIT-2026-06-11 #19: the inner *_len fields are attacker-controllable
    // (a malicious CP, or anything that wins the pipe ACL) and are used below to
    // slice fixed-size arrays for Base64Url encoding into an outbound HTTP POST
    // and to build the used-credential vector. HandleDdsAuthResponse only checks
    // that the payload is at least sizeof(IPC_REQ_DDS_AUTH_RESPONSE); it does not
    // bound these inner lengths. Without this check a declared length larger than
    // its array would read past the field into adjacent bridge memory and
    // base64-encode it into the request body (info leak). Bound every inner
    // length against its actual array capacity and reject on overflow.
    if (pResp->authenticator_data_len > sizeof(pResp->authenticator_data) ||
        pResp->signature_len          > sizeof(pResp->signature)          ||
        pResp->credential_id_len      > sizeof(pResp->credential_id)      ||
        pResp->hmac_secret_len        > sizeof(pResp->hmac_secret))
    {
        FileLog::Writef("DdsAuth.worker: AUTH_RESPONSE inner length out of bounds "
                        "(authDataLen=%u sigLen=%u credIdLen=%u hmacLen=%u) — rejecting\n",
                        pResp->authenticator_data_len, pResp->signature_len,
                        pResp->credential_id_len, pResp->hmac_secret_len);
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::SERVICE_ERROR,
            L"Malformed authentication response");
        return;
    }

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
        // Tell the original client (CP) so its blocking AuthenticateDds()
        // call returns immediately. Without this the CP would still wait
        // for DDS_AUTH_COMPLETE for its own timeout, freezing the LogonUI
        // even though the bridge has already given up.
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::USER_CANCELLED,
            L"Authentication cancelled");
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
        // Multi-credential auto-select: the CP offered every credential
        // enrolled for this user and the authenticator signed with whichever
        // key it physically held — which may NOT be the representative entry
        // (`pVaultEntry`) the tile carried. The password blob and salt are
        // per-credential, so we MUST decrypt with the vault entry that matches
        // the credential the assertion actually used (pResp->credential_id),
        // not the representative. Re-resolve here; fall back to the
        // representative only if the lookup somehow misses.
        const VaultEntry* pUsedEntry = nullptr;
        {
            std::vector<uint8_t> usedCredId(
                pResp->credential_id,
                pResp->credential_id + pResp->credential_id_len);
            if (!usedCredId.empty())
                pUsedEntry = m_vault.FindByCredentialId(usedCredId);
        }
        if (!pUsedEntry)
        {
            FileLog::Write("DdsAuth.worker: used credential not in vault — "
                           "falling back to representative entry\n");
            pUsedEntry = pVaultEntry;
        }
        else if (pUsedEntry != pVaultEntry)
        {
            FileLog::Writef("DdsAuth.worker: authenticator used a different "
                            "enrolled credential than the tile's representative "
                            "(sid='%ls') — decrypting with the used entry\n",
                            pUsedEntry->userSid.c_str());
        }

        if (!CCredentialVault::DecryptPassword(pResp->hmac_secret, pResp->hmac_secret_len,
                                               *pUsedEntry, password))
        {
            FileLog::Write("DdsAuth.worker: password decryption failed (wrong key or corrupt vault)\n");
            SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::VAULT_ERROR,
                L"Failed to decrypt stored password — re-enrollment may be required");
            return;
        }

        // Keep the resolved SID consistent with the credential actually used.
        resolvedSid = pUsedEntry->userSid;

        FileLog::Write("DdsAuth.worker: password decrypted successfully\n");
    }
    else
    {
        SendAuthProgress(pOp->pClientCtx, pOp->seqId,
            IPC_AUTH_STATE::PROCESSING, L"Claiming local Windows account...");

        // AD-08: the JoinState gate now lives in HandleDdsStartAuth, which
        // refuses non-Workgroup claims with PRE_ENROLLMENT_REQUIRED /
        // UNSUPPORTED_HOST *before* the WebAuthn ceremony. Reaching the worker
        // in claim mode therefore implies a Workgroup host. Defence-in-depth:
        // re-check here so a future refactor that bypasses the start-auth
        // gate cannot silently fall back to the claim path on AD/Hybrid.
        if (GetJoinState() != dds::JoinState::Workgroup)
        {
            SendAuthError(pOp->pClientCtx, pOp->seqId,
                IPC_ERROR::PRE_ENROLLMENT_REQUIRED,
                L"DDS sign-in is available only after enrollment on this "
                L"AD-joined machine.");
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
        // AUDIT-2026-06-12 R4: never log password-derived data, in any form —
        // the exact plaintext length collapses the offline-cracking space and
        // was written here for every DDS logon (sibling of the #12 site).
        // Domain/username are non-secret routing context and stay.
        FileLog::Writef("DdsAuth.worker: domain='%s' username='%s'\n",
            domA, userA);
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

    // AUDIT-2026-06-11 #17: deliver the decrypted password ONLY if the pipe slot
    // still belongs to the client that initiated this auth. During the ~60s wait
    // the original client may have disconnected and its slot been recycled to a
    // different SYSTEM client; SendResponseToClient validates the unique clientId
    // under the server lock and refuses to send to a recycled/closed slot, so
    // one client's password can never be delivered to another.
    if (!m_pipeServer.SendResponseToClient(pOp->pClientCtx, pOp->clientId,
            IPC_MSG::DDS_AUTH_COMPLETE, pOp->seqId,
            reinterpret_cast<const BYTE*>(&result), sizeof(result)))
    {
        FileLog::Write("DdsAuth.worker: initiating client gone/recycled — "
                       "DDS_AUTH_COMPLETE withheld (password not delivered)\n");
    }

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

// AD-09: send a status-bearing IPC_RESP_DDS_USER_LIST with the supplied
// `entries`. `statusCode` follows the IPC_ERROR taxonomy (SUCCESS or one of
// UNSUPPORTED_HOST / PRE_ENROLLMENT_REQUIRED). `statusText` is a UI-ready wide
// string that the credential provider can surface verbatim. The response shape
// matches the DDS contract regardless of count, so legacy CP clients that only
// read `count` see no entries on unsupported hosts and the new field-aware CP
// can render the canonical §4.4 strings.
//
// The function is local to this translation unit because it owns the buffer
// management and the wire format of the response.
namespace {

struct StagedUserEntry
{
    std::wstring subjectUrn;
    std::wstring displayName;
    std::wstring credentialId; // base64url-encoded
};

// Extract the Windows-user grouping key (the SID) from a DDS subject URN.
// Enrollment uses the Windows SID as the Vouchsafe label, so the URN is
// `urn:vouchsafe:<SID>.<hash>` on the dds-node path and a bare SID on the
// vault-synthesis fallback path. Stripping the scheme prefix and taking the
// text up to the first '.' yields the SID in both cases (a SID never contains
// a '.'). Two enrollments of the same user therefore share a key.
std::wstring GroupKeyFromSubjectUrn(const std::wstring& urn)
{
    static const std::wstring kPrefix = L"urn:vouchsafe:";
    std::wstring s = urn;
    if (s.rfind(kPrefix, 0) == 0)
        s = s.substr(kPrefix.size());
    const size_t dot = s.find(L'.');
    if (dot != std::wstring::npos)
        s = s.substr(0, dot);
    return s;
}

// Collapse multiple enrollments of the same Windows user to a single tile.
// A user with several FIDO2 credentials (backup keys, or re-enrollments —
// every WebAuthn create() mints a fresh credential_id) shows up once. The
// auth flow then offers ALL of that user's credentials to the authenticator
// (see HandleDdsStartAuth's FindByUserSid expansion), which uses whichever
// key it holds. The kept entry's credential_id is only a representative the
// bridge uses to resolve the user's SID; every credential is offered at auth.
std::vector<StagedUserEntry> CollapseByUser(const std::vector<StagedUserEntry>& in)
{
    std::vector<StagedUserEntry> out;
    std::vector<std::wstring> seen;
    for (const auto& e : in)
    {
        const std::wstring key = GroupKeyFromSubjectUrn(e.subjectUrn);
        bool dup = false;
        for (const auto& k : seen)
        {
            if (k == key) { dup = true; break; }
        }
        if (dup)
            continue;
        seen.push_back(key);
        out.push_back(e);
    }
    return out;
}

BOOL SendDdsUserListResponse(
    CIpcPipeServer& pipeServer,
    IPC_CLIENT_CONTEXT* pClientCtx,
    UINT32 seqId,
    UINT32 statusCode,
    const wchar_t* statusText,
    const std::vector<StagedUserEntry>& entries)
{
    BYTE buffer[IPC_PIPE::BUFFER_SIZE]{};
    IPC_RESP_DDS_USER_LIST* pList = reinterpret_cast<IPC_RESP_DDS_USER_LIST*>(buffer);

    // Collapse multiple credentials of the same Windows user to one tile.
    // Every caller of this function funnels through here, so both the
    // dds-node and vault-synthesis paths get one-tile-per-user for free.
    const std::vector<StagedUserEntry> collapsed = CollapseByUser(entries);

    const size_t maxUsers =
        (sizeof(buffer) - sizeof(IPC_RESP_DDS_USER_LIST)) / sizeof(IPC_DDS_USER_ENTRY);
    const UINT32 count = static_cast<UINT32>((std::min)(collapsed.size(), maxUsers));

    pList->count = count;
    pList->status_code = statusCode;
    if (statusText && statusText[0] != L'\0')
        wcsncpy_s(pList->status_text, statusText, _TRUNCATE);

    IPC_DDS_USER_ENTRY* pEntries = reinterpret_cast<IPC_DDS_USER_ENTRY*>(
        buffer + sizeof(IPC_RESP_DDS_USER_LIST));
    for (UINT32 i = 0; i < count; ++i)
    {
        ZeroMemory(&pEntries[i], sizeof(IPC_DDS_USER_ENTRY));
        wcsncpy_s(pEntries[i].subject_urn,   collapsed[i].subjectUrn.c_str(),   _TRUNCATE);
        wcsncpy_s(pEntries[i].display_name,  collapsed[i].displayName.c_str(),  _TRUNCATE);
        wcsncpy_s(pEntries[i].credential_id, collapsed[i].credentialId.c_str(), _TRUNCATE);
    }

    const DWORD totalSize =
        sizeof(IPC_RESP_DDS_USER_LIST) + count * sizeof(IPC_DDS_USER_ENTRY);
    return pipeServer.SendResponse(
        pClientCtx, IPC_MSG::DDS_USER_LIST, seqId, buffer, totalSize);
}

} // namespace

BOOL CDdsAuthBridgeMain::HandleDdsListUsers(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT32 seqId)
{
    // AD-09: refuse Entra-only / Unknown hosts up front with a status-bearing
    // empty DDS_USER_LIST so CP can show the §4.4 unsupported text. An empty
    // vector alone is ambiguous — the new status_code carries the intent.
    const dds::JoinState joinState = GetJoinState();
    if (joinState == dds::JoinState::EntraOnlyJoined ||
        joinState == dds::JoinState::Unknown)
    {
        FileLog::Writef("DdsListUsers: refusing — JoinState=%ls\n",
                        dds::JoinStateName(joinState));
        return SendDdsUserListResponse(
            m_pipeServer, pClientCtx, seqId,
            IPC_ERROR::UNSUPPORTED_HOST,
            L"DDS sign-in is not yet supported on Entra-joined machines.",
            {});
    }

    FileLog::Write("DdsListUsers: fetching from dds-node\n");
    DdsEnrolledUsersResult result = m_httpClient.GetEnrolledUsers(m_config.DeviceUrn());

    // The vault is the source of truth for "this user can actually sign in
    // here". Refresh it once so the AD/Hybrid intersection (and the synthesized
    // fallback below) see any enrollments the tray agent just added.
    m_vault.Load();
    const auto& vaultEntries = m_vault.GetEntries();

    if (!result.success)
    {
        FileLog::Writef("DdsListUsers: dds-node request failed: %s\n",
                        result.errorMessage.c_str());

        // AD-09: the legacy fallback called HandleListUsers, which returned
        // IPC_MSG::USER_LIST — the DDS CP rejects that message type. Synthesize
        // DDS-shape entries from the vault so CP gets a usable list. Vault
        // does not persist DDS subject URNs, so fall back to the SID as a
        // local identifier (spec §4.1).
        std::vector<StagedUserEntry> synthesized;
        synthesized.reserve(vaultEntries.size());
        for (const auto& v : vaultEntries)
        {
            StagedUserEntry e;
            e.subjectUrn   = v.userSid;
            e.displayName  = v.displayName.empty() ? v.userSid : v.displayName;
            std::string b64 = Base64UrlEncode(v.credentialId.data(), v.credentialId.size());
            std::wstring b64w(b64.begin(), b64.end());
            e.credentialId = std::move(b64w);
            synthesized.push_back(std::move(e));
        }

        FileLog::Writef("DdsListUsers: synthesizing %zu user(s) from vault\n",
                        synthesized.size());
        return SendDdsUserListResponse(
            m_pipeServer, pClientCtx, seqId,
            IPC_ERROR::SUCCESS, L"", synthesized);
    }

    // AD-09: on AD/Hybrid hosts, intersect the dds-node user list with the
    // local vault by credential_id. Users without a vault entry on this
    // machine cannot complete a sign-in here — surfacing them produces
    // tiles that always fail with PRE_ENROLLMENT_REQUIRED. Workgroup hosts
    // continue to see the full list (they can still claim).
    const bool intersectWithVault =
        (joinState == dds::JoinState::AdJoined ||
         joinState == dds::JoinState::HybridJoined);

    std::vector<StagedUserEntry> staged;
    staged.reserve(result.users.size());
    for (const auto& u : result.users)
    {
        if (intersectWithVault)
        {
            std::vector<uint8_t> credIdBytes = Base64UrlDecode(u.credentialId);
            if (credIdBytes.empty() || m_vault.FindByCredentialId(credIdBytes) == nullptr)
            {
                continue;
            }
        }

        StagedUserEntry e;
        // Convert UTF-8 → UTF-16 with explicit length so the wide buffer is
        // correctly sized; the existing helper `wcsncpy_s` truncates on
        // overflow.
        wchar_t wbuf[IPC_MAX_URN_LEN]{};
        MultiByteToWideChar(CP_UTF8, 0, u.subjectUrn.c_str(), -1,
                            wbuf, _countof(wbuf));
        e.subjectUrn = wbuf;

        wchar_t dbuf[IPC_MAX_DISPLAY_NAME_LEN]{};
        MultiByteToWideChar(CP_UTF8, 0, u.displayName.c_str(), -1,
                            dbuf, _countof(dbuf));
        e.displayName = dbuf;

        wchar_t cbuf[IPC_MAX_CREDENTIAL_ID_LEN]{};
        MultiByteToWideChar(CP_UTF8, 0, u.credentialId.c_str(), -1,
                            cbuf, _countof(cbuf));
        e.credentialId = cbuf;

        staged.push_back(std::move(e));
    }

    FileLog::Writef("DdsListUsers: returning %zu user(s) from dds-node "
                    "(intersect=%d, joinState=%ls)\n",
                    staged.size(), intersectWithVault ? 1 : 0,
                    dds::JoinStateName(joinState));

    return SendDdsUserListResponse(
        m_pipeServer, pClientCtx, seqId,
        IPC_ERROR::SUCCESS, L"", staged);
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
        // Wake the worker immediately — without this, the worker stays
        // blocked in WaitForSingleObject(hResponseEvent, AUTH_TIMEOUT_MS)
        // until the full 60s timeout fires, which freezes the LogonUI
        // when the user presses Esc in the WebAuthn dialog.
        if (m_activeAuth.hResponseEvent != NULL)
            SetEvent(m_activeAuth.hResponseEvent);
        // Also abort an in-flight raw-CTAP getAssertion (the worker is blocked in
        // HID I/O, not on hResponseEvent, during the fallback).
        SetEvent(m_hCtapCancel);
        FileLog::Write("CancelAuth: cancellation flag set, worker signalled\n");
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
