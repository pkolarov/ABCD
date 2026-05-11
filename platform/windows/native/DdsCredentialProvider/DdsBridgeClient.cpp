// DdsBridgeClient.cpp
// High-level DDS Auth Bridge client for the Credential Provider DLL.
// Forked from Crayonic BridgeClient; PIV path removed, DDS auth path added.

#include "DdsBridgeClient.h"
#include <cstring>
#include <functional>
#include <vector>
#include <bcrypt.h>
#include <stdio.h>
#include <setupapi.h>
#include <hidsdi.h>

#pragma comment(lib, "webauthn.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")

// FIDO Alliance HID usage page for CTAPHID — every USB FIDO2 authenticator
// reports this on its HID interface (per CTAP2 spec §8.1.2).
static const USHORT FIDO_USAGE_PAGE = 0xF1D0;

// File logger shared with CDdsProvider.cpp — writes to C:\Temp\dds_cp.log.
// Declared here so every WebAuthn checkpoint reaches the on-disk log instead
// of only the debugger via OutputDebugString.
extern void CPLog(const char* fmt, ...);

// Hex-dump the first `n` bytes of a buffer into a caller-supplied string
// so CPLog lines stay single-line and grep-friendly.
static std::string HexPrefix(const uint8_t* data, size_t totalLen, size_t prefixLen)
{
    if (!data || totalLen == 0) return std::string();
    const size_t n = (totalLen < prefixLen) ? totalLen : prefixLen;
    std::string out;
    out.reserve(n * 2);
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i)
    {
        out.push_back(hex[(data[i] >> 4) & 0xF]);
        out.push_back(hex[data[i] & 0xF]);
    }
    return out;
}

// Compute SHA-256 of a buffer using BCrypt.
static bool Sha256(const uint8_t* data, size_t len, uint8_t outHash[32])
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return false;

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    status = BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(len), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptDestroyHash(hHash); BCryptCloseAlgorithmProvider(hAlg, 0); return false; }

    status = BCryptFinishHash(hHash, outHash, 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(status);
}

// Generate random bytes.
static bool GenRandom(uint8_t* buf, size_t len)
{
    return BCRYPT_SUCCESS(BCryptGenRandom(NULL, buf, static_cast<ULONG>(len),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// Base64url encode (no padding) for clientDataJSON challenge field.
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

CDdsBridgeClient::CDdsBridgeClient()
{
    InitializeCriticalSection(&m_csWebAuthn);
}

CDdsBridgeClient::~CDdsBridgeClient()
{
    m_client.Disconnect();
    DeleteCriticalSection(&m_csWebAuthn);
}

// Cross-thread cancel for an in-flight WebAuthn call. See header for
// rationale. Safe and idempotent: called from CDdsCredential's deselect /
// UnAdvise paths so when LogonUI tears down the tile (ESC, switch tile,
// device unplug detected externally) we don't sit blocked inside the
// platform API for the full 60s timeout.
void CDdsBridgeClient::CancelCurrentWebAuthn()
{
    GUID  guidCopy = {};
    BOOL  shouldCancel = FALSE;
    UINT32 seqIdCopy = 0;

    EnterCriticalSection(&m_csWebAuthn);
    if (m_webauthnInProgress)
    {
        guidCopy     = m_currentCancelId;
        seqIdCopy    = m_currentWebauthnSeqId;
        shouldCancel = TRUE;
    }
    LeaveCriticalSection(&m_csWebAuthn);

    if (!shouldCancel)
    {
        CPLog("CancelCurrentWebAuthn: no WebAuthn call in flight — no-op");
        return;
    }

    HRESULT hr = WebAuthNCancelCurrentOperation(&guidCopy);
    CPLog("CancelCurrentWebAuthn: seqId=%u WebAuthNCancelCurrentOperation hr=0x%08lX",
          seqIdCopy, (unsigned long)hr);
}

// Pre-flight: enumerate HID-class device interfaces and look for one
// whose top-level collection advertises the FIDO usage page (0xF1D0).
// Doesn't open the device for any I/O — just reads the preparsed HID
// capabilities. Returns TRUE if at least one FIDO HID authenticator is
// currently enumerated by Windows.
//
// Why not trust the WebAuthn API: when no FIDO HID is present, the API
// still enters the blocking "Insert your security key" UI and sits there
// for the full dwTimeoutMilliseconds (up to 60s) with no synchronous way
// for the caller to back out. Failing fast here gives the user immediate
// feedback and avoids a 60s lockup.
BOOL CDdsBridgeClient::AnyFidoHidDevicePresent()
{
    GUID hidGuid;
    HidD_GetHidGuid(&hidGuid);

    HDEVINFO hDev = SetupDiGetClassDevsW(
        &hidGuid, nullptr, nullptr,
        DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (hDev == INVALID_HANDLE_VALUE)
    {
        CPLog("AnyFidoHidDevicePresent: SetupDiGetClassDevs failed gle=%lu — "
              "treating as 'present' to avoid false negative",
              (unsigned long)GetLastError());
        return TRUE; // fail open — don't block login on a SetupAPI hiccup
    }

    BOOL found = FALSE;
    SP_DEVICE_INTERFACE_DATA ifData{};
    ifData.cbSize = sizeof(ifData);

    for (DWORD i = 0;
         !found && SetupDiEnumDeviceInterfaces(hDev, nullptr, &hidGuid, i, &ifData);
         ++i)
    {
        DWORD reqSize = 0;
        SetupDiGetDeviceInterfaceDetailW(hDev, &ifData, nullptr, 0, &reqSize, nullptr);
        if (reqSize == 0) continue;

        std::vector<BYTE> buf(reqSize);
        auto* detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buf.data());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        if (!SetupDiGetDeviceInterfaceDetailW(hDev, &ifData, detail, reqSize, nullptr, nullptr))
            continue;

        // Open with zero access mask — we only want to query, not read/write.
        HANDLE hHid = CreateFileW(
            detail->DevicePath, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (hHid == INVALID_HANDLE_VALUE)
            continue;

        PHIDP_PREPARSED_DATA pd = nullptr;
        if (HidD_GetPreparsedData(hHid, &pd))
        {
            HIDP_CAPS caps{};
            if (HidP_GetCaps(pd, &caps) == HIDP_STATUS_SUCCESS &&
                caps.UsagePage == FIDO_USAGE_PAGE)
            {
                found = TRUE;
            }
            HidD_FreePreparsedData(pd);
        }
        CloseHandle(hHid);
    }

    SetupDiDestroyDeviceInfoList(hDev);
    return found;
}

BOOL CDdsBridgeClient::EnsureConnected()
{
    if (m_client.IsConnected()) return TRUE;
    return m_client.Connect(IPC_PIPE::PIPE_CONNECT_MS);
}

// ============================================================================
// Status
// ============================================================================

BOOL CDdsBridgeClient::GetStatus(_Out_opt_ IPC_RESP_STATUS* pStatus)
{
    if (!EnsureConnected()) return FALSE;

    IPC_RESP_STATUS status{};
    BOOL ok = m_client.GetStatus(&status);
    if (ok && pStatus) *pStatus = status;

    if (!ok || !status.serviceRunning)
    {
        m_client.Disconnect();
        return FALSE;
    }
    return ok;
}

// ============================================================================
// GetStatusShort — short connect timeout for background poll thread
// ============================================================================
// This variant attempts to connect with a user-supplied short timeout (default
// 200 ms) so the poll thread never blocks the 5-second EnsureConnected() call
// and can be stopped quickly by CleanupSmartCardDetection().
BOOL CDdsBridgeClient::GetStatusShort(DWORD connectTimeoutMs,
                                      _Out_opt_ IPC_RESP_STATUS* pStatus)
{
    if (!m_client.IsConnected())
    {
        if (!m_client.Connect(connectTimeoutMs))
            return FALSE;
    }

    IPC_RESP_STATUS status{};
    BOOL ok = m_client.GetStatus(&status);
    if (ok && pStatus) *pStatus = status;

    if (!ok || !status.serviceRunning)
    {
        m_client.Disconnect();
        return FALSE;
    }
    return ok;
}

// ============================================================================
// DDS user enumeration
// ============================================================================

std::vector<DdsBridgeUser> CDdsBridgeClient::ListDdsUsers(PCWSTR deviceUrn)
{
    std::vector<DdsBridgeUser> result;
    if (!EnsureConnected()) return result;

    BYTE buf[IPC_PIPE::BUFFER_SIZE]{};
    INT32 count = m_client.ListDdsUsers(deviceUrn, buf, sizeof(buf));
    if (count <= 0) return result;

    // Payload starts after the 10-byte IPC_MESSAGE_HEADER.
    const BYTE* pPayload = buf + sizeof(IPC_MESSAGE_HEADER);
    const IPC_RESP_DDS_USER_LIST* pList =
        reinterpret_cast<const IPC_RESP_DDS_USER_LIST*>(pPayload);
    const IPC_DDS_USER_ENTRY* pEntries =
        reinterpret_cast<const IPC_DDS_USER_ENTRY*>(pPayload + sizeof(IPC_RESP_DDS_USER_LIST));

    UINT32 safeCount = static_cast<UINT32>(count);
    for (UINT32 i = 0; i < safeCount; ++i)
    {
        DdsBridgeUser u;
        u.subjectUrn   = pEntries[i].subject_urn;
        u.displayName  = pEntries[i].display_name;
        u.credentialId = pEntries[i].credential_id;
        result.push_back(u);
    }
    return result;
}

std::vector<DdsBridgeUser> CDdsBridgeClient::ListDdsUsersTimeout(PCWSTR deviceUrn, DWORD timeoutMs)
{
    std::vector<DdsBridgeUser> result;
    // Quick connect attempt with short timeout
    if (!m_client.IsConnected())
    {
        if (!m_client.Connect(timeoutMs))
            return result; // service not available within timeout
    }

    BYTE buf[IPC_PIPE::BUFFER_SIZE]{};
    INT32 count = m_client.ListDdsUsers(deviceUrn, buf, sizeof(buf));
    if (count <= 0) return result;

    // Payload starts after the 10-byte IPC_MESSAGE_HEADER.
    const BYTE* pPayload = buf + sizeof(IPC_MESSAGE_HEADER);
    const IPC_RESP_DDS_USER_LIST* pList =
        reinterpret_cast<const IPC_RESP_DDS_USER_LIST*>(pPayload);
    const IPC_DDS_USER_ENTRY* pEntries =
        reinterpret_cast<const IPC_DDS_USER_ENTRY*>(pPayload + sizeof(IPC_RESP_DDS_USER_LIST));

    UINT32 safeCount = static_cast<UINT32>(count);
    for (UINT32 i = 0; i < safeCount; ++i)
    {
        DdsBridgeUser u;
        u.subjectUrn   = pEntries[i].subject_urn;
        u.displayName  = pEntries[i].display_name;
        u.credentialId = pEntries[i].credential_id;
        result.push_back(u);
    }
    return result;
}

// ============================================================================
// Wait for DDS auth complete helper
// ============================================================================

DdsBridgeAuthResult CDdsBridgeClient::WaitForDdsAuthComplete(
    UINT32 seqId, DWORD timeoutMs,
    std::function<void(UINT32, PCWSTR)> progressCallback)
{
    DdsBridgeAuthResult result;
    const DWORD start    = GetTickCount();
    const DWORD deadline = start + timeoutMs;

    CPLog("WaitForDdsAuthComplete: seqId=%u timeoutMs=%lu", seqId, timeoutMs);

    while (true)
    {
        DWORD now       = GetTickCount();
        DWORD remaining = (now >= deadline) ? 0 : (deadline - now);
        if (remaining == 0)
        {
            CPLog("WaitForDdsAuthComplete: seqId=%u TIMEOUT after %lu ms",
                  seqId, (unsigned long)(now - start));
            result.errorMessage = L"Authentication timed out";
            result.errorCode    = IPC_ERROR::AUTH_TIMEOUT;
            return result;
        }

        IPC_MESSAGE_HEADER hdr{};
        BYTE buf[IPC_PIPE::BUFFER_SIZE]{};
        DWORD bytesRead = 0;

        BOOL ok = m_client.ReadMessage(&hdr, buf, sizeof(buf), &bytesRead, min(remaining, 2000));
        if (!ok)
        {
            // Timeout on this read — keep waiting if overall deadline not passed
            continue;
        }

        if (hdr.seqId != seqId && hdr.seqId != 0)
        {
            CPLog("WaitForDdsAuthComplete: seqId=%u IGNORING msgType=%u from seqId=%u",
                  seqId, (unsigned)hdr.msgType, hdr.seqId);
            continue;
        }

        // ReadMessage fills `buf` with the RAW FRAME (10-byte header +
        // payload). The payload starts sizeof(IPC_MESSAGE_HEADER) bytes
        // into buf.
        const BYTE* payload    = buf + sizeof(IPC_MESSAGE_HEADER);
        const DWORD payloadLen =
            (bytesRead >= sizeof(IPC_MESSAGE_HEADER))
                ? (bytesRead - (DWORD)sizeof(IPC_MESSAGE_HEADER))
                : 0u;

        switch (hdr.msgType)
        {
        case IPC_MSG::DDS_AUTH_PROGRESS:
            if (payloadLen >= sizeof(IPC_RESP_DDS_AUTH_PROGRESS))
            {
                const IPC_RESP_DDS_AUTH_PROGRESS* prog =
                    reinterpret_cast<const IPC_RESP_DDS_AUTH_PROGRESS*>(payload);
                if (progressCallback)
                    progressCallback(prog->state, prog->message);
            }
            break;

        case IPC_MSG::DDS_AUTH_CHALLENGE:
            if (payloadLen >= sizeof(IPC_RESP_DDS_AUTH_CHALLENGE))
            {
                const IPC_RESP_DDS_AUTH_CHALLENGE* pChallenge =
                    reinterpret_cast<const IPC_RESP_DDS_AUTH_CHALLENGE*>(payload);

                CPLog("WaitForDdsAuthComplete: seqId=%u DDS_AUTH_CHALLENGE received "
                      "(rp='%s' credIdLen=%u saltLen=%u challengeIdLen=%zu) "
                      "after %lu ms — dispatching to WebAuthn",
                      seqId,
                      pChallenge->rp_id,
                      (unsigned)pChallenge->credential_id_len,
                      (unsigned)pChallenge->salt_len,
                      strnlen(pChallenge->challenge_id, sizeof(pChallenge->challenge_id)),
                      (unsigned long)(GetTickCount() - start));

                if (!HandleWebAuthnChallenge(seqId, pChallenge, result))
                {
                    // HandleWebAuthnChallenge already filled result.error*
                    CPLog("WaitForDdsAuthComplete: seqId=%u HandleWebAuthnChallenge returned FALSE "
                          "(errorCode=%d) — bailing out",
                          seqId, (int)result.errorCode);
                    return result;
                }
                // WebAuthn succeeded and DDS_AUTH_RESPONSE sent — continue waiting for AUTH_COMPLETE
                CPLog("WaitForDdsAuthComplete: seqId=%u WebAuthn OK, waiting for DDS_AUTH_COMPLETE",
                      seqId);
                if (progressCallback)
                    progressCallback(IPC_AUTH_STATE::PROCESSING, L"Verifying with DDS node...");
            }
            else
            {
                CPLog("WaitForDdsAuthComplete: seqId=%u DDS_AUTH_CHALLENGE payload too small "
                      "(got %lu, need %zu)",
                      seqId, (unsigned long)payloadLen, sizeof(IPC_RESP_DDS_AUTH_CHALLENGE));
            }
            break;

        case IPC_MSG::DDS_AUTH_COMPLETE:
            if (payloadLen >= sizeof(IPC_RESP_DDS_AUTH_COMPLETE))
            {
                const IPC_RESP_DDS_AUTH_COMPLETE* complete =
                    reinterpret_cast<const IPC_RESP_DDS_AUTH_COMPLETE*>(payload);
                if (complete->success)
                {
                    CPLog("WaitForDdsAuthComplete: seqId=%u DDS_AUTH_COMPLETE success=true "
                          "(pwdLen=%zu tokenLen=%zu) after %lu ms",
                          seqId,
                          wcsnlen(complete->password, IPC_MAX_PASSWORD_LEN),
                          strnlen(complete->session_token, IPC_MAX_SESSION_TOKEN_LEN),
                          (unsigned long)(GetTickCount() - start));
                    result.success         = true;
                    result.domain          = complete->domain;
                    result.username        = complete->username;
                    result.password        = complete->password;
                    result.sessionTokenB64 = complete->session_token;
                    result.subjectUrn      = complete->subject_urn;
                    result.expiresAt       = complete->expires_at;
                }
                else
                {
                    CPLog("WaitForDdsAuthComplete: seqId=%u DDS_AUTH_COMPLETE success=false "
                          "after %lu ms",
                          seqId, (unsigned long)(GetTickCount() - start));
                    result.errorCode    = IPC_ERROR::AUTH_FAILED;
                    result.errorMessage = L"DDS authentication failed";
                }
            }
            return result;

        case IPC_MSG::DDS_AUTH_ERROR:
            if (payloadLen >= sizeof(IPC_RESP_DDS_AUTH_ERROR))
            {
                const IPC_RESP_DDS_AUTH_ERROR* err =
                    reinterpret_cast<const IPC_RESP_DDS_AUTH_ERROR*>(payload);
                char msgA[256]{};
                WideCharToMultiByte(CP_UTF8, 0, err->message, -1, msgA, sizeof(msgA), NULL, NULL);
                CPLog("WaitForDdsAuthComplete: seqId=%u DDS_AUTH_ERROR errorCode=%d msg='%s' "
                      "after %lu ms",
                      seqId, (int)err->error_code, msgA,
                      (unsigned long)(GetTickCount() - start));
                result.errorCode    = err->error_code;
                result.errorMessage = err->message;
            }
            else
            {
                CPLog("WaitForDdsAuthComplete: seqId=%u DDS_AUTH_ERROR payload too small "
                      "(got %lu) — treating as SERVICE_ERROR",
                      seqId, (unsigned long)payloadLen);
                result.errorCode    = IPC_ERROR::SERVICE_ERROR;
                result.errorMessage = L"Unknown DDS error";
            }
            return result;

        default:
            break; // ignore unrelated messages
        }
    }
}

// ============================================================================
// Wait for auth complete helper (legacy Crayonic FIDO2 path)
// ============================================================================

DdsBridgeAuthResult CDdsBridgeClient::WaitForAuthComplete(
    UINT32 seqId, DWORD timeoutMs,
    std::function<void(UINT32, PCWSTR)> progressCallback)
{
    DdsBridgeAuthResult result;
    const DWORD deadline = GetTickCount() + timeoutMs;

    while (true)
    {
        DWORD now       = GetTickCount();
        DWORD remaining = (now >= deadline) ? 0 : (deadline - now);
        if (remaining == 0)
        {
            result.errorMessage = L"Authentication timed out";
            result.errorCode    = IPC_ERROR::AUTH_TIMEOUT;
            return result;
        }

        IPC_MESSAGE_HEADER hdr{};
        BYTE buf[IPC_PIPE::BUFFER_SIZE]{};
        DWORD bytesRead = 0;

        BOOL ok = m_client.ReadMessage(&hdr, buf, sizeof(buf), &bytesRead, min(remaining, 2000));
        if (!ok)
        {
            // Timeout on this read — keep waiting if overall deadline not passed
            continue;
        }

        if (hdr.seqId != seqId && hdr.seqId != 0)
        {
            // Not our response — ignore
            continue;
        }

        // ReadMessage fills `buf` with the RAW FRAME (10-byte header +
        // payload). The payload starts sizeof(IPC_MESSAGE_HEADER) bytes
        // into buf. Casting buf itself to a response struct silently
        // reads the header bytes as the first fields of the struct,
        // producing garbage. Always work off payload+payloadLen.
        const BYTE* payload    = buf + sizeof(IPC_MESSAGE_HEADER);
        const DWORD payloadLen =
            (bytesRead >= sizeof(IPC_MESSAGE_HEADER))
                ? (bytesRead - (DWORD)sizeof(IPC_MESSAGE_HEADER))
                : 0u;

        switch (hdr.msgType)
        {
        case IPC_MSG::AUTH_PROGRESS:
            if (payloadLen >= sizeof(IPC_RESP_AUTH_PROGRESS))
            {
                const IPC_RESP_AUTH_PROGRESS* prog =
                    reinterpret_cast<const IPC_RESP_AUTH_PROGRESS*>(payload);
                if (progressCallback)
                    progressCallback(prog->state, prog->message);
            }
            break;

        case IPC_MSG::AUTH_COMPLETE:
            if (payloadLen >= sizeof(IPC_RESP_AUTH_COMPLETE_FIDO))
            {
                const IPC_RESP_AUTH_COMPLETE_FIDO* complete =
                    reinterpret_cast<const IPC_RESP_AUTH_COMPLETE_FIDO*>(payload);
                if (complete->success)
                {
                    result.success  = true;
                    result.domain   = complete->domain;
                    result.username = complete->username;
                    result.password = complete->password;
                }
                else
                {
                    result.errorCode    = IPC_ERROR::AUTH_FAILED;
                    result.errorMessage = L"Authentication failed";
                }
            }
            return result;

        case IPC_MSG::AUTH_ERROR:
            if (payloadLen >= sizeof(IPC_RESP_AUTH_ERROR))
            {
                const IPC_RESP_AUTH_ERROR* err =
                    reinterpret_cast<const IPC_RESP_AUTH_ERROR*>(payload);
                result.errorCode    = err->errorCode;
                result.errorMessage = err->message;
            }
            else
            {
                result.errorCode    = IPC_ERROR::SERVICE_ERROR;
                result.errorMessage = L"Unknown error";
            }
            return result;

        default:
            break; // ignore unrelated messages
        }
    }
}

// ============================================================================
// WebAuthn platform API call
// ============================================================================

bool CDdsBridgeClient::HandleWebAuthnChallenge(
    UINT32 seqId,
    const IPC_RESP_DDS_AUTH_CHALLENGE* pChallenge,
    DdsBridgeAuthResult& result)
{
    const DWORD fnStart = GetTickCount();

    CPLog("HandleWebAuthnChallenge: seqId=%u ENTER (credIdLen=%u saltLen=%u "
          "rp='%s' challengeB64Len=%zu challengeIdLen=%zu)",
          seqId,
          (unsigned)pChallenge->credential_id_len,
          (unsigned)pChallenge->salt_len,
          pChallenge->rp_id,
          strnlen(pChallenge->challenge_b64url, sizeof(pChallenge->challenge_b64url)),
          strnlen(pChallenge->challenge_id, sizeof(pChallenge->challenge_id)));

    // Check WebAuthn API availability
    DWORD apiVersion = WebAuthNGetApiVersionNumber();
    CPLog("HandleWebAuthnChallenge: seqId=%u WebAuthNGetApiVersionNumber=%lu",
          seqId, (unsigned long)apiVersion);
    if (apiVersion < WEBAUTHN_API_VERSION_1)
    {
        CPLog("HandleWebAuthnChallenge: seqId=%u FAIL — WebAuthn API not available "
              "(version=%lu < %d)",
              seqId, (unsigned long)apiVersion, (int)WEBAUTHN_API_VERSION_1);
        result.errorCode = IPC_ERROR::SERVICE_ERROR;
        result.errorMessage = L"WebAuthn API not available on this system";
        return false;
    }

    // Probe whether a platform/user-verifying platform authenticator is even
    // reachable.  Useful for diagnosing post-reboot failures where the FIDO2
    // HID driver hasn't enumerated yet — the answer can flip between calls.
    BOOL uvpaAvailable = FALSE;
    HRESULT hrProbe = WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&uvpaAvailable);
    CPLog("HandleWebAuthnChallenge: seqId=%u UVPA probe hr=0x%08lX available=%d",
          seqId, (unsigned long)hrProbe, uvpaAvailable ? 1 : 0);

    // Pre-flight: refuse to enter the blocking WebAuthn API if no FIDO HID
    // authenticator is currently enumerated by Windows. Without this check,
    // a user who selects the FIDO2 tile without their security key plugged
    // in spends 60s staring at "Insert your security key" with no working
    // ESC path (Windows' own dialog ignores ESC in that state).
    if (!AnyFidoHidDevicePresent())
    {
        CPLog("HandleWebAuthnChallenge: seqId=%u FAIL — no FIDO HID device "
              "enumerated, refusing to enter blocking WebAuthn call",
              seqId);
        result.errorCode    = IPC_ERROR::DEVICE_NOT_FOUND;
        result.errorMessage = L"Insert your security key and try again.";

        // Wake the bridge worker so it doesn't sit on its own AUTH_TIMEOUT_MS
        // — same pattern as the post-WebAuthn cancel path below.
        IPC_REQ_CANCEL_AUTH cancelReq = {};
        cancelReq.targetSeqId = seqId;
        m_client.SendMessageWithSeqId(
            IPC_MSG::CANCEL_AUTH, seqId,
            reinterpret_cast<const BYTE*>(&cancelReq), sizeof(cancelReq));
        return false;
    }
    CPLog("HandleWebAuthnChallenge: seqId=%u pre-flight: FIDO HID device "
          "present", seqId);

    // Use the server-issued challenge forwarded by the Bridge over IPC.
    // Do NOT generate a local random challenge — the server has already stored
    // this nonce and will consume it during /v1/session/assert verification.
    std::string challengeB64(pChallenge->challenge_b64url,
        strnlen(pChallenge->challenge_b64url, sizeof(pChallenge->challenge_b64url)));
    if (challengeB64.empty())
    {
        CPLog("HandleWebAuthnChallenge: seqId=%u FAIL — empty server challenge", seqId);
        result.errorCode = IPC_ERROR::SERVICE_ERROR;
        result.errorMessage = L"Bridge did not supply a server challenge";
        return false;
    }

    // Use the enrolled RP ID for the origin — must exactly match what the server
    // enrolled and what verify_assertion_common reconstructs for hash comparison.
    std::string rpIdStr(pChallenge->rp_id,
        strnlen(pChallenge->rp_id, sizeof(pChallenge->rp_id)));

    // Construct clientDataJSON.  Field order and whitespace must be identical to
    // what the server reconstructs in service.rs::verify_assertion_common:
    //   {"type":"webauthn.get","challenge":"<43-char-b64url>","origin":"https://<rpId>"}
    std::string clientDataJson = "{\"type\":\"webauthn.get\",\"challenge\":\"" +
        challengeB64 + "\",\"origin\":\"https://" + rpIdStr + "\"}";

    CPLog("HandleWebAuthnChallenge: seqId=%u clientDataJSON len=%zu json='%s'",
          seqId, clientDataJson.size(), clientDataJson.c_str());

    // Compute SHA-256 of clientDataJSON — this is what dds-node needs
    uint8_t clientDataHash[32]{};
    if (!Sha256(reinterpret_cast<const uint8_t*>(clientDataJson.data()),
                clientDataJson.size(), clientDataHash))
    {
        CPLog("HandleWebAuthnChallenge: seqId=%u FAIL — Sha256(clientDataJson) returned false",
              seqId);
        result.errorCode = IPC_ERROR::SERVICE_ERROR;
        result.errorMessage = L"Failed to compute clientDataHash";
        return false;
    }

    {
        std::string hashHex = HexPrefix(clientDataHash, 32, 32);
        CPLog("HandleWebAuthnChallenge: seqId=%u clientDataHash=%s", seqId, hashHex.c_str());
    }

    {
        // First 8 bytes of credId + salt — enough to correlate against the bridge
        // and the vault entry without dumping the full credential material.
        std::string credPrefix =
            HexPrefix(pChallenge->credential_id, pChallenge->credential_id_len, 8);
        std::string saltPrefix =
            HexPrefix(pChallenge->salt, pChallenge->salt_len, 8);
        CPLog("HandleWebAuthnChallenge: seqId=%u credId[0..8]=%s salt[0..8]=%s",
              seqId, credPrefix.c_str(), saltPrefix.c_str());
    }

    WEBAUTHN_CLIENT_DATA clientData = {};
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = static_cast<DWORD>(clientDataJson.size());
    clientData.pbClientDataJSON = reinterpret_cast<PBYTE>(
        const_cast<char*>(clientDataJson.data()));
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // Build allow list with the specific credential ID
    // Must use CredentialList (inline WEBAUTHN_CREDENTIALS) — not pAllowCredentialList —
    // to match the enrollment flow exactly. Using pAllowCredentialList + different flags
    // causes the Windows WebAuthn API to produce different hmac-secret output.
    WEBAUTHN_CREDENTIAL allowCred = {};
    allowCred.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
    allowCred.cbId = pChallenge->credential_id_len;
    allowCred.pbId = const_cast<PBYTE>(pChallenge->credential_id);
    allowCred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

    WEBAUTHN_CREDENTIALS allowList = {};
    allowList.cCredentials = 1;
    allowList.pCredentials = &allowCred;

    // Build hmac-secret salt — must match enrollment's approach exactly:
    // both pGlobalHmacSalt AND per-credential salt with cCredWithHmacSecretSaltList=1
    WEBAUTHN_HMAC_SECRET_SALT hmacSalt = {};
    hmacSalt.cbFirst = pChallenge->salt_len;
    hmacSalt.pbFirst = const_cast<PBYTE>(pChallenge->salt);
    hmacSalt.cbSecond = 0;
    hmacSalt.pbSecond = nullptr;

    WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT credSalt = {};
    credSalt.cbCredID = pChallenge->credential_id_len;
    credSalt.pbCredID = const_cast<PBYTE>(pChallenge->credential_id);
    credSalt.pHmacSecretSalt = &hmacSalt;

    WEBAUTHN_HMAC_SECRET_SALT_VALUES hmacSaltValues = {};
    hmacSaltValues.pGlobalHmacSalt = &hmacSalt;
    hmacSaltValues.cCredWithHmacSecretSaltList = 1;
    hmacSaltValues.pCredWithHmacSecretSaltList = &credSalt;

    // Convert RP ID to wide string
    wchar_t rpIdW[IPC_MAX_RPID_LEN]{};
    MultiByteToWideChar(CP_UTF8, 0, pChallenge->rp_id, -1, rpIdW, IPC_MAX_RPID_LEN);

    // Build GetAssertion options — must match enrollment exactly:
    // CURRENT_VERSION, CredentialList (not pAllowCredentialList), DISCOURAGED, no dwFlags
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = {};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.CredentialList = allowList;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
    options.pHmacSecretSaltValues = &hmacSaltValues;

    CPLog("HandleWebAuthnChallenge: seqId=%u options dwVersion=%lu timeoutMs=%lu "
          "cCredentials=%lu uv=%d (DISCOURAGED) hmacSalts=1/%lu rpIdW='%ls'",
          seqId,
          (unsigned long)options.dwVersion,
          (unsigned long)options.dwTimeoutMilliseconds,
          (unsigned long)options.CredentialList.cCredentials,
          (int)options.dwUserVerificationRequirement,
          (unsigned long)hmacSaltValues.cCredWithHmacSecretSaltList,
          rpIdW);

    // Use a cancellation GUID so the CP can abort if needed
    GUID cancelId = {};
    HRESULT hrCancel = WebAuthNGetCancellationId(&cancelId);
    if (SUCCEEDED(hrCancel))
    {
        options.pCancellationId = &cancelId;
        CPLog("HandleWebAuthnChallenge: seqId=%u cancellation GUID acquired "
              "{%08lX-%04X-%04X-...}",
              seqId, (unsigned long)cancelId.Data1,
              (unsigned)cancelId.Data2, (unsigned)cancelId.Data3);

        // Publish under the lock so CancelCurrentWebAuthn() (called from
        // CDdsCredential::SetDeselected / UnAdvise on a different thread)
        // can find this GUID and call WebAuthNCancelCurrentOperation,
        // unblocking the platform API. Cleared in the post-call block
        // below regardless of success/failure.
        EnterCriticalSection(&m_csWebAuthn);
        m_currentCancelId       = cancelId;
        m_currentWebauthnSeqId  = seqId;
        m_webauthnInProgress    = TRUE;
        LeaveCriticalSection(&m_csWebAuthn);
    }
    else
    {
        CPLog("HandleWebAuthnChallenge: seqId=%u WebAuthNGetCancellationId FAILED hr=0x%08lX "
              "— continuing without cancellation GUID (cross-thread cancel "
              "will be unavailable for this attempt)",
              seqId, (unsigned long)hrCancel);
    }

    // Call WebAuthNAuthenticatorGetAssertion
    // The CP runs inside LogonUI.exe on the secure desktop, so GetForegroundWindow()
    // gives us the correct HWND for the WebAuthn UI prompt.
    HWND hWndFg = GetForegroundWindow();
    HWND hWndDt = GetDesktopWindow();
    HWND hWnd   = hWndFg ? hWndFg : hWndDt;
    CPLog("HandleWebAuthnChallenge: seqId=%u hWnd fg=%p desktop=%p using=%p (visible=%d) "
          "session=%lu",
          seqId, (void*)hWndFg, (void*)hWndDt, (void*)hWnd,
          hWnd ? IsWindowVisible(hWnd) : 0,
          (unsigned long)GetCurrentProcessId());

    PWEBAUTHN_ASSERTION pAssertion = nullptr;

    const DWORD callStart = GetTickCount();
    CPLog("HandleWebAuthnChallenge: seqId=%u >>> WebAuthNAuthenticatorGetAssertion CALL",
          seqId);

    HRESULT hr = WebAuthNAuthenticatorGetAssertion(
        hWnd,
        rpIdW,
        &clientData,
        &options,
        &pAssertion);

    const DWORD callElapsed = GetTickCount() - callStart;
    const DWORD gleAfter   = GetLastError();
    CPLog("HandleWebAuthnChallenge: seqId=%u <<< WebAuthNAuthenticatorGetAssertion RETURN "
          "hr=0x%08lX pAssertion=%p elapsed=%lu ms GetLastError=%lu",
          seqId, (unsigned long)hr, (void*)pAssertion,
          (unsigned long)callElapsed, (unsigned long)gleAfter);

    // Tear down the cross-thread cancel state right away — the call is done,
    // any further CancelCurrentWebAuthn() invocation should be a no-op.
    EnterCriticalSection(&m_csWebAuthn);
    m_webauthnInProgress    = FALSE;
    m_currentWebauthnSeqId  = 0;
    m_currentCancelId       = GUID{};
    LeaveCriticalSection(&m_csWebAuthn);

    if (FAILED(hr) || pAssertion == nullptr)
    {
        // Common case: user pressed Esc / Cancel in the WebAuthn OS prompt
        // (NTE_USER_CANCELLED / WEBAUTHN_HRESULT_CANCELLED). Send an explicit
        // CANCEL_AUTH to the bridge so it wakes its worker immediately
        // instead of blocking the CP for the full AUTH_TIMEOUT_MS — that's
        // what makes the LogonUI feel frozen for ~60 seconds when the user
        // bails out of FIDO2 to try password sign-in.
        PCWSTR webauthnErrName = WebAuthNGetErrorName(hr);
        char errNameA[128]{};
        if (webauthnErrName)
            WideCharToMultiByte(CP_UTF8, 0, webauthnErrName, -1,
                                errNameA, sizeof(errNameA), NULL, NULL);
        else
            strcpy_s(errNameA, "<null>");

        CPLog("HandleWebAuthnChallenge: seqId=%u WebAuthn FAIL hr=0x%08lX (low16=0x%04lX) "
              "errName='%s' elapsed=%lu ms — sending CANCEL_AUTH to bridge",
              seqId, (unsigned long)hr,
              (unsigned long)(hr & 0x0000FFFF),
              errNameA,
              (unsigned long)callElapsed);

        IPC_REQ_CANCEL_AUTH cancelReq = {};
        cancelReq.targetSeqId = seqId;
        BOOL cancelSent = m_client.SendMessageWithSeqId(
            IPC_MSG::CANCEL_AUTH, seqId,
            reinterpret_cast<const BYTE*>(&cancelReq), sizeof(cancelReq));
        CPLog("HandleWebAuthnChallenge: seqId=%u CANCEL_AUTH sent=%d", seqId, (int)cancelSent);

        // Map cancellation to USER_CANCELLED specifically so the CP can
        // distinguish "user gave up" from a real auth failure. Everything
        // else is still AUTH_FAILED.
        const bool isUserCancel =
            hr == HRESULT_FROM_WIN32(ERROR_CANCELLED) ||
            hr == HRESULT_FROM_WIN32(ERROR_TIMEOUT)   ||
            (hr & 0x0000FFFF) == ERROR_CANCELLED;
        result.errorCode = isUserCancel ? IPC_ERROR::USER_CANCELLED
                                        : IPC_ERROR::AUTH_FAILED;

        CPLog("HandleWebAuthnChallenge: seqId=%u classified as %s "
              "(elapsed<100ms=%d  pAssertion==nullptr=%d)",
              seqId,
              isUserCancel ? "USER_CANCELLED" : "AUTH_FAILED",
              callElapsed < 100 ? 1 : 0,
              pAssertion == nullptr ? 1 : 0);

        wchar_t errMsg[256];
        if (isUserCancel) {
            swprintf_s(errMsg, L"Cancelled. Try again or use a different sign-in.");
        } else {
            swprintf_s(errMsg, L"WebAuthn assertion failed (HRESULT 0x%08lX)", hr);
        }
        result.errorMessage = errMsg;

        OutputDebugString(errMsg);
        OutputDebugString(L"\n");
        return false;
    }

    CPLog("HandleWebAuthnChallenge: seqId=%u WebAuthn SUCCESS — assertion dwVersion=%lu "
          "authDataLen=%lu sigLen=%lu credIdLen=%lu hmacSecretPresent=%d elapsed=%lu ms",
          seqId,
          (unsigned long)pAssertion->dwVersion,
          (unsigned long)pAssertion->cbAuthenticatorData,
          (unsigned long)pAssertion->cbSignature,
          (unsigned long)pAssertion->Credential.cbId,
          (pAssertion->dwVersion >= WEBAUTHN_ASSERTION_VERSION_3 &&
           pAssertion->pHmacSecret != nullptr) ? 1 : 0,
          (unsigned long)callElapsed);

    // Build DDS_AUTH_RESPONSE from the assertion
    IPC_REQ_DDS_AUTH_RESPONSE response = {};

    // Copy authenticator data
    DWORD authDataLen = min(pAssertion->cbAuthenticatorData, (DWORD)sizeof(response.authenticator_data));
    memcpy(response.authenticator_data, pAssertion->pbAuthenticatorData, authDataLen);
    response.authenticator_data_len = authDataLen;

    // Copy signature
    DWORD sigLen = min(pAssertion->cbSignature, (DWORD)sizeof(response.signature));
    memcpy(response.signature, pAssertion->pbSignature, sigLen);
    response.signature_len = sigLen;

    // Copy credential ID
    DWORD credIdLen = min(pAssertion->Credential.cbId, (DWORD)sizeof(response.credential_id));
    memcpy(response.credential_id, pAssertion->Credential.pbId, credIdLen);
    response.credential_id_len = credIdLen;

    // Copy hmac-secret output (from assertion version >= 3)
    if (pAssertion->dwVersion >= WEBAUTHN_ASSERTION_VERSION_3 &&
        pAssertion->pHmacSecret != nullptr &&
        pAssertion->pHmacSecret->cbFirst == 32)
    {
        memcpy(response.hmac_secret, pAssertion->pHmacSecret->pbFirst, 32);
        response.hmac_secret_len = 32;
        CPLog("HandleWebAuthnChallenge: seqId=%u hmac-secret received (32 bytes, "
              "cbSecond=%lu)",
              seqId, (unsigned long)pAssertion->pHmacSecret->cbSecond);
    }
    else
    {
        response.hmac_secret_len = 0;
        CPLog("HandleWebAuthnChallenge: seqId=%u WARNING — no hmac-secret in assertion "
              "(dwVersion=%lu pHmacSecret=%p cbFirst=%lu) — vault decrypt will fail",
              seqId,
              (unsigned long)pAssertion->dwVersion,
              (void*)pAssertion->pHmacSecret,
              pAssertion->pHmacSecret ? (unsigned long)pAssertion->pHmacSecret->cbFirst : 0u);
    }

    // Send the clientDataHash (SHA-256 of our clientDataJSON) — dds-node needs this
    // to verify the assertion signature (sig = sign(authenticatorData || clientDataHash))
    memcpy(response.client_data_hash, clientDataHash, 32);

    // Echo the server challenge ID back so the Bridge can include it in the
    // POST /v1/session/assert body.  The server matches it against the stored
    // nonce to enforce single-use and freshness.
    strncpy_s(response.challenge_id, sizeof(response.challenge_id),
        pChallenge->challenge_id, _TRUNCATE);

    // Free the assertion
    WebAuthNFreeAssertion(pAssertion);
    pAssertion = nullptr;

    // Send DDS_AUTH_RESPONSE to Bridge with the same seqId
    BOOL sent = m_client.SendMessageWithSeqId(
        IPC_MSG::DDS_AUTH_RESPONSE, seqId,
        reinterpret_cast<const BYTE*>(&response), sizeof(response));

    // Secure cleanup of hmac-secret from local memory
    SecureZeroMemory(response.hmac_secret, sizeof(response.hmac_secret));

    if (!sent)
    {
        CPLog("HandleWebAuthnChallenge: seqId=%u FAIL — SendMessageWithSeqId returned FALSE "
              "(payloadLen=%zu) GetLastError=%lu",
              seqId, sizeof(response), (unsigned long)GetLastError());
        result.errorCode = IPC_ERROR::SERVICE_ERROR;
        result.errorMessage = L"Failed to send WebAuthn response to Auth Bridge";
        return false;
    }

    CPLog("HandleWebAuthnChallenge: seqId=%u DDS_AUTH_RESPONSE sent (authDataLen=%lu "
          "sigLen=%lu hmacLen=%lu) — total fn elapsed=%lu ms",
          seqId, (unsigned long)response.authenticator_data_len,
          (unsigned long)response.signature_len,
          (unsigned long)response.hmac_secret_len,
          (unsigned long)(GetTickCount() - fnStart));
    return true; // Continue waiting for DDS_AUTH_COMPLETE
}

// ============================================================================
// DDS auth
// ============================================================================

DdsBridgeAuthResult CDdsBridgeClient::AuthenticateDds(
    _In_ PCWSTR pszDeviceUrn,
    _In_ PCWSTR pszCredentialId,
    _In_ PCWSTR pszRpId,
    _In_ DWORD  timeoutMs,
    _In_opt_ std::function<void(UINT32, PCWSTR)> progressCallback)
{
    DdsBridgeAuthResult fail;
    if (!EnsureConnected())
    {
        fail.errorCode    = IPC_ERROR::DEVICE_NOT_FOUND;
        fail.errorMessage = L"Bridge Service not available";
        return fail;
    }

    UINT32 seqId = 0;
    if (!m_client.StartAuthDds(pszDeviceUrn, pszCredentialId, pszRpId, &seqId))
    {
        fail.errorCode    = IPC_ERROR::SERVICE_ERROR;
        fail.errorMessage = L"Failed to send DDS auth request to Bridge Service";
        return fail;
    }

    return WaitForDdsAuthComplete(seqId, timeoutMs, progressCallback);
}

// ============================================================================
// FIDO2 auth (legacy Crayonic BLE badge path — kept but deferred)
// ============================================================================

DdsBridgeAuthResult CDdsBridgeClient::AuthenticateFido(
    _In_ PCWSTR pszSid,
    _In_ PCWSTR pszRpId,
    _In_ DWORD  timeoutMs,
    _In_opt_ std::function<void(UINT32, PCWSTR)> progressCallback)
{
    DdsBridgeAuthResult fail;
    if (!EnsureConnected())
    {
        fail.errorCode    = IPC_ERROR::DEVICE_NOT_FOUND;
        fail.errorMessage = L"Bridge Service not available";
        return fail;
    }

    UINT32 seqId = 0;
    if (!m_client.StartAuthFido(pszSid, pszRpId, &seqId))
    {
        fail.errorCode    = IPC_ERROR::SERVICE_ERROR;
        fail.errorMessage = L"Failed to send auth request to Bridge Service";
        return fail;
    }

    return WaitForAuthComplete(seqId, timeoutMs, progressCallback);
}

// ============================================================================
// AD-14 — fire-and-forget post-logon NTSTATUS report
// ============================================================================

BOOL CDdsBridgeClient::ReportLogonResult(
    _In_ PCWSTR pszCredentialId,
    _In_ INT32  ntStatus)
{
    if (pszCredentialId == nullptr || pszCredentialId[0] == L'\0')
        return FALSE;

    if (!EnsureConnected())
        return FALSE;

    IPC_REQ_DDS_REPORT_LOGON_RESULT req{};
    wcsncpy_s(req.credential_id, pszCredentialId, _TRUNCATE);
    req.ntStatus = ntStatus;

    return m_client.SendRequestNoReply(
        IPC_MSG::DDS_REPORT_LOGON_RESULT,
        reinterpret_cast<const BYTE*>(&req),
        sizeof(req));
}
