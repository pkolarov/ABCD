// DdsBridgeClient.cpp
// High-level DDS Auth Bridge client for the Credential Provider DLL.
// Forked from Crayonic BridgeClient; PIV path removed, DDS auth path added.

#include "DdsBridgeClient.h"
#include <cstring>
#include <functional>

CDdsBridgeClient::CDdsBridgeClient() = default;
CDdsBridgeClient::~CDdsBridgeClient() { m_client.Disconnect(); }

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

        case IPC_MSG::DDS_AUTH_COMPLETE:
            if (payloadLen >= sizeof(IPC_RESP_DDS_AUTH_COMPLETE))
            {
                const IPC_RESP_DDS_AUTH_COMPLETE* complete =
                    reinterpret_cast<const IPC_RESP_DDS_AUTH_COMPLETE*>(payload);
                if (complete->success)
                {
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
                result.errorCode    = err->error_code;
                result.errorMessage = err->message;
            }
            else
            {
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
