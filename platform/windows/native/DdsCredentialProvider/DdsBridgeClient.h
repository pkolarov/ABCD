// DdsBridgeClient.h
// High-level DDS Auth Bridge client for the Credential Provider DLL.
// Forked from Crayonic BridgeClient; PIV path removed, DDS auth path added.

#pragma once

#include <windows.h>
#include <webauthn.h>
#include <string>
#include <vector>
#include <functional>
#include "../DdsBridgeIPC/ipc_pipe_client.h"
#include "../DdsBridgeIPC/ipc_messages.h"

// ============================================================================
// User tile info — built from IPC DDS_USER_LIST response
// ============================================================================
struct DdsBridgeUser
{
    std::wstring subjectUrn;      // Vouchsafe URN
    std::wstring displayName;
    std::wstring credentialId;    // FIDO2 credential ID (base64url)
};

// ============================================================================
// Auth result returned to GetSerialization
// ============================================================================
struct DdsBridgeAuthResult
{
    bool    success{ false };
    std::wstring domain;
    std::wstring username;
    std::wstring password;          // cleared after use with SecureZeroMemory
    std::string  sessionTokenB64;   // DDS session token (CBOR base64)
    std::wstring subjectUrn;        // authenticated Vouchsafe URN
    UINT64  expiresAt{ 0 };         // session expiry (Unix seconds)
    UINT32  errorCode{ 0 };
    std::wstring errorMessage;
};

// ============================================================================
// CDdsBridgeClient
// ============================================================================
class CDdsBridgeClient
{
public:
    CDdsBridgeClient();
    ~CDdsBridgeClient();

    // ---- Status ----
    BOOL GetStatus(_Out_opt_ IPC_RESP_STATUS* pStatus = nullptr);
    BOOL GetStatusShort(DWORD connectTimeoutMs = 200,
                        _Out_opt_ IPC_RESP_STATUS* pStatus = nullptr);

    // ---- User enumeration ----
    std::vector<DdsBridgeUser> ListDdsUsers(PCWSTR deviceUrn);
    std::vector<DdsBridgeUser> ListDdsUsersTimeout(PCWSTR deviceUrn, DWORD timeoutMs);

    // ---- Authentication ----

    // DDS FIDO2 auth: sends DDS_START_AUTH and waits for DDS_AUTH_COMPLETE.
    DdsBridgeAuthResult AuthenticateDds(
        _In_ PCWSTR pszDeviceUrn,
        _In_ PCWSTR pszCredentialId,
        _In_ PCWSTR pszRpId = L"dds.local",
        _In_ DWORD  timeoutMs = 60000,
        _In_opt_ std::function<void(UINT32 state, PCWSTR message)> progressCallback = nullptr
    );

    // Legacy Crayonic FIDO2 auth (for BLE badge path — kept but deferred).
    DdsBridgeAuthResult AuthenticateFido(
        _In_ PCWSTR pszSid,
        _In_ PCWSTR pszRpId,
        _In_ DWORD  timeoutMs = 60000,
        _In_opt_ std::function<void(UINT32 state, PCWSTR message)> progressCallback = nullptr
    );

private:
    DdsBridgeAuthResult WaitForDdsAuthComplete(UINT32 seqId, DWORD timeoutMs,
        std::function<void(UINT32, PCWSTR)> progressCallback);

    DdsBridgeAuthResult WaitForAuthComplete(UINT32 seqId, DWORD timeoutMs,
        std::function<void(UINT32, PCWSTR)> progressCallback);

    // Call Windows WebAuthn API to get assertion + hmac-secret, then send response to Bridge.
    // Returns false and fills result.error* on failure.
    bool HandleWebAuthnChallenge(
        UINT32 seqId,
        const IPC_RESP_DDS_AUTH_CHALLENGE* pChallenge,
        DdsBridgeAuthResult& result);

    CIpcPipeClient m_client;
    BOOL EnsureConnected();
};
