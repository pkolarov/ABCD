// DdsBridgeClient.cpp
// High-level DDS Auth Bridge client for the Credential Provider DLL.
// Forked from Crayonic BridgeClient; PIV path removed, DDS auth path added.

#include "DdsBridgeClient.h"
#include <cstring>
#include <functional>
#include <bcrypt.h>

#pragma comment(lib, "webauthn.lib")
#pragma comment(lib, "bcrypt.lib")

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

        case IPC_MSG::DDS_AUTH_CHALLENGE:
            if (payloadLen >= sizeof(IPC_RESP_DDS_AUTH_CHALLENGE))
            {
                const IPC_RESP_DDS_AUTH_CHALLENGE* pChallenge =
                    reinterpret_cast<const IPC_RESP_DDS_AUTH_CHALLENGE*>(payload);

                OutputDebugString(L"DdsBridgeClient: received AUTH_CHALLENGE, calling WebAuthn\n");

                if (!HandleWebAuthnChallenge(seqId, pChallenge, result))
                {
                    // HandleWebAuthnChallenge already filled result.error*
                    return result;
                }
                // WebAuthn succeeded and DDS_AUTH_RESPONSE sent — continue waiting for AUTH_COMPLETE
                if (progressCallback)
                    progressCallback(IPC_AUTH_STATE::PROCESSING, L"Verifying with DDS node...");
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
// WebAuthn platform API call
// ============================================================================

bool CDdsBridgeClient::HandleWebAuthnChallenge(
    UINT32 seqId,
    const IPC_RESP_DDS_AUTH_CHALLENGE* pChallenge,
    DdsBridgeAuthResult& result)
{
    // Check WebAuthn API availability
    DWORD apiVersion = WebAuthNGetApiVersionNumber();
    if (apiVersion < WEBAUTHN_API_VERSION_1)
    {
        result.errorCode = IPC_ERROR::SERVICE_ERROR;
        result.errorMessage = L"WebAuthn API not available on this system";
        return false;
    }

    OutputDebugStringA("HandleWebAuthnChallenge: WebAuthn API present\n");

    // Generate a random challenge and construct clientDataJSON.
    // The WebAuthn API will SHA-256 this JSON to produce the clientDataHash
    // that the authenticator signs over. We must send the same hash to dds-node.
    uint8_t challengeBytes[32]{};
    if (!GenRandom(challengeBytes, sizeof(challengeBytes)))
    {
        result.errorCode = IPC_ERROR::SERVICE_ERROR;
        result.errorMessage = L"Failed to generate random challenge";
        return false;
    }

    std::string challengeB64 = Base64UrlEncode(challengeBytes, sizeof(challengeBytes));

    // Construct a minimal WebAuthn clientDataJSON
    std::string clientDataJson = "{\"type\":\"webauthn.get\",\"challenge\":\"" +
        challengeB64 + "\",\"origin\":\"https://dds.local\"}";

    // Compute SHA-256 of clientDataJSON — this is what dds-node needs
    uint8_t clientDataHash[32]{};
    if (!Sha256(reinterpret_cast<const uint8_t*>(clientDataJson.data()),
                clientDataJson.size(), clientDataHash))
    {
        result.errorCode = IPC_ERROR::SERVICE_ERROR;
        result.errorMessage = L"Failed to compute clientDataHash";
        return false;
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

    // Use a cancellation GUID so the CP can abort if needed
    GUID cancelId = {};
    if (SUCCEEDED(WebAuthNGetCancellationId(&cancelId)))
    {
        options.pCancellationId = &cancelId;
    }

    // Call WebAuthNAuthenticatorGetAssertion
    // The CP runs inside LogonUI.exe on the secure desktop, so GetForegroundWindow()
    // gives us the correct HWND for the WebAuthn UI prompt.
    HWND hWnd = GetForegroundWindow();
    if (hWnd == NULL)
        hWnd = GetDesktopWindow();

    PWEBAUTHN_ASSERTION pAssertion = nullptr;

    OutputDebugString(L"HandleWebAuthnChallenge: calling WebAuthNAuthenticatorGetAssertion\n");

    HRESULT hr = WebAuthNAuthenticatorGetAssertion(
        hWnd,
        rpIdW,
        &clientData,
        &options,
        &pAssertion);

    if (FAILED(hr) || pAssertion == nullptr)
    {
        result.errorCode = IPC_ERROR::AUTH_FAILED;
        wchar_t errMsg[256];
        swprintf_s(errMsg, L"WebAuthn assertion failed (HRESULT 0x%08lX)", hr);
        result.errorMessage = errMsg;

        OutputDebugString(errMsg);
        OutputDebugString(L"\n");
        return false;
    }

    OutputDebugStringA("HandleWebAuthnChallenge: assertion succeeded\n");

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
        OutputDebugStringA("HandleWebAuthnChallenge: hmac-secret output received (32 bytes)\n");
    }
    else
    {
        response.hmac_secret_len = 0;
        OutputDebugStringA("HandleWebAuthnChallenge: WARNING - no hmac-secret in assertion response\n");
    }

    // Send the clientDataHash (SHA-256 of our clientDataJSON) — dds-node needs this
    // to verify the assertion signature (sig = sign(authenticatorData || clientDataHash))
    memcpy(response.client_data_hash, clientDataHash, 32);

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
        result.errorCode = IPC_ERROR::SERVICE_ERROR;
        result.errorMessage = L"Failed to send WebAuthn response to Auth Bridge";
        return false;
    }

    OutputDebugString(L"HandleWebAuthnChallenge: DDS_AUTH_RESPONSE sent to bridge\n");
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
