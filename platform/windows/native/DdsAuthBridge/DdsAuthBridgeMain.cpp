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
#include <string.h>
#include <lm.h>          // NetGetJoinInformation
#include <sddl.h>        // ConvertStringSidToSidW
#include <webauthn.h>     // WebAuthNAuthenticatorGetAssertion (Win10 1903+)
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "webauthn.lib")

// ============================================================================
// Base64url encoding helper (for credential ID and assertion fields)
// ============================================================================
static std::string Base64Encode(const BYTE* data, DWORD len)
{
    static const char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len * 4 + 2) / 3);
    for (DWORD i = 0; i < len; i += 3)
    {
        DWORD val = (DWORD)data[i] << 16;
        if (i + 1 < len) val |= (DWORD)data[i + 1] << 8;
        if (i + 2 < len) val |= data[i + 2];
        out += kTable[(val >> 18) & 0x3F];
        out += kTable[(val >> 12) & 0x3F];
        out += (i + 1 < len) ? kTable[(val >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? kTable[val & 0x3F] : '=';
    }
    return out;
}

// ============================================================================
// Platform WebAuthn getAssertion with hmac-secret extension.
//
// Uses the Windows 10 1903+ WebAuthn API (webauthn.h) to:
//   1. Prompt the user for biometric/PIN via Windows Hello
//   2. Perform a FIDO2 getAssertion
//   3. Extract authenticatorData, signature, and hmac-secret output
//
// Returns TRUE on success; fills out assertion fields and hmac-secret key.
// ============================================================================
struct WebAuthnAssertionResult
{
    std::vector<BYTE> authenticatorData;
    std::vector<BYTE> signature;
    std::vector<BYTE> clientDataHash;
    std::vector<BYTE> hmacSecretOutput;   // 32 bytes from hmac-secret extension
    bool              success = false;
    std::string       errorMessage;
};

static WebAuthnAssertionResult CallPlatformWebAuthn(
    _In_ const std::vector<BYTE>& credentialId,
    _In_ const std::string& rpId,
    _In_ const std::vector<BYTE>& hmacSalt,
    _In_ volatile BOOL* pCancelled)
{
    WebAuthnAssertionResult result;

    // Check API availability
    DWORD apiVersion = WebAuthNGetApiVersionNumber();
    FileLog::Writef("WebAuthn: API version %lu\n", apiVersion);
    if (apiVersion < WEBAUTHN_API_VERSION_1)
    {
        result.errorMessage = "WebAuthn API not available on this system";
        return result;
    }

    // --- Build clientDataJSON + hash ---
    // For platform assertion within a service context, we build a minimal
    // clientDataJSON. The hash is what gets signed by the authenticator.
    std::string clientDataJson = "{\"type\":\"webauthn.get\","
        "\"challenge\":\"DDS-local-auth\","
        "\"origin\":\"https://dds.local\"}";
    // SHA-256 hash of clientDataJSON
    BYTE cdHash[32];
    {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        BCRYPT_HASH_HANDLE hHash = NULL;
        BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
        BCryptHashData(hHash, (PUCHAR)clientDataJson.data(),
                       (ULONG)clientDataJson.size(), 0);
        BCryptFinishHash(hHash, cdHash, sizeof(cdHash), 0);
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    result.clientDataHash.assign(cdHash, cdHash + 32);

    // --- Relying party ---
    std::wstring rpIdW(rpId.begin(), rpId.end());
    WEBAUTHN_RP_ENTITY_INFORMATION rpInfo = {};
    rpInfo.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpInfo.pwszId = rpIdW.c_str();
    rpInfo.pwszName = L"DDS";

    // --- Client data ---
    WEBAUTHN_CLIENT_DATA clientData = {};
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)clientDataJson.size();
    clientData.pbClientDataJSON = (BYTE*)clientDataJson.data();
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // --- Allowed credential ---
    WEBAUTHN_CREDENTIAL credDesc = {};
    credDesc.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
    credDesc.cbId = (DWORD)credentialId.size();
    credDesc.pbId = (BYTE*)credentialId.data();
    credDesc.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

    WEBAUTHN_CREDENTIALS allowCreds = {};
    allowCreds.cCredentials = 1;
    allowCreds.pCredentials = &credDesc;

    // --- hmac-secret extension ---
    // The hmac-secret extension sends a salt to the authenticator.
    // The authenticator returns HMAC-SHA-256(credRandom, salt) which
    // is deterministic per credential + salt, giving us a stable 32-byte key.
    WEBAUTHN_HMAC_SECRET_SALT hmacSaltStruct = {};
    hmacSaltStruct.cbFirst = (DWORD)hmacSalt.size();
    hmacSaltStruct.pbFirst = (BYTE*)hmacSalt.data();
    // pbSecond/cbSecond left NULL — we only need one salt output.

    WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT credHmac = {};
    credHmac.cbCredId = (DWORD)credentialId.size();
    credHmac.pbCredId = (BYTE*)credentialId.data();
    credHmac.pHmacSecretSalt = &hmacSaltStruct;

    WEBAUTHN_HMAC_SECRET_SALT_VALUES hmacSaltValues = {};
    hmacSaltValues.pGlobalHmacSalt = &hmacSaltStruct;
    hmacSaltValues.cCredWithHmacSecretSaltList = 1;
    hmacSaltValues.pCredWithHmacSecretSaltList = &credHmac;

    WEBAUTHN_EXTENSION hmacExt = {};
    hmacExt.pwszExtensionIdentifier = WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET;
    hmacExt.cbExtension = sizeof(hmacSaltValues);
    hmacExt.pvExtension = &hmacSaltValues;

    WEBAUTHN_EXTENSIONS extensions = {};
    extensions.cExtensions = 1;
    extensions.pExtensions = &hmacExt;

    // --- Assertion options ---
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = {};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000; // 60-second user interaction timeout
    options.CredentialList = allowCreds;
    options.Extensions = extensions;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED;

    // Cancellation support
    WEBAUTHN_CANCELLATION_ID cancelId = {};
    if (WebAuthNGetCancellationId(&cancelId) == S_OK)
    {
        options.pCancellationId = &cancelId;
    }

    // --- Call the platform API ---
    FileLog::Write("WebAuthn: calling WebAuthNAuthenticatorGetAssertion...\n");

    PWEBAUTHN_ASSERTION pAssertion = NULL;
    HWND hWnd = GetForegroundWindow();
    if (!hWnd) hWnd = GetDesktopWindow();

    HRESULT hr = WebAuthNAuthenticatorGetAssertion(
        hWnd,
        rpIdW.c_str(),
        &clientData,
        &options,
        &pAssertion
    );

    if (FAILED(hr) || pAssertion == NULL)
    {
        if (*pCancelled)
        {
            result.errorMessage = "Authentication cancelled by user";
        }
        else
        {
            wchar_t* errStr = WebAuthNGetErrorName(hr);
            char errBuf[256];
            snprintf(errBuf, sizeof(errBuf), "WebAuthn getAssertion failed: 0x%08lX (%ls)",
                     (unsigned long)hr, errStr ? errStr : L"unknown");
            result.errorMessage = errBuf;
        }
        FileLog::Writef("WebAuthn: FAILED — %s\n", result.errorMessage.c_str());
        return result;
    }

    // --- Extract results ---
    result.authenticatorData.assign(
        pAssertion->pbAuthenticatorData,
        pAssertion->pbAuthenticatorData + pAssertion->cbAuthenticatorData);
    result.signature.assign(
        pAssertion->pbSignature,
        pAssertion->pbSignature + pAssertion->cbSignature);

    FileLog::Writef("WebAuthn: OK — authDataLen=%lu sigLen=%lu\n",
                    pAssertion->cbAuthenticatorData, pAssertion->cbSignature);

    // --- Extract hmac-secret output from extensions ---
    if (pAssertion->pHmacSecret &&
        pAssertion->pHmacSecret->cbFirst >= 32)
    {
        result.hmacSecretOutput.assign(
            pAssertion->pHmacSecret->pbFirst,
            pAssertion->pHmacSecret->pbFirst + 32);
        FileLog::Writef("WebAuthn: hmac-secret output OK (%lu bytes)\n",
                        pAssertion->pHmacSecret->cbFirst);
    }
    else
    {
        FileLog::Write("WebAuthn: WARNING — no hmac-secret output in response\n");
        // This happens if the authenticator doesn't support hmac-secret.
        // Password decryption will fail, but session token issuance can proceed.
    }

    result.success = true;
    WebAuthNFreeAssertion(pAssertion);
    return result;
}

CDdsAuthBridgeMain::CDdsAuthBridgeMain()
    : m_hStopEvent(NULL)
    , m_bInitialized(FALSE)
{
    ZeroMemory(&m_activeAuth, sizeof(m_activeAuth));
    InitializeCriticalSection(&m_csAuth);
}

CDdsAuthBridgeMain::~CDdsAuthBridgeMain()
{
    Shutdown();
    DeleteCriticalSection(&m_csAuth);
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

    // Configure dds-node HTTP client
    m_httpClient.SetPort(m_config.DdsNodePort());

    // Load credential vault
    if (!m_vault.Load())
    {
        CEventLogger::LogWarning(EVENT_ID::SERVICE_START_FAILED,
            L"Credential vault failed to load -- starting with empty vault");
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
    IPC_RESP_AUTH_PROGRESS progress = {};
    progress.state = state;
    wcscpy_s(progress.message, message);

    m_pipeServer.SendNotification(pClientCtx, IPC_MSG::AUTH_PROGRESS, seqId,
        reinterpret_cast<const BYTE*>(&progress), sizeof(progress));
}

void CDdsAuthBridgeMain::SendAuthError(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId,
    _In_ UINT32 errorCode, _In_ PCWSTR message)
{
    IPC_RESP_AUTH_ERROR errResp = {};
    errResp.errorCode = errorCode;
    wcscpy_s(errResp.message, message);

    m_pipeServer.SendResponse(pClientCtx, IPC_MSG::AUTH_ERROR, seqId,
        reinterpret_cast<const BYTE*>(&errResp), sizeof(errResp));
}

BOOL CDdsAuthBridgeMain::IsDomainJoined()
{
    LPWSTR pDomain = nullptr;
    NETSETUP_JOIN_STATUS joinStatus = NetSetupUnknownStatus;

    NET_API_STATUS status = NetGetJoinInformation(nullptr, &pDomain, &joinStatus);
    if (status == NERR_Success)
    {
        if (pDomain) NetApiBufferFree(pDomain);
        return (joinStatus == NetSetupDomainName);
    }

    return FALSE;
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

    case IPC_MSG::DDS_LIST_USERS:
        return pSelf->HandleDdsListUsers(pClientCtx, pHeader->seqId);

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

    // Extract user SID from payload (first field in the DDS start auth request)
    // For now, treat the payload as an IPC_REQ_START_AUTH_FIDO-compatible struct
    const IPC_REQ_START_AUTH_FIDO* pReq = nullptr;
    if (payloadLen >= sizeof(IPC_REQ_START_AUTH_FIDO))
    {
        pReq = reinterpret_cast<const IPC_REQ_START_AUTH_FIDO*>(pPayload);
    }
    else
    {
        LeaveCriticalSection(&m_csAuth);
        SendAuthError(pClientCtx, seqId, IPC_ERROR::SERVICE_ERROR,
            L"Invalid DDS_START_AUTH payload");
        return TRUE;
    }

    std::wstring sid(pReq->sid);

    // Check if user has enrolled credentials in vault
    auto userEntries = m_vault.FindByUserSid(sid);
    if (userEntries.empty())
    {
        LeaveCriticalSection(&m_csAuth);
        char sidA[160]{};
        WideCharToMultiByte(CP_UTF8, 0, pReq->sid, -1, sidA, sizeof(sidA), nullptr, nullptr);
        FileLog::Writef("DdsStartAuth: REJECTED -- no vault entry for sid='%s'\n", sidA);
        SendAuthError(pClientCtx, seqId, IPC_ERROR::NO_CREDENTIAL,
            L"No credential enrolled for this user");
        return TRUE;
    }

    // Set up auth operation
    m_activeAuth.pClientCtx = pClientCtx;
    m_activeAuth.seqId = seqId;
    m_activeAuth.authMethod = IPC_AUTH_METHOD::FIDO2;
    m_activeAuth.userSid = sid;
    m_activeAuth.rpId = m_config.RpId();
    m_activeAuth.cancelled = FALSE;

    // Spawn worker thread
    m_activeAuth.hThread = CreateThread(NULL, 0, DdsAuthWorkerThread, this, 0, NULL);
    if (m_activeAuth.hThread == NULL)
    {
        ZeroMemory(&m_activeAuth, sizeof(m_activeAuth));
        LeaveCriticalSection(&m_csAuth);
        SendAuthError(pClientCtx, seqId, IPC_ERROR::SERVICE_ERROR,
            L"Failed to start authentication thread");
        return TRUE;
    }

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

    // Clean up
    EnterCriticalSection(&pSelf->m_csAuth);
    if (pSelf->m_activeAuth.hThread != NULL)
    {
        CloseHandle(pSelf->m_activeAuth.hThread);
    }
    ZeroMemory(&pSelf->m_activeAuth, sizeof(pSelf->m_activeAuth));
    LeaveCriticalSection(&pSelf->m_csAuth);

    return 0;
}

void CDdsAuthBridgeMain::ExecuteDdsAuth(_In_ AuthOperation* pOp)
{
    // ================================================================
    // DDS Authentication Flow
    //
    // 1. Find vault entry for the user
    // 2. Call platform WebAuthn API for getAssertion (TODO: stub)
    // 3. POST assertion proof to dds-node /v1/session/assert
    // 4. Use hmac-secret to decrypt password from vault
    // 5. Return DDS_AUTH_COMPLETE with password + session token
    // ================================================================

    FileLog::Writef("DdsAuth.worker: seqId=%u begin (rpId='%s')\n",
                    pOp->seqId, pOp->rpId.c_str());

    // Step 1: Find vault entry
    auto userEntries = m_vault.FindByUserSid(pOp->userSid);
    if (userEntries.empty())
    {
        FileLog::Write("DdsAuth.worker: vault lookup failed (race?)\n");
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::NO_CREDENTIAL,
            L"No credential found for user");
        return;
    }

    const VaultEntry* pVaultEntry = userEntries[0];
    FileLog::Writef("DdsAuth.worker: using vault entry (credIdLen=%zu rp='%s')\n",
                    pVaultEntry->credentialId.size(), pVaultEntry->rpId.c_str());

    // Step 2: Send "processing" progress
    SendAuthProgress(pOp->pClientCtx, pOp->seqId,
        IPC_AUTH_STATE::PROCESSING, L"Contacting authenticator...");

    // Step 3: Call platform WebAuthn API for getAssertion + hmac-secret
    WebAuthnAssertionResult webauthn = CallPlatformWebAuthn(
        pVaultEntry->credentialId,
        pOp->rpId,
        pVaultEntry->salt,
        &pOp->cancelled);

    if (!webauthn.success)
    {
        wchar_t errMsg[256];
        swprintf_s(errMsg, L"%hs", webauthn.errorMessage.c_str());
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::AUTH_FAILED, errMsg);
        return;
    }

    if (pOp->cancelled)
    {
        FileLog::Write("DdsAuth.worker: cancelled by client\n");
        return;
    }

    // Step 4: POST assertion proof to dds-node for server-side verification
    SendAuthProgress(pOp->pClientCtx, pOp->seqId,
        IPC_AUTH_STATE::PROCESSING, L"Verifying assertion with DDS node...");

    // Build JSON payload with base64-encoded assertion fields.
    std::string credIdB64 = Base64Encode(pVaultEntry->credentialId.data(),
                                          (DWORD)pVaultEntry->credentialId.size());
    std::string authDataB64 = Base64Encode(webauthn.authenticatorData.data(),
                                            (DWORD)webauthn.authenticatorData.size());
    std::string sigB64 = Base64Encode(webauthn.signature.data(),
                                       (DWORD)webauthn.signature.size());
    std::string cdhB64 = Base64Encode(webauthn.clientDataHash.data(),
                                       (DWORD)webauthn.clientDataHash.size());

    std::string assertionJson = "{\"credential_id\":\"" + credIdB64 +
        "\",\"authenticator_data\":\"" + authDataB64 +
        "\",\"signature\":\"" + sigB64 +
        "\",\"client_data_hash\":\"" + cdhB64 +
        "\",\"duration_secs\":3600}";

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
                    assertResult.sessionToken.size());

    if (pOp->cancelled)
    {
        FileLog::Write("DdsAuth.worker: cancelled by client\n");
        return;
    }

    // Step 5: Decrypt password from vault using hmac-secret output
    std::wstring password;
    if (!webauthn.hmacSecretOutput.empty())
    {
        if (!m_vault.DecryptPassword(
                webauthn.hmacSecretOutput.data(),
                (DWORD)webauthn.hmacSecretOutput.size(),
                *pVaultEntry, password))
        {
            FileLog::Write("DdsAuth.worker: vault password decryption FAILED\n");
            SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::AUTH_FAILED,
                L"Failed to decrypt Windows password from vault");
            return;
        }
        FileLog::Write("DdsAuth.worker: vault password decrypted OK\n");
    }
    else
    {
        FileLog::Write("DdsAuth.worker: no hmac-secret — password unavailable "
                        "(session-only auth)\n");
        // Session token was issued by dds-node; password-less logon requires
        // a custom LSA AP (v2). For now, the tile will show an error when LSA
        // rejects the empty password.
    }

    // Clear hmac-secret key material immediately
    SecureZeroMemory(webauthn.hmacSecretOutput.data(),
                     webauthn.hmacSecretOutput.size());

    // Step 6: Return DDS_AUTH_COMPLETE with password + session token
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
        if (ConvertStringSidToSidW(pOp->userSid.c_str(), &pSid))
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

    if (!password.empty())
    {
        wcsncpy_s(result.password, password.c_str(), _TRUNCATE);
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    }

    // Copy session token and subject URN
    strncpy_s(result.session_token, assertResult.sessionToken.c_str(), _TRUNCATE);
    // TODO: get subject_urn from the DDS_START_AUTH request; for now use SID
    wcsncpy_s(result.subject_urn, pOp->userSid.c_str(), _TRUNCATE);
    result.expires_at = (UINT64)time(NULL) + 3600; // 1 hour from now

    m_pipeServer.SendResponse(pOp->pClientCtx, IPC_MSG::DDS_AUTH_COMPLETE, pOp->seqId,
        reinterpret_cast<const BYTE*>(&result), sizeof(result));

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

    // Build IPC response from dds-node data
    BYTE buffer[IPC_PIPE::BUFFER_SIZE];
    IPC_RESP_USER_LIST* pList = reinterpret_cast<IPC_RESP_USER_LIST*>(buffer);

    size_t maxUsers = (sizeof(buffer) - sizeof(IPC_RESP_USER_LIST)) / sizeof(IPC_USER_ENTRY);
    UINT32 count = static_cast<UINT32>(min(result.users.size(), maxUsers));
    pList->userCount = count;

    IPC_USER_ENTRY* pEntries = reinterpret_cast<IPC_USER_ENTRY*>(buffer + sizeof(IPC_RESP_USER_LIST));
    for (UINT32 i = 0; i < count; i++)
    {
        ZeroMemory(&pEntries[i], sizeof(IPC_USER_ENTRY));
        // Convert narrow UTF-8 strings to wide
        MultiByteToWideChar(CP_UTF8, 0,
            result.users[i].userSid.c_str(), -1,
            pEntries[i].sid, _countof(pEntries[i].sid));
        MultiByteToWideChar(CP_UTF8, 0,
            result.users[i].displayName.c_str(), -1,
            pEntries[i].displayName, _countof(pEntries[i].displayName));
        pEntries[i].authMethod = IPC_AUTH_METHOD::FIDO2;
    }

    DWORD totalSize = sizeof(IPC_RESP_USER_LIST) + count * sizeof(IPC_USER_ENTRY);

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
    resp.transport       = TRANSPORT::NONE;

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
    UINT32 count = static_cast<UINT32>(min(entries.size(), maxUsers));
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
