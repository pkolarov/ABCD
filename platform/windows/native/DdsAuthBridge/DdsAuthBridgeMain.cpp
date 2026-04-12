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

CDdsAuthBridgeMain::CDdsAuthBridgeMain()
    : m_hStopEvent(NULL)
    , m_bInitialized(FALSE)
{
    ZeroMemory(&m_activeAuth, sizeof(m_activeAuth));
    m_activeAuth.hResponseEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    InitializeCriticalSection(&m_csAuth);
}

CDdsAuthBridgeMain::~CDdsAuthBridgeMain()
{
    Shutdown();
    if (m_activeAuth.hResponseEvent)
        CloseHandle(m_activeAuth.hResponseEvent);
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

    case IPC_MSG::DDS_AUTH_RESPONSE:
        if (pPayload != nullptr && payloadLen > 0)
        {
            return pSelf->HandleDdsAuthResponse(pClientCtx, pHeader->seqId,
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

    std::wstring deviceUrn(pReq->device_urn);
    std::wstring credentialId(pReq->credential_id);
    std::wstring rpIdW(pReq->rp_id);

    // Convert RP ID to narrow string for HTTP and vault use.
    char rpIdA[256]{};
    WideCharToMultiByte(CP_UTF8, 0, rpIdW.c_str(), -1, rpIdA, sizeof(rpIdA), nullptr, nullptr);

    {
        char urnA[160]{}, credA[160]{};
        WideCharToMultiByte(CP_UTF8, 0, deviceUrn.c_str(), -1, urnA, sizeof(urnA), nullptr, nullptr);
        WideCharToMultiByte(CP_UTF8, 0, credentialId.c_str(), -1, credA, sizeof(credA), nullptr, nullptr);
        FileLog::Writef("DdsStartAuth: device='%s' credId='%s' rp='%s'\n", urnA, credA, rpIdA);
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

    if (!pMatchedEntry)
    {
        LeaveCriticalSection(&m_csAuth);
        FileLog::Write("DdsStartAuth: REJECTED -- no vault entry matches credential_id\n");
        SendAuthError(pClientCtx, seqId, IPC_ERROR::NO_CREDENTIAL,
            L"No credential enrolled matching the requested credential ID");
        return TRUE;
    }

    FileLog::Writef("DdsStartAuth: matched vault entry sid='%ls' credIdLen=%zu\n",
                    pMatchedEntry->userSid.c_str(), pMatchedEntry->credentialId.size());

    // Set up auth operation using the matched vault entry
    m_activeAuth.pClientCtx = pClientCtx;
    m_activeAuth.seqId = seqId;
    m_activeAuth.authMethod = IPC_AUTH_METHOD::FIDO2;
    m_activeAuth.userSid = pMatchedEntry->userSid;   // Windows SID from vault (for password decryption + SID resolve)
    m_activeAuth.subjectUrn = deviceUrn;              // DDS subject URN (for auth complete response)
    m_activeAuth.credentialId = credentialId;
    m_activeAuth.rpId = rpIdA[0] ? std::string(rpIdA) : m_config.RpId();
    m_activeAuth.cancelled = FALSE;
    m_activeAuth.responseReceived = FALSE;
    ResetEvent(m_activeAuth.hResponseEvent);
    ZeroMemory(&m_activeAuth.responseData, sizeof(m_activeAuth.responseData));

    // Spawn worker thread
    m_activeAuth.hThread = CreateThread(NULL, 0, DdsAuthWorkerThread, this, 0, NULL);
    if (m_activeAuth.hThread == NULL)
    {
        HANDLE hEvt = m_activeAuth.hResponseEvent; // preserve event handle
        ZeroMemory(&m_activeAuth, sizeof(m_activeAuth));
        m_activeAuth.hResponseEvent = hEvt;
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
    SecureZeroMemory(&pSelf->m_activeAuth.responseData, sizeof(pSelf->m_activeAuth.responseData));
    ZeroMemory(&pSelf->m_activeAuth, sizeof(pSelf->m_activeAuth));
    pSelf->m_activeAuth.hResponseEvent = hEvt;
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

    // Step 1: Find the specific vault entry matching the requested credential.
    // Use the credential_id from the DDS_START_AUTH request to select the
    // exact credential, not just the first one for a given SID.
    const VaultEntry* pVaultEntry = nullptr;
    {
        char credIdNarrow[256]{};
        WideCharToMultiByte(CP_UTF8, 0, pOp->credentialId.c_str(), -1,
                            credIdNarrow, sizeof(credIdNarrow), nullptr, nullptr);
        std::vector<uint8_t> credIdBytes = Base64UrlDecode(std::string(credIdNarrow));
        if (!credIdBytes.empty())
            pVaultEntry = m_vault.FindByCredentialId(credIdBytes);
    }

    if (!pVaultEntry)
    {
        // Fall back to SID-based lookup (shouldn't happen if HandleDdsStartAuth matched)
        auto userEntries = m_vault.FindByUserSid(pOp->userSid);
        if (!userEntries.empty())
            pVaultEntry = userEntries[0];
    }

    if (!pVaultEntry)
    {
        FileLog::Write("DdsAuth.worker: vault lookup failed -- no matching credential\n");
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::NO_CREDENTIAL,
            L"No credential found for user");
        return;
    }

    FileLog::Writef("DdsAuth.worker: using vault entry (credIdLen=%zu rp='%s' sid='%ls')\n",
                    pVaultEntry->credentialId.size(), pVaultEntry->rpId.c_str(),
                    pVaultEntry->userSid.c_str());

    // Step 2: Build and send DDS_AUTH_CHALLENGE to CP
    IPC_RESP_DDS_AUTH_CHALLENGE challenge = {};

    // Copy credential ID
    DWORD credIdLen = static_cast<DWORD>(min(pVaultEntry->credentialId.size(),
                                              sizeof(challenge.credential_id)));
    memcpy(challenge.credential_id, pVaultEntry->credentialId.data(), credIdLen);
    challenge.credential_id_len = credIdLen;

    // Copy RP ID
    strncpy_s(challenge.rp_id, pOp->rpId.c_str(), _TRUNCATE);

    // Copy hmac-secret salt from vault
    DWORD saltLen = static_cast<DWORD>(min(pVaultEntry->salt.size(),
                                            sizeof(challenge.salt)));
    if (saltLen > 0)
        memcpy(challenge.salt, pVaultEntry->salt.data(), saltLen);
    challenge.salt_len = saltLen;

    FileLog::Writef("DdsAuth.worker: sending AUTH_CHALLENGE (credIdLen=%u saltLen=%u)\n",
                    credIdLen, saltLen);

    m_pipeServer.SendNotification(pOp->pClientCtx, IPC_MSG::DDS_AUTH_CHALLENGE, pOp->seqId,
        reinterpret_cast<const BYTE*>(&challenge), sizeof(challenge));

    SendAuthProgress(pOp->pClientCtx, pOp->seqId,
        IPC_AUTH_STATE::USER_PRESENCE, L"Touch your security key or use Windows Hello...");

    // Step 4: Wait for DDS_AUTH_RESPONSE from CP (up to 60 seconds)
    DWORD waitResult = WaitForSingleObject(pOp->hResponseEvent, IPC_PIPE::AUTH_TIMEOUT_MS);

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

    // Build the JSON expected by dds-node's AssertionSessionRequestJson
    std::string assertionJson = "{";
    assertionJson += "\"credential_id\":\"" + credIdB64 + "\",";
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

    // Step 6: Decrypt password from vault using hmac-secret
    if (pResp->hmac_secret_len != 32)
    {
        FileLog::Writef("DdsAuth.worker: invalid hmac-secret length: %u (expected 32)\n",
                        pResp->hmac_secret_len);
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::AUTH_FAILED,
            L"Authenticator did not return hmac-secret output");
        return;
    }

    std::wstring password;
    if (!CCredentialVault::DecryptPassword(pResp->hmac_secret, pResp->hmac_secret_len,
                                            *pVaultEntry, password))
    {
        FileLog::Write("DdsAuth.worker: password decryption failed (wrong key or corrupt vault)\n");
        SendAuthError(pOp->pClientCtx, pOp->seqId, IPC_ERROR::VAULT_ERROR,
            L"Failed to decrypt stored password — re-enrollment may be required");
        return;
    }

    FileLog::Write("DdsAuth.worker: password decrypted successfully\n");

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

    wcsncpy_s(result.password, password.c_str(), _TRUNCATE);

    // Fill session token (token_cbor_b64 from Rust /v1/session/assert)
    strncpy_s(result.session_token, assertResult.tokenCborB64.c_str(), _TRUNCATE);
    // Use the DDS subject URN from the DDS_START_AUTH request, not the Windows SID.
    wcsncpy_s(result.subject_urn,
              pOp->subjectUrn.empty() ? pOp->userSid.c_str() : pOp->subjectUrn.c_str(),
              _TRUNCATE);
    result.expires_at = assertResult.expiresAt; // from dds-node response

    m_pipeServer.SendResponse(pOp->pClientCtx, IPC_MSG::DDS_AUTH_COMPLETE, pOp->seqId,
        reinterpret_cast<const BYTE*>(&result), sizeof(result));

    // Secure cleanup
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
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
    UINT32 count = static_cast<UINT32>(min(result.users.size(), maxUsers));
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
