// DdsAuthBridgeMain.h
// Main coordinator for the DDS Auth Bridge Service.
// Manages the IPC pipe server, credential vault, CTAP2 engine,
// and dds-node HTTP client.
//
// Forked from Crayonic BridgeServiceMain.h with BLE removed and
// dds-node HTTP client added.
//

#pragma once

#include <windows.h>
#include "../DdsBridgeIPC/ipc_pipe_server.h"
#include "../DdsBridgeIPC/ipc_messages.h"
#include "Configuration.h"
#include "CredentialVault.h"
#include "DdsNodeHttpClient.h"
#include "ctap2/ctap2_protocol.h"
#include "ctap2/ctap2_pin_protocol.h"

// Tracks an in-progress authentication operation.
struct AuthOperation
{
    IPC_CLIENT_CONTEXT* pClientCtx; // Client that initiated the auth
    UINT32              seqId;      // IPC sequence ID for correlating progress/result
    UINT32              authMethod; // IPC_AUTH_METHOD::FIDO2
    std::string         deviceUrn;  // DDS device URN for this endpoint
    std::wstring        userSid;    // Target user SID (for vault lookup)
    std::wstring        subjectUrn; // DDS subject URN (for auth complete response)
    std::wstring        credentialId; // FIDO2 credential ID from DDS_START_AUTH
    std::string         rpId;       // FIDO2 relying party ID
    BOOL                claimMode;  // TRUE when no vault entry exists yet
    BYTE                claimSalt[IPC_MAX_SALT_LEN]; // hmac-secret salt for first claim
    DWORD               claimSaltLen; // Actual claimSalt length
    HANDLE              hThread;    // Worker thread handle
    volatile BOOL       cancelled;  // Set to TRUE to cancel

    // Two-phase challenge/response: set by HandleDdsAuthResponse
    HANDLE              hResponseEvent; // Signaled when CP sends DDS_AUTH_RESPONSE
    IPC_REQ_DDS_AUTH_RESPONSE responseData; // Filled by HandleDdsAuthResponse
    BOOL                responseReceived;   // TRUE once responseData is valid
};

class CDdsAuthBridgeMain
{
public:
    CDdsAuthBridgeMain();
    ~CDdsAuthBridgeMain();

    // Initialize all subsystems. Must be called before Start().
    // hStopEvent: signaled when the service should shut down.
    BOOL Initialize(_In_ HANDLE hStopEvent);

    // Start the IPC server.
    BOOL Start();

    // Stop all subsystems and clean up.
    void Shutdown();

    // --- Vault access (for enrollment) ---

    CCredentialVault* GetVault() { return &m_vault; }

private:
    HANDLE              m_hStopEvent;
    CIpcPipeServer      m_pipeServer;
    CDdsConfiguration   m_config;
    CCredentialVault    m_vault;
    CDdsNodeHttpClient  m_httpClient;
    BOOL                m_bInitialized;

    // Active auth operation (one at a time)
    AuthOperation       m_activeAuth;
    CRITICAL_SECTION    m_csAuth;

    // IPC request handler callback
    static BOOL CALLBACK OnIpcRequest(
        _In_ IPC_CLIENT_CONTEXT* pClientCtx,
        _In_ const IPC_MESSAGE_HEADER* pHeader,
        _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
        _In_ DWORD payloadLen,
        _In_opt_ void* pUserContext
    );

    // Handle individual message types

    // --- DDS-specific handlers ---
    BOOL HandleDdsStartAuth(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId,
        _In_ const BYTE* pPayload, _In_ DWORD payloadLen);
    BOOL HandleDdsAuthResponse(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId,
        _In_ const BYTE* pPayload, _In_ DWORD payloadLen);
    BOOL HandleDdsListUsers(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId);

    // --- Legacy Crayonic handlers (kept for backwards compat) ---
    BOOL HandleGetStatus(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId);
    BOOL HandleListUsers(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId);
    BOOL HandleStartAuthFido(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId, _In_ const IPC_REQ_START_AUTH_FIDO* pReq);
    BOOL HandleCancelAuth(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId, _In_ const IPC_REQ_CANCEL_AUTH* pReq);
    BOOL HandleEnrollUser(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId, _In_ const IPC_REQ_ENROLL_USER* pReq);
    BOOL HandleUnenrollUser(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId, _In_ const IPC_REQ_UNENROLL_USER* pReq);

    // DDS auth worker thread
    static DWORD WINAPI DdsAuthWorkerThread(_In_ LPVOID pParam);
    void ExecuteDdsAuth(_In_ AuthOperation* pOp);

    // Send auth progress notification to client
    void SendAuthProgress(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId,
        _In_ UINT32 state, _In_ PCWSTR message);

    // Send auth error to client
    void SendAuthError(_In_ IPC_CLIENT_CONTEXT* pClientCtx, _In_ UINT32 seqId,
        _In_ UINT32 errorCode, _In_ PCWSTR message);

    // Determine if this machine is domain-joined
    static BOOL IsDomainJoined();
};
