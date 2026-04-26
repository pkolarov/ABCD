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
#include <map>
#include <string>
#include "../DdsBridgeIPC/ipc_pipe_server.h"
#include "../DdsBridgeIPC/ipc_messages.h"
#include "Configuration.h"
#include "CredentialVault.h"
#include "DdsNodeHttpClient.h"
#include "JoinState.h"
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

    // AD-14 — fire-and-forget post-logon NTSTATUS report from CP::ReportResult.
    BOOL HandleDdsReportLogonResult(_In_ const BYTE* pPayload, _In_ DWORD payloadLen);

    // AD-13 — fire-and-forget cooldown clear from the tray after refresh.
    BOOL HandleDdsClearStale(_In_ const BYTE* pPayload, _In_ DWORD payloadLen);

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

    // Determine the host's directory join classification.
    // See docs/windows-ad-coexistence-spec.md §2 for the contract.
    static dds::JoinState GetJoinState();

    // --- AD-14: stale-vault cooldown ---
    //
    // Default cooldown duration. Spec §4.5 calls for 15 minutes (900 s) so the
    // bridge cools off well before the AD lockout reset window. Configurable
    // via the AuthBridge registry value `StaleVaultCooldownMs` for hardened
    // deployments that need a different value; loaded at startup.
    static constexpr ULONGLONG STALE_COOLDOWN_DEFAULT_MS = 15ULL * 60ULL * 1000ULL;

    CRITICAL_SECTION                      m_csCooldown;
    std::map<std::wstring, ULONGLONG>     m_staleCooldown; // key = lowered base64url credential_id, value = expiry tick (GetTickCount64)
    ULONGLONG                             m_staleCooldownMs;

    // Mark `(credential_id)` as stale until now + STALE_COOLDOWN_*_MS.
    void MarkStaleCooldown(_In_ const std::wstring& credentialId);

    // Return TRUE if a non-expired cooldown entry exists for `credential_id`.
    // Always prunes the entry when expired, so the map cannot grow unbounded.
    BOOL IsStaleCooldownActive(_In_ const std::wstring& credentialId);

    // Remove any cooldown entry for `credential_id` (no-op if absent).
    void ClearStaleCooldown(_In_ const std::wstring& credentialId);

    // Translate an NTSTATUS reported by CP::ReportResult into the
    // canonical IPC error code, or 0 if the status does not indicate a
    // stale/expired/must-change AD password situation.
    static UINT32 NtStatusToStaleError(_In_ INT32 ntStatus);
};
