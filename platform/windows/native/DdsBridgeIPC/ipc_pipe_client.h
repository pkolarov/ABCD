// ipc_pipe_client.h
// Named Pipe client for the DDS Bridge IPC protocol.
// Used by the Credential Provider DLL to communicate with the Bridge Service.
//
// Retains all Crayonic BLE badge methods and adds DDS-specific convenience methods.
//

#pragma once

#include "ipc_protocol.h"
#include "ipc_messages.h"

class CIpcPipeClient
{
public:
    CIpcPipeClient();
    ~CIpcPipeClient();

    // Connect to the Bridge Service pipe. Returns TRUE on success.
    // timeoutMs: maximum time to wait for the pipe to become available.
    BOOL Connect(_In_ DWORD timeoutMs = IPC_PIPE::PIPE_CONNECT_MS);

    // Disconnect from the pipe.
    void Disconnect();

    // Returns TRUE if the pipe handle is valid and connected.
    BOOL IsConnected() const;

    // Send a request message and wait for a response.
    // Returns TRUE on success. The response header and payload are written to the output params.
    // The caller must provide a response buffer large enough for the expected response.
    // timeoutMs: maximum time to wait for the response.
    BOOL SendRequest(
        _In_ UINT16 requestType,
        _In_reads_bytes_opt_(requestPayloadLen) const BYTE* pRequestPayload,
        _In_ DWORD requestPayloadLen,
        _Out_ IPC_MESSAGE_HEADER* pResponseHeader,
        _Out_writes_bytes_(responseBufferSize) BYTE* pResponseBuffer,
        _In_ DWORD responseBufferSize,
        _Out_ DWORD* pResponseBytesRead,
        _In_ DWORD timeoutMs = IPC_PIPE::AUTH_TIMEOUT_MS
    );

    // Send a request message without waiting for a response (fire-and-forget).
    BOOL SendRequestNoReply(
        _In_ UINT16 requestType,
        _In_reads_bytes_opt_(requestPayloadLen) const BYTE* pRequestPayload,
        _In_ DWORD requestPayloadLen
    );

    // Read the next message from the pipe (for receiving async progress notifications).
    // Returns TRUE if a message was read, FALSE on timeout or error.
    BOOL ReadMessage(
        _Out_ IPC_MESSAGE_HEADER* pHeader,
        _Out_writes_bytes_(bufferSize) BYTE* pBuffer,
        _In_ DWORD bufferSize,
        _Out_ DWORD* pBytesRead,
        _In_ DWORD timeoutMs
    );

    // --- Convenience methods for Crayonic BLE badge requests ---

    // Query service and device status.
    BOOL GetStatus(_Out_ IPC_RESP_STATUS* pStatus);

    // List enrolled users for tile enumeration.
    // Returns the number of users, or -1 on error.
    // ppUsers points into pResponseBuffer and is valid only while pResponseBuffer is alive.
    INT32 ListUsers(
        _Out_writes_bytes_(responseBufferSize) BYTE* pResponseBuffer,
        _In_ DWORD responseBufferSize
    );

    // Begin FIDO2 authentication for a user.
    // This is an async operation -- call ReadMessage() to receive AUTH_PROGRESS and AUTH_COMPLETE.
    BOOL StartAuthFido(
        _In_ PCWSTR pszSid,
        _In_ PCWSTR pszRpId,
        _Out_ UINT32* pSeqId
    );

    // Begin PIV authentication for a user.
    BOOL StartAuthPiv(
        _In_ PCWSTR pszSid,
        _In_reads_bytes_(challengeLen) const BYTE* pChallenge,
        _In_ DWORD challengeLen,
        _Out_ UINT32* pSeqId
    );

    // Cancel an in-progress authentication.
    BOOL CancelAuth(_In_ UINT32 targetSeqId);

    // Begin enrollment for a user (async -- call ReadMessage for ENROLL_PROGRESS / ENROLL_RESULT).
    BOOL StartEnrollUser(
        _In_ PCWSTR pszSid,
        _In_ PCWSTR pszDisplayName,
        _In_ PCWSTR pszPassword,
        _In_ PCWSTR pszRpId,
        _Out_ UINT32* pSeqId
    );

    // Remove enrollment for a user (synchronous).
    BOOL UnenrollUser(
        _In_ PCWSTR pszSid,
        _Out_opt_ IPC_RESP_ENROLL_RESULT* pResult
    );

    // Retrieve a PIV certificate.
    BOOL GetCert(
        _In_ PCWSTR pszSid,
        _In_ BYTE slot,
        _Out_ IPC_RESP_CERT_DATA* pCertData
    );

    // --- Convenience methods for DDS cloud auth requests ---

    // Begin DDS authentication for a device/credential.
    // This is an async operation -- call ReadMessage() to receive
    // DDS_AUTH_PROGRESS, DDS_AUTH_COMPLETE, or DDS_AUTH_ERROR.
    BOOL StartAuthDds(
        _In_ PCWSTR pszDeviceUrn,
        _In_ PCWSTR pszCredentialId,
        _In_ PCWSTR pszRpId,
        _Out_ UINT32* pSeqId
    );

    // List DDS users available on a device.
    // Returns the number of users, or -1 on error.
    INT32 ListDdsUsers(
        _In_ PCWSTR pszDeviceUrn,
        _Out_writes_bytes_(responseBufferSize) BYTE* pResponseBuffer,
        _In_ DWORD responseBufferSize
    );

private:
    HANDLE m_hPipe;
    UINT32 m_lastSeqId;

    BOOL WriteRaw(_In_reads_bytes_(len) const BYTE* pData, _In_ DWORD len);
    BOOL ReadRaw(_Out_writes_bytes_(bufferSize) BYTE* pBuffer, _In_ DWORD bufferSize, _Out_ DWORD* pBytesRead, _In_ DWORD timeoutMs);
};
