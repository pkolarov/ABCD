// ipc_pipe_client.cpp
// Named Pipe client implementation for the DDS Bridge IPC protocol.
//

#include "ipc_pipe_client.h"
#include <stdio.h>
#include <string.h>

namespace {
// RAII helper for CRITICAL_SECTION — keeps the per-method lock/unlock noise low
// and guarantees release on every return path.
struct CsLock
{
    CRITICAL_SECTION* cs;
    explicit CsLock(CRITICAL_SECTION* c) : cs(c) { EnterCriticalSection(cs); }
    ~CsLock() { LeaveCriticalSection(cs); }
    CsLock(const CsLock&) = delete;
    CsLock& operator=(const CsLock&) = delete;
};
} // namespace

CIpcPipeClient::CIpcPipeClient()
    : m_hPipe(INVALID_HANDLE_VALUE)
    , m_lastSeqId(0)
{
    InitializeCriticalSection(&m_cs);
}

CIpcPipeClient::~CIpcPipeClient()
{
    Disconnect();
    DeleteCriticalSection(&m_cs);
}

BOOL CIpcPipeClient::Connect(_In_ DWORD timeoutMs)
{
    CsLock lock(&m_cs);

    if (m_hPipe != INVALID_HANDLE_VALUE)
    {
        return TRUE; // Already connected
    }

    // Wait for the pipe to become available
    if (!WaitNamedPipeW(IPC_PIPE::PIPE_NAME, timeoutMs))
    {
        DWORD err = GetLastError();
        // Log to C:\Temp for diagnostics (visible after reboot)
        {
            CreateDirectoryA("C:\\Temp", nullptr);
            FILE* f = nullptr; fopen_s(&f, "C:\\Temp\\dds_pipe.log", "a");
            if (f) {
                SYSTEMTIME st{}; GetLocalTime(&st);
                fprintf(f, "[%02d:%02d:%02d PID=%lu SID=%lu] WaitNamedPipe FAILED err=%lu to=%lu\n",
                        st.wHour, st.wMinute, st.wSecond,
                        GetCurrentProcessId(),
                        (ULONG)GetCurrentThreadId(),
                        err, timeoutMs);
                fclose(f);
            }
        }
        return FALSE;
    }
    {
        FILE* f = nullptr; fopen_s(&f, "C:\\Temp\\dds_pipe.log", "a");
        if (f) {
            SYSTEMTIME st{}; GetLocalTime(&st);
            fprintf(f, "[%02d:%02d:%02d PID=%lu] WaitNamedPipe OK — connecting\n",
                    st.wHour, st.wMinute, st.wSecond, GetCurrentProcessId());
            fclose(f);
        }
    }

    // FILE_FLAG_OVERLAPPED is required for ReadRaw/WriteRaw to honour their
    // timeoutMs argument. Without it, ReadFile/WriteFile ignore the OVERLAPPED
    // parameter and block synchronously — which froze LogonUI indefinitely
    // whenever the bridge accepted a connection but then stopped responding,
    // forcing the user to reboot.
    m_hPipe = CreateFileW(
        IPC_PIPE::PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,                      // No sharing
        NULL,                   // Default security
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,   // Async I/O so timeouts actually work
        NULL                    // No template
    );

    if (m_hPipe == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    // Set pipe to message-read mode
    DWORD dwMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(m_hPipe, &dwMode, NULL, NULL))
    {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    return TRUE;
}

void CIpcPipeClient::Disconnect()
{
    CsLock lock(&m_cs);
    if (m_hPipe != INVALID_HANDLE_VALUE)
    {
        CloseHandle(m_hPipe);
        m_hPipe = INVALID_HANDLE_VALUE;
    }
}

BOOL CIpcPipeClient::IsConnected() const
{
    return m_hPipe != INVALID_HANDLE_VALUE;
}

BOOL CIpcPipeClient::WriteRaw(_In_reads_bytes_(len) const BYTE* pData, _In_ DWORD len)
{
    if (m_hPipe == INVALID_HANDLE_VALUE || pData == nullptr || len == 0)
    {
        return FALSE;
    }

    // The pipe handle is opened with FILE_FLAG_OVERLAPPED, so WriteFile must
    // be supplied an OVERLAPPED structure. Bound the wait so a hung bridge
    // never blocks the LogonUI thread indefinitely.
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL)
    {
        return FALSE;
    }

    BOOL  result       = FALSE;
    DWORD bytesWritten = 0;
    const DWORD kWriteTimeoutMs = 5000;

    if (WriteFile(m_hPipe, pData, len, &bytesWritten, &ov))
    {
        result = (bytesWritten == len);
    }
    else if (GetLastError() == ERROR_IO_PENDING)
    {
        DWORD waitResult = WaitForSingleObject(ov.hEvent, kWriteTimeoutMs);
        if (waitResult == WAIT_OBJECT_0)
        {
            if (GetOverlappedResult(m_hPipe, &ov, &bytesWritten, FALSE))
            {
                result = (bytesWritten == len);
            }
        }
        else
        {
            // Timeout — cancel and drain the pending write so the OVERLAPPED
            // is safe to free.
            CancelIoEx(m_hPipe, &ov);
            GetOverlappedResult(m_hPipe, &ov, &bytesWritten, TRUE);
        }
    }

    CloseHandle(ov.hEvent);
    return result;
}

BOOL CIpcPipeClient::ReadRaw(
    _Out_writes_bytes_(bufferSize) BYTE* pBuffer,
    _In_ DWORD bufferSize,
    _Out_ DWORD* pBytesRead,
    _In_ DWORD timeoutMs)
{
    if (m_hPipe == INVALID_HANDLE_VALUE || pBuffer == nullptr || pBytesRead == nullptr)
    {
        return FALSE;
    }

    *pBytesRead = 0;

    // For timeout support, we use overlapped I/O with a wait
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (ov.hEvent == NULL)
    {
        return FALSE;
    }

    BOOL result = FALSE;
    DWORD bytesRead = 0;

    if (ReadFile(m_hPipe, pBuffer, bufferSize, &bytesRead, &ov))
    {
        *pBytesRead = bytesRead;
        result = TRUE;
    }
    else if (GetLastError() == ERROR_IO_PENDING)
    {
        DWORD waitResult = WaitForSingleObject(ov.hEvent, timeoutMs);
        if (waitResult == WAIT_OBJECT_0)
        {
            if (GetOverlappedResult(m_hPipe, &ov, &bytesRead, FALSE))
            {
                *pBytesRead = bytesRead;
                result = TRUE;
            }
        }
        else
        {
            // Timeout or error -- cancel the pending I/O
            CancelIoEx(m_hPipe, &ov);
            GetOverlappedResult(m_hPipe, &ov, &bytesRead, TRUE);
        }
    }

    CloseHandle(ov.hEvent);
    return result;
}

BOOL CIpcPipeClient::SendRequest(
    _In_ UINT16 requestType,
    _In_reads_bytes_opt_(requestPayloadLen) const BYTE* pRequestPayload,
    _In_ DWORD requestPayloadLen,
    _Out_ IPC_MESSAGE_HEADER* pResponseHeader,
    _Out_writes_bytes_(responseBufferSize) BYTE* pResponseBuffer,
    _In_ DWORD responseBufferSize,
    _Out_ DWORD* pResponseBytesRead,
    _In_ DWORD timeoutMs)
{
    if (pResponseHeader == nullptr || pResponseBuffer == nullptr || pResponseBytesRead == nullptr)
    {
        return FALSE;
    }

    // Lock around the full write+read so a concurrent caller from another
    // thread cannot consume our response or write into the middle of ours.
    CsLock lock(&m_cs);

    *pResponseBytesRead = 0;

    // Serialize and send request
    BYTE sendBuffer[IPC_PIPE::BUFFER_SIZE];
    UINT32 seqId = IpcNextSeqId();
    m_lastSeqId = seqId;

    DWORD sendLen = IpcSerializeMessage(
        sendBuffer, sizeof(sendBuffer),
        requestType, seqId,
        pRequestPayload, requestPayloadLen
    );

    if (sendLen == 0 || !WriteRaw(sendBuffer, sendLen))
    {
        return FALSE;
    }

    // Read response
    DWORD bytesRead = 0;
    if (!ReadRaw(pResponseBuffer, responseBufferSize, &bytesRead, timeoutMs))
    {
        return FALSE;
    }

    // Deserialize response header
    const BYTE* pPayload = nullptr;
    if (!IpcDeserializeHeader(pResponseBuffer, bytesRead, pResponseHeader, &pPayload))
    {
        return FALSE;
    }

    *pResponseBytesRead = bytesRead;
    return TRUE;
}

BOOL CIpcPipeClient::SendRequestNoReply(
    _In_ UINT16 requestType,
    _In_reads_bytes_opt_(requestPayloadLen) const BYTE* pRequestPayload,
    _In_ DWORD requestPayloadLen)
{
    CsLock lock(&m_cs);

    BYTE sendBuffer[IPC_PIPE::BUFFER_SIZE];
    UINT32 seqId = IpcNextSeqId();

    DWORD sendLen = IpcSerializeMessage(
        sendBuffer, sizeof(sendBuffer),
        requestType, seqId,
        pRequestPayload, requestPayloadLen
    );

    if (sendLen == 0)
    {
        return FALSE;
    }

    return WriteRaw(sendBuffer, sendLen);
}

BOOL CIpcPipeClient::SendMessageWithSeqId(
    _In_ UINT16 msgType,
    _In_ UINT32 seqId,
    _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
    _In_ DWORD payloadLen)
{
    CsLock lock(&m_cs);

    BYTE sendBuffer[IPC_PIPE::BUFFER_SIZE];

    DWORD sendLen = IpcSerializeMessage(
        sendBuffer, sizeof(sendBuffer),
        msgType, seqId,
        pPayload, payloadLen
    );

    if (sendLen == 0)
    {
        return FALSE;
    }

    return WriteRaw(sendBuffer, sendLen);
}

BOOL CIpcPipeClient::ReadMessage(
    _Out_ IPC_MESSAGE_HEADER* pHeader,
    _Out_writes_bytes_(bufferSize) BYTE* pBuffer,
    _In_ DWORD bufferSize,
    _Out_ DWORD* pBytesRead,
    _In_ DWORD timeoutMs)
{
    if (pHeader == nullptr || pBuffer == nullptr || pBytesRead == nullptr)
    {
        return FALSE;
    }

    CsLock lock(&m_cs);

    *pBytesRead = 0;

    DWORD bytesRead = 0;
    if (!ReadRaw(pBuffer, bufferSize, &bytesRead, timeoutMs))
    {
        return FALSE;
    }

    const BYTE* pPayload = nullptr;
    if (!IpcDeserializeHeader(pBuffer, bytesRead, pHeader, &pPayload))
    {
        return FALSE;
    }

    *pBytesRead = bytesRead;
    return TRUE;
}

// ============================================================================
// Convenience Methods — Crayonic BLE badge path
// ============================================================================

BOOL CIpcPipeClient::GetStatus(_Out_ IPC_RESP_STATUS* pStatus)
{
    if (pStatus == nullptr)
    {
        return FALSE;
    }

    BYTE responseBuffer[IPC_PIPE::BUFFER_SIZE];
    IPC_MESSAGE_HEADER responseHeader;
    DWORD bytesRead = 0;

    if (!SendRequest(
        IPC_MSG::GET_STATUS,
        nullptr, 0,
        &responseHeader, responseBuffer, sizeof(responseBuffer),
        &bytesRead, IPC_PIPE::PIPE_STATUS_MS))
    {
        return FALSE;
    }

    if (responseHeader.msgType != IPC_MSG::STATUS ||
        responseHeader.length < sizeof(IPC_RESP_STATUS))
    {
        return FALSE;
    }

    const BYTE* pPayload = nullptr;
    IPC_MESSAGE_HEADER hdr;
    IpcDeserializeHeader(responseBuffer, bytesRead, &hdr, &pPayload);
    if (pPayload != nullptr)
    {
        memcpy(pStatus, pPayload, sizeof(IPC_RESP_STATUS));
    }

    return TRUE;
}

INT32 CIpcPipeClient::ListUsers(
    _Out_writes_bytes_(responseBufferSize) BYTE* pResponseBuffer,
    _In_ DWORD responseBufferSize)
{
    IPC_MESSAGE_HEADER responseHeader;
    DWORD bytesRead = 0;

    if (!SendRequest(
        IPC_MSG::LIST_USERS,
        nullptr, 0,
        &responseHeader, pResponseBuffer, responseBufferSize,
        &bytesRead, IPC_PIPE::PIPE_STATUS_MS))
    {
        return -1;
    }

    if (responseHeader.msgType != IPC_MSG::USER_LIST)
    {
        return -1;
    }

    const BYTE* pPayload = nullptr;
    IPC_MESSAGE_HEADER hdr;
    IpcDeserializeHeader(pResponseBuffer, bytesRead, &hdr, &pPayload);
    if (pPayload == nullptr || hdr.length < sizeof(IPC_RESP_USER_LIST))
    {
        return -1;
    }

    const IPC_RESP_USER_LIST* pUserList = reinterpret_cast<const IPC_RESP_USER_LIST*>(pPayload);
    return (INT32)pUserList->userCount;
}

BOOL CIpcPipeClient::StartAuthFido(
    _In_ PCWSTR pszSid,
    _In_ PCWSTR pszRpId,
    _Out_ UINT32* pSeqId)
{
    if (pszSid == nullptr || pszRpId == nullptr || pSeqId == nullptr)
    {
        return FALSE;
    }

    CsLock lock(&m_cs);

    IPC_REQ_START_AUTH_FIDO req = {};
    wcsncpy_s(req.sid, pszSid, _TRUNCATE);
    wcsncpy_s(req.rpId, pszRpId, _TRUNCATE);

    BYTE sendBuffer[IPC_PIPE::BUFFER_SIZE];
    UINT32 seqId = IpcNextSeqId();
    *pSeqId = seqId;

    DWORD sendLen = IpcSerializeMessage(
        sendBuffer, sizeof(sendBuffer),
        IPC_MSG::START_AUTH_FIDO, seqId,
        reinterpret_cast<const BYTE*>(&req), sizeof(req)
    );

    if (sendLen == 0)
    {
        return FALSE;
    }

    return WriteRaw(sendBuffer, sendLen);
}

BOOL CIpcPipeClient::StartAuthPiv(
    _In_ PCWSTR pszSid,
    _In_reads_bytes_(challengeLen) const BYTE* pChallenge,
    _In_ DWORD challengeLen,
    _Out_ UINT32* pSeqId)
{
    if (pszSid == nullptr || pChallenge == nullptr || pSeqId == nullptr || challengeLen > 32)
    {
        return FALSE;
    }

    CsLock lock(&m_cs);

    IPC_REQ_START_AUTH_PIV req = {};
    wcsncpy_s(req.sid, pszSid, _TRUNCATE);
    memcpy(req.challenge, pChallenge, challengeLen);
    req.challengeLen = challengeLen;

    BYTE sendBuffer[IPC_PIPE::BUFFER_SIZE];
    UINT32 seqId = IpcNextSeqId();
    *pSeqId = seqId;

    DWORD sendLen = IpcSerializeMessage(
        sendBuffer, sizeof(sendBuffer),
        IPC_MSG::START_AUTH_PIV, seqId,
        reinterpret_cast<const BYTE*>(&req), sizeof(req)
    );

    if (sendLen == 0)
    {
        return FALSE;
    }

    return WriteRaw(sendBuffer, sendLen);
}

BOOL CIpcPipeClient::CancelAuth(_In_ UINT32 targetSeqId)
{
    IPC_REQ_CANCEL_AUTH req = {};
    req.targetSeqId = targetSeqId;

    return SendRequestNoReply(
        IPC_MSG::CANCEL_AUTH,
        reinterpret_cast<const BYTE*>(&req), sizeof(req)
    );
}

BOOL CIpcPipeClient::GetCert(
    _In_ PCWSTR pszSid,
    _In_ BYTE slot,
    _Out_ IPC_RESP_CERT_DATA* pCertData)
{
    if (pszSid == nullptr || pCertData == nullptr)
    {
        return FALSE;
    }

    IPC_REQ_GET_CERT req = {};
    wcsncpy_s(req.sid, pszSid, _TRUNCATE);
    req.slot = slot;

    BYTE responseBuffer[IPC_PIPE::BUFFER_SIZE];
    IPC_MESSAGE_HEADER responseHeader;
    DWORD bytesRead = 0;

    if (!SendRequest(
        IPC_MSG::GET_CERT,
        reinterpret_cast<const BYTE*>(&req), sizeof(req),
        &responseHeader, responseBuffer, sizeof(responseBuffer),
        &bytesRead, IPC_PIPE::AUTH_TIMEOUT_MS))
    {
        return FALSE;
    }

    if (responseHeader.msgType != IPC_MSG::CERT_DATA)
    {
        return FALSE;
    }

    const BYTE* pPayload = nullptr;
    IPC_MESSAGE_HEADER hdr;
    IpcDeserializeHeader(responseBuffer, bytesRead, &hdr, &pPayload);
    if (pPayload == nullptr || hdr.length < sizeof(IPC_RESP_CERT_DATA))
    {
        return FALSE;
    }

    memcpy(pCertData, pPayload, sizeof(IPC_RESP_CERT_DATA));
    return TRUE;
}

// ============================================================================
// StartEnrollUser -- async enrollment (like StartAuthFido)
// ============================================================================

BOOL CIpcPipeClient::StartEnrollUser(
    _In_ PCWSTR pszSid,
    _In_ PCWSTR pszDisplayName,
    _In_ PCWSTR pszPassword,
    _In_ PCWSTR pszRpId,
    _Out_ UINT32* pSeqId)
{
    if (!pszSid || !pszDisplayName || !pszPassword || !pSeqId)
        return FALSE;

    CsLock lock(&m_cs);

    IPC_REQ_ENROLL_USER req{};
    wcsncpy_s(req.sid,         pszSid,         _TRUNCATE);
    wcsncpy_s(req.displayName, pszDisplayName, _TRUNCATE);
    wcsncpy_s(req.password,    pszPassword,    _TRUNCATE);
    wcsncpy_s(req.rpId,        pszRpId && pszRpId[0] ? pszRpId : L"crayonic.local.login", _TRUNCATE);

    UINT32 seqId = IpcNextSeqId();
    m_lastSeqId  = seqId;
    *pSeqId = seqId;

    BYTE sendBuffer[IPC_PIPE::BUFFER_SIZE]{};
    DWORD sendLen = IpcSerializeMessage(sendBuffer, sizeof(sendBuffer),
        IPC_MSG::ENROLL_USER, seqId,
        reinterpret_cast<const BYTE*>(&req), sizeof(req));

    // Zero the password from the send buffer after serialisation
    // (password is at a fixed offset inside req, which was copied into sendBuffer)
    SecureZeroMemory(req.password, sizeof(req.password));

    if (!sendLen) return FALSE;
    return WriteRaw(sendBuffer, sendLen);
}

// ============================================================================
// UnenrollUser -- synchronous
// ============================================================================

BOOL CIpcPipeClient::UnenrollUser(
    _In_ PCWSTR pszSid,
    _Out_opt_ IPC_RESP_ENROLL_RESULT* pResult)
{
    if (!pszSid) return FALSE;

    IPC_REQ_UNENROLL_USER req{};
    wcsncpy_s(req.sid, pszSid, _TRUNCATE);

    BYTE respBuf[IPC_PIPE::BUFFER_SIZE]{};
    IPC_MESSAGE_HEADER respHdr{};
    DWORD bytesRead = 0;

    if (!SendRequest(IPC_MSG::UNENROLL_USER,
        reinterpret_cast<const BYTE*>(&req), sizeof(req),
        &respHdr, respBuf, sizeof(respBuf), &bytesRead, 10000))
        return FALSE;

    if (pResult && respHdr.msgType == IPC_MSG::ENROLL_RESULT)
    {
        const BYTE* pPayload = nullptr;
        IPC_MESSAGE_HEADER hdr{};
        IpcDeserializeHeader(respBuf, bytesRead, &hdr, &pPayload);
        if (pPayload && hdr.length >= sizeof(IPC_RESP_ENROLL_RESULT))
            memcpy(pResult, pPayload, sizeof(IPC_RESP_ENROLL_RESULT));
    }
    return TRUE;
}

// ============================================================================
// Convenience Methods — DDS cloud auth path
// ============================================================================

BOOL CIpcPipeClient::StartAuthDds(
    _In_ PCWSTR pszDeviceUrn,
    _In_ PCWSTR pszCredentialId,
    _In_ PCWSTR pszRpId,
    _Out_ UINT32* pSeqId)
{
    if (pszDeviceUrn == nullptr || pszCredentialId == nullptr || pszRpId == nullptr || pSeqId == nullptr)
    {
        return FALSE;
    }

    CsLock lock(&m_cs);

    IPC_REQ_DDS_START_AUTH req = {};
    wcsncpy_s(req.device_urn,    pszDeviceUrn,    _TRUNCATE);
    wcsncpy_s(req.credential_id, pszCredentialId,  _TRUNCATE);
    wcsncpy_s(req.rp_id,         pszRpId,          _TRUNCATE);

    BYTE sendBuffer[IPC_PIPE::BUFFER_SIZE];
    UINT32 seqId = IpcNextSeqId();
    m_lastSeqId = seqId;
    *pSeqId = seqId;

    DWORD sendLen = IpcSerializeMessage(
        sendBuffer, sizeof(sendBuffer),
        IPC_MSG::DDS_START_AUTH, seqId,
        reinterpret_cast<const BYTE*>(&req), sizeof(req)
    );

    if (sendLen == 0)
    {
        return FALSE;
    }

    return WriteRaw(sendBuffer, sendLen);
}

INT32 CIpcPipeClient::ListDdsUsers(
    _In_ PCWSTR pszDeviceUrn,
    _Out_writes_bytes_(responseBufferSize) BYTE* pResponseBuffer,
    _In_ DWORD responseBufferSize)
{
    if (pszDeviceUrn == nullptr || pResponseBuffer == nullptr)
    {
        return -1;
    }

    IPC_REQ_DDS_LIST_USERS req = {};
    wcsncpy_s(req.device_urn, pszDeviceUrn, _TRUNCATE);

    IPC_MESSAGE_HEADER responseHeader;
    DWORD bytesRead = 0;

    if (!SendRequest(
        IPC_MSG::DDS_LIST_USERS,
        reinterpret_cast<const BYTE*>(&req), sizeof(req),
        &responseHeader, pResponseBuffer, responseBufferSize,
        &bytesRead, IPC_PIPE::PIPE_STATUS_MS))
    {
        return -1;
    }

    if (responseHeader.msgType != IPC_MSG::DDS_USER_LIST)
    {
        return -1;
    }

    const BYTE* pPayload = nullptr;
    IPC_MESSAGE_HEADER hdr;
    IpcDeserializeHeader(pResponseBuffer, bytesRead, &hdr, &pPayload);
    if (pPayload == nullptr || hdr.length < sizeof(IPC_RESP_DDS_USER_LIST))
    {
        return -1;
    }

    const IPC_RESP_DDS_USER_LIST* pUserList = reinterpret_cast<const IPC_RESP_DDS_USER_LIST*>(pPayload);
    return (INT32)pUserList->count;
}
