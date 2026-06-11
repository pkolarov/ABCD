// ipc_pipe_client.cpp
// Named Pipe client implementation for the DDS Bridge IPC protocol.
//

#include "ipc_pipe_client.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

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

// AUDIT-2026-06-11 #6: verify the named-pipe SERVER is the LocalSystem
// (SID S-1-5-18) DdsAuthBridge service and not a low-priv squatter that
// pre-created the pipe to capture plaintext logon passwords. The server adds
// FILE_FLAG_FIRST_PIPE_INSTANCE so it can never attach to a squatted name,
// but a squatter could still create the name first and have the bridge fail
// to start; in that case the CP must refuse to talk to the impostor. We pull
// the server process id off the connected handle, open the process, read its
// token user SID, and require it to equal LocalSystem.
bool ServerIsLocalSystem(HANDLE hPipe)
{
    if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL)
        return false;

    ULONG serverPid = 0;
    if (!GetNamedPipeServerProcessId(hPipe, &serverPid) || serverPid == 0)
        return false;

    // PROCESS_QUERY_LIMITED_INFORMATION is sufficient to open the token and is
    // grantable across integrity levels for a SYSTEM process when the caller is
    // SYSTEM (the CP runs in winlogon.exe as SYSTEM).
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, serverPid);
    if (hProc == NULL)
        return false;

    bool isSystem = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
    {
        DWORD len = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
        if (len > 0)
        {
            BYTE* buf = static_cast<BYTE*>(LocalAlloc(LMEM_FIXED, len));
            if (buf != nullptr)
            {
                if (GetTokenInformation(hToken, TokenUser, buf, len, &len))
                {
                    PSID pTokenSid = reinterpret_cast<TOKEN_USER*>(buf)->User.Sid;

                    // Build the well-known LocalSystem SID (S-1-5-18) and compare.
                    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
                    PSID pSystemSid = NULL;
                    if (AllocateAndInitializeSid(&ntAuth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                                 0, 0, 0, 0, 0, 0, 0, &pSystemSid))
                    {
                        isSystem = (EqualSid(pTokenSid, pSystemSid) == TRUE);
                        FreeSid(pSystemSid);
                    }
                }
                LocalFree(buf);
            }
        }
        CloseHandle(hToken);
    }

    CloseHandle(hProc);
    return isSystem;
}

// AUDIT-2026-06-11 #14 (same world-readable-diagnostic-log class as the
// CDdsProvider.cpp CPLog finding): the Connect() diagnostics previously went
// to C:\Temp\dds_pipe.log with no DACL, so any local user could read
// boot-time pipe diagnostics emitted from the winlogon-hosted SYSTEM
// credential provider. Write to %ProgramData%\DDS\logs\dds_pipe.log instead,
// with the protected DACL granting FullControl only to LocalSystem and
// BUILTIN\Administrators — mirrors CDdsProvider.cpp's CPLogPath() and
// DdsAuthBridge/FileLog.cpp's ApplyRestrictedDacl(). When this code runs in
// a non-privileged process (e.g. the tray agent), opening the log simply
// fails and the write is silently skipped.

// Resolve %ProgramData%\DDS\logs\dds_pipe.log once, creating the directory
// with the protected DACL. Returns the path, or "" on failure.
const wchar_t* PipeLogPath()
{
    static wchar_t g_pipeLogPath[MAX_PATH] = L"";
    static bool    g_resolved = false;
    if (g_resolved)
        return g_pipeLogPath;
    g_resolved = true;

    wchar_t programData[MAX_PATH] = {0};
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programData) != S_OK)
        wcscpy_s(programData, L"C:\\ProgramData");

    wchar_t parent[MAX_PATH];
    swprintf_s(parent, L"%s\\DDS", programData);
    wchar_t dir[MAX_PATH];
    swprintf_s(dir, L"%s\\DDS\\logs", programData);
    CreateDirectoryW(parent, NULL);
    CreateDirectoryW(dir, NULL);

    // SY -> LocalSystem, BA -> BUILTIN\Administrators; PAI = protected +
    // non-inherited; OICI propagates to files created inside.
    const wchar_t* sddl = L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &pSD, nullptr))
    {
        BOOL daclPresent = FALSE, daclDefaulted = FALSE;
        PACL pDacl = nullptr;
        if (GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted) &&
            daclPresent)
        {
            SetNamedSecurityInfoW(dir, SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, pDacl, nullptr);
        }
        LocalFree(pSD);
    }

    swprintf_s(g_pipeLogPath, L"%s\\dds_pipe.log", dir);
    return g_pipeLogPath;
}

void PipeLog(const char* fmt, ...)
{
    const wchar_t* path = PipeLogPath();
    if (path[0] == L'\0') return;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"a") != 0 || !f) return;
    SYSTEMTIME st{}; GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d PID=%lu TID=%lu] ",
            st.wHour, st.wMinute, st.wSecond,
            GetCurrentProcessId(), GetCurrentThreadId());
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f);
    fclose(f);
}
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

    // Wait for the pipe to become available.
    //
    // WaitNamedPipeW honours its timeout only when the pipe object exists but
    // every instance is busy. If the pipe does not exist yet, it returns
    // immediately with ERROR_FILE_NOT_FOUND — which is exactly the boot-time
    // race where LogonUI loads the credential provider before the SCM has
    // finished starting DdsAuthBridge. Poll WaitNamedPipeW until either it
    // succeeds or the caller's timeout elapses.
    DWORD err = ERROR_SUCCESS;
    BOOL  available = FALSE;
    {
        const ULONGLONG startTick = GetTickCount64();
        for (;;)
        {
            const ULONGLONG elapsed = GetTickCount64() - startTick;
            if (elapsed >= timeoutMs) { err = ERROR_SEM_TIMEOUT; break; }

            DWORD remaining = (DWORD)(timeoutMs - elapsed);
            DWORD slice = remaining < 100 ? remaining : 100;

            if (WaitNamedPipeW(IPC_PIPE::PIPE_NAME, slice))
            {
                available = TRUE;
                break;
            }
            err = GetLastError();
            if (err == ERROR_FILE_NOT_FOUND)
            {
                // Pipe not yet created — back off and retry within the budget.
                Sleep(50);
                continue;
            }
            if (err == ERROR_SEM_TIMEOUT)
            {
                // Slice expired; loop checks overall deadline.
                continue;
            }
            // Anything else: unrecoverable.
            break;
        }
    }

    // AUDIT-2026-06-11 #14: diagnostics go to the DACL-protected PipeLog —
    // never to world-readable C:\Temp.
    if (!available)
    {
        PipeLog("WaitNamedPipe FAILED err=%lu to=%lu", err, timeoutMs);
        return FALSE;
    }
    PipeLog("WaitNamedPipe OK — connecting");

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

    // AUDIT-2026-06-11 #6: verify the connected server is the LocalSystem
    // DdsAuthBridge service before sending any request. A squatter that
    // pre-created the pipe name would be running at a lower privilege; refuse
    // to hand it FIDO2 assertions / plaintext passwords. This runs on every
    // (re)connect so the named-pipe instance race cannot be exploited.
    if (!ServerIsLocalSystem(m_hPipe))
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

    // AUDIT-2026-06-11 #18: do NOT trust pUserList->count verbatim. The caller
    // (CDdsBridgeClient::ListDdsUsers) reads `count` IPC_DDS_USER_ENTRY structs
    // straight out of the fixed pipe buffer; a malicious/buggy server could send
    // a header that passes length validation but declares more entries than were
    // actually received, causing an out-of-bounds read inside winlogon. Require
    // header + count*sizeof(entry) to fit within the validated payload length
    // (hdr.length, already bounded against bytesRead and BUFFER_SIZE by
    // IpcDeserializeHeader). Reject on mismatch rather than clamp so a corrupt
    // frame is never partially trusted.
    const DWORD count = pUserList->count;
    const DWORD maxEntries =
        (hdr.length - (DWORD)sizeof(IPC_RESP_DDS_USER_LIST)) / (DWORD)sizeof(IPC_DDS_USER_ENTRY);
    if (count > maxEntries)
    {
        return -1;
    }
    return (INT32)count;
}
