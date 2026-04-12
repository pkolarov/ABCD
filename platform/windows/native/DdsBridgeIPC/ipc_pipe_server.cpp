// ipc_pipe_server.cpp
// Named Pipe server implementation for the DDS Bridge IPC protocol.
//

#include "ipc_pipe_server.h"
#include <aclapi.h>
#include <sddl.h>
#include <string.h>
#include <new>       // std::nothrow

CIpcPipeServer::CIpcPipeServer()
    : m_pfnHandler(nullptr)
    , m_pUserContext(nullptr)
    , m_hStopEvent(NULL)
    , m_hListenerThread(NULL)
    , m_bRunning(FALSE)
    , m_clientCount(0)
    , m_nextClientId(1)
{
    ZeroMemory(m_clients, sizeof(m_clients));
    InitializeCriticalSection(&m_csClients);
}

CIpcPipeServer::~CIpcPipeServer()
{
    Stop();
    DeleteCriticalSection(&m_csClients);
}

BOOL CIpcPipeServer::Initialize(
    _In_ PFN_IPC_REQUEST_HANDLER pfnHandler,
    _In_opt_ void* pUserContext)
{
    if (pfnHandler == nullptr)
    {
        return FALSE;
    }

    m_pfnHandler = pfnHandler;
    m_pUserContext = pUserContext;

    m_hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (m_hStopEvent == NULL)
    {
        return FALSE;
    }

    return TRUE;
}

BOOL CIpcPipeServer::Start()
{
    if (m_bRunning || m_hStopEvent == NULL)
    {
        return FALSE;
    }

    ResetEvent(m_hStopEvent);
    m_bRunning = TRUE;

    m_hListenerThread = CreateThread(NULL, 0, ListenerThreadProc, this, 0, NULL);
    if (m_hListenerThread == NULL)
    {
        m_bRunning = FALSE;
        return FALSE;
    }

    return TRUE;
}

void CIpcPipeServer::Stop()
{
    if (!m_bRunning)
    {
        return;
    }

    m_bRunning = FALSE;

    if (m_hStopEvent != NULL)
    {
        SetEvent(m_hStopEvent);
    }

    // Wait for listener thread to exit
    if (m_hListenerThread != NULL)
    {
        WaitForSingleObject(m_hListenerThread, 5000);
        CloseHandle(m_hListenerThread);
        m_hListenerThread = NULL;
    }

    // Disconnect all clients
    EnterCriticalSection(&m_csClients);
    for (DWORD i = 0; i < IPC_PIPE::MAX_INSTANCES; i++)
    {
        if (m_clients[i].hPipe != NULL && m_clients[i].hPipe != INVALID_HANDLE_VALUE)
        {
            DisconnectNamedPipe(m_clients[i].hPipe);
            CloseHandle(m_clients[i].hPipe);
            m_clients[i].hPipe = NULL;
            if (m_clients[i].ov.hEvent != NULL)
            {
                CloseHandle(m_clients[i].ov.hEvent);
                m_clients[i].ov.hEvent = NULL;
            }
        }
    }
    m_clientCount = 0;
    LeaveCriticalSection(&m_csClients);

    if (m_hStopEvent != NULL)
    {
        CloseHandle(m_hStopEvent);
        m_hStopEvent = NULL;
    }
}

HANDLE CIpcPipeServer::CreatePipeInstance()
{
    PSECURITY_DESCRIPTOR pSD = nullptr;
    PSECURITY_ATTRIBUTES pSA = nullptr;

    if (!CreatePipeSecurity(&pSD, &pSA))
    {
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hPipe = CreateNamedPipeW(
        IPC_PIPE::PIPE_NAME,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        IPC_PIPE::MAX_INSTANCES,
        IPC_PIPE::BUFFER_SIZE,
        IPC_PIPE::BUFFER_SIZE,
        0,
        pSA
    );

    FreePipeSecurity(pSD, pSA);
    return hPipe;
}

BOOL CIpcPipeServer::CreatePipeSecurity(
    _Out_ PSECURITY_DESCRIPTOR* ppSD,
    _Out_ PSECURITY_ATTRIBUTES* ppSA)
{
    // SDDL: Allow SYSTEM (SY) and INTERACTIVE (IU) full access, deny all others
    // D: DACL
    // (A;;GA;;;SY) - Allow Generic All to SYSTEM
    // (A;;GA;;;IU) - Allow Generic All to INTERACTIVE (LogonUI sessions)
    PCWSTR pszSDDL = L"D:(A;;GA;;;SY)(A;;GA;;;IU)";

    PSECURITY_DESCRIPTOR pSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        pszSDDL, SDDL_REVISION_1, &pSD, NULL))
    {
        return FALSE;
    }

    PSECURITY_ATTRIBUTES pSA = (PSECURITY_ATTRIBUTES)LocalAlloc(LMEM_FIXED, sizeof(SECURITY_ATTRIBUTES));
    if (pSA == nullptr)
    {
        LocalFree(pSD);
        return FALSE;
    }

    pSA->nLength = sizeof(SECURITY_ATTRIBUTES);
    pSA->lpSecurityDescriptor = pSD;
    pSA->bInheritHandle = FALSE;

    *ppSD = pSD;
    *ppSA = pSA;
    return TRUE;
}

void CIpcPipeServer::FreePipeSecurity(
    _In_ PSECURITY_DESCRIPTOR pSD,
    _In_ PSECURITY_ATTRIBUTES pSA)
{
    if (pSD != nullptr) LocalFree(pSD);
    if (pSA != nullptr) LocalFree(pSA);
}

// ============================================================================
// Listener Thread
// ============================================================================

DWORD WINAPI CIpcPipeServer::ListenerThreadProc(_In_ LPVOID pParam)
{
    CIpcPipeServer* pServer = static_cast<CIpcPipeServer*>(pParam);
    return pServer->ListenerThread();
}

DWORD CIpcPipeServer::ListenerThread()
{
    while (m_bRunning)
    {
        // Create a new pipe instance for the next client
        HANDLE hPipe = CreatePipeInstance();
        if (hPipe == INVALID_HANDLE_VALUE)
        {
            // Failed to create pipe, wait briefly and retry
            if (WaitForSingleObject(m_hStopEvent, 1000) == WAIT_OBJECT_0)
            {
                break;
            }
            continue;
        }

        // Wait for a client to connect
        OVERLAPPED ov = {};
        ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (ov.hEvent == NULL)
        {
            CloseHandle(hPipe);
            continue;
        }

        BOOL connected = ConnectNamedPipe(hPipe, &ov);
        if (!connected)
        {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING)
            {
                // Wait for connection or stop event
                HANDLE waitHandles[2] = { ov.hEvent, m_hStopEvent };
                DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

                if (waitResult == WAIT_OBJECT_0)
                {
                    // Client connected
                    connected = TRUE;
                }
                else
                {
                    // Stop event or error
                    CancelIoEx(hPipe, &ov);
                    CloseHandle(ov.hEvent);
                    CloseHandle(hPipe);
                    break;
                }
            }
            else if (err == ERROR_PIPE_CONNECTED)
            {
                // Client already connected before ConnectNamedPipe was called
                connected = TRUE;
            }
        }

        CloseHandle(ov.hEvent);

        if (connected)
        {
            // Find a free client slot
            IPC_CLIENT_CONTEXT* pClientCtx = nullptr;

            EnterCriticalSection(&m_csClients);
            for (DWORD i = 0; i < IPC_PIPE::MAX_INSTANCES; i++)
            {
                if (m_clients[i].hPipe == NULL || m_clients[i].hPipe == INVALID_HANDLE_VALUE)
                {
                    pClientCtx = &m_clients[i];
                    ZeroMemory(pClientCtx, sizeof(IPC_CLIENT_CONTEXT));
                    pClientCtx->hPipe = hPipe;
                    pClientCtx->clientId = m_nextClientId++;
                    pClientCtx->ov.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
                    m_clientCount++;
                    break;
                }
            }
            LeaveCriticalSection(&m_csClients);

            if (pClientCtx != nullptr)
            {
                // Spawn a handler thread for this client
                CLIENT_THREAD_PARAMS* pParams = new (std::nothrow) CLIENT_THREAD_PARAMS;
                if (pParams != nullptr)
                {
                    pParams->pServer = this;
                    pParams->pClientCtx = pClientCtx;

                    HANDLE hThread = CreateThread(NULL, 0, ClientThreadProc, pParams, 0, NULL);
                    if (hThread != NULL)
                    {
                        CloseHandle(hThread); // Let it run detached
                    }
                    else
                    {
                        delete pParams;
                        RemoveClient(pClientCtx);
                    }
                }
            }
            else
            {
                // No free slots -- reject client
                DisconnectNamedPipe(hPipe);
                CloseHandle(hPipe);
            }
        }
    }

    return 0;
}

// ============================================================================
// Client Handler Thread
// ============================================================================

DWORD WINAPI CIpcPipeServer::ClientThreadProc(_In_ LPVOID pParam)
{
    CLIENT_THREAD_PARAMS* pParams = static_cast<CLIENT_THREAD_PARAMS*>(pParam);
    pParams->pServer->HandleClient(pParams->pClientCtx);
    delete pParams;
    return 0;
}

void CIpcPipeServer::HandleClient(_In_ IPC_CLIENT_CONTEXT* pClientCtx)
{
    while (m_bRunning)
    {
        DWORD bytesRead = 0;
        BOOL success = ReadFile(
            pClientCtx->hPipe,
            pClientCtx->readBuffer,
            sizeof(pClientCtx->readBuffer),
            &bytesRead,
            &pClientCtx->ov
        );

        if (!success)
        {
            DWORD err = GetLastError();
            if (err == ERROR_IO_PENDING)
            {
                HANDLE waitHandles[2] = { pClientCtx->ov.hEvent, m_hStopEvent };
                DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

                if (waitResult == WAIT_OBJECT_0)
                {
                    if (!GetOverlappedResult(pClientCtx->hPipe, &pClientCtx->ov, &bytesRead, FALSE))
                    {
                        break; // Read failed
                    }
                }
                else
                {
                    // Stop event
                    CancelIoEx(pClientCtx->hPipe, &pClientCtx->ov);
                    break;
                }
            }
            else
            {
                break; // Pipe broken or client disconnected
            }
        }

        if (bytesRead == 0)
        {
            break; // Client disconnected
        }

        // Deserialize the message
        IPC_MESSAGE_HEADER header;
        const BYTE* pPayload = nullptr;

        if (!IpcDeserializeHeader(pClientCtx->readBuffer, bytesRead, &header, &pPayload))
        {
            continue; // Malformed message, skip
        }

        // Invoke the request handler
        BOOL keepAlive = m_pfnHandler(
            pClientCtx,
            &header,
            pPayload,
            header.length,
            m_pUserContext
        );

        if (!keepAlive)
        {
            break;
        }
    }

    // Cleanup
    RemoveClient(pClientCtx);
}

// ============================================================================
// Send/Broadcast
// ============================================================================

BOOL CIpcPipeServer::SendResponse(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT16 responseType,
    _In_ UINT32 seqId,
    _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
    _In_ DWORD payloadLen)
{
    BYTE sendBuffer[IPC_PIPE::BUFFER_SIZE];
    DWORD sendLen = IpcSerializeMessage(
        sendBuffer, sizeof(sendBuffer),
        responseType, seqId,
        pPayload, payloadLen
    );

    if (sendLen == 0)
    {
        return FALSE;
    }

    DWORD bytesWritten = 0;
    return WriteFile(pClientCtx->hPipe, sendBuffer, sendLen, &bytesWritten, NULL)
        && (bytesWritten == sendLen);
}

BOOL CIpcPipeServer::SendNotification(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ UINT16 notificationType,
    _In_ UINT32 seqId,
    _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
    _In_ DWORD payloadLen)
{
    return SendResponse(pClientCtx, notificationType, seqId, pPayload, payloadLen);
}

void CIpcPipeServer::BroadcastNotification(
    _In_ UINT16 notificationType,
    _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
    _In_ DWORD payloadLen)
{
    BYTE sendBuffer[IPC_PIPE::BUFFER_SIZE];
    UINT32 seqId = IpcNextSeqId();
    DWORD sendLen = IpcSerializeMessage(
        sendBuffer, sizeof(sendBuffer),
        notificationType, seqId,
        pPayload, payloadLen
    );

    if (sendLen == 0)
    {
        return;
    }

    EnterCriticalSection(&m_csClients);
    for (DWORD i = 0; i < IPC_PIPE::MAX_INSTANCES; i++)
    {
        if (m_clients[i].hPipe != NULL && m_clients[i].hPipe != INVALID_HANDLE_VALUE)
        {
            DWORD bytesWritten = 0;
            WriteFile(m_clients[i].hPipe, sendBuffer, sendLen, &bytesWritten, NULL);
        }
    }
    LeaveCriticalSection(&m_csClients);
}

DWORD CIpcPipeServer::GetClientCount() const
{
    return m_clientCount;
}

// ============================================================================
// Client Management
// ============================================================================

void CIpcPipeServer::AddClient(_In_ IPC_CLIENT_CONTEXT* pClientCtx)
{
    // Client is already added in ListenerThread -- this is a placeholder
    // for future accounting (e.g., logging).
    (void)pClientCtx;
}

void CIpcPipeServer::RemoveClient(_In_ IPC_CLIENT_CONTEXT* pClientCtx)
{
    EnterCriticalSection(&m_csClients);

    if (pClientCtx->hPipe != NULL && pClientCtx->hPipe != INVALID_HANDLE_VALUE)
    {
        DisconnectNamedPipe(pClientCtx->hPipe);
        CloseHandle(pClientCtx->hPipe);
    }
    if (pClientCtx->ov.hEvent != NULL)
    {
        CloseHandle(pClientCtx->ov.hEvent);
    }

    ZeroMemory(pClientCtx, sizeof(IPC_CLIENT_CONTEXT));

    if (m_clientCount > 0)
    {
        m_clientCount--;
    }

    LeaveCriticalSection(&m_csClients);
}
