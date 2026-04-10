// ipc_pipe_server.h
// Named Pipe server for the DDS Bridge IPC protocol.
// Used by the Bridge Service to accept connections from CP DLL instances.
//

#pragma once

#include "ipc_protocol.h"
#include "ipc_messages.h"

// Forward declaration
struct IPC_CLIENT_CONTEXT;

// Callback function type for handling incoming requests.
// Called on the server's worker thread when a complete message is received from a client.
// The handler should process the request and call IpcServerSendResponse() to reply.
// Return TRUE to keep the connection alive, FALSE to disconnect the client.
typedef BOOL(CALLBACK* PFN_IPC_REQUEST_HANDLER)(
    _In_ IPC_CLIENT_CONTEXT* pClientCtx,
    _In_ const IPC_MESSAGE_HEADER* pHeader,
    _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
    _In_ DWORD payloadLen,
    _In_opt_ void* pUserContext
    );

// Represents one connected client.
struct IPC_CLIENT_CONTEXT
{
    HANDLE      hPipe;          // Pipe handle for this client
    OVERLAPPED  ov;             // Overlapped structure for async I/O
    BYTE        readBuffer[IPC_PIPE::BUFFER_SIZE];
    DWORD       clientId;       // Unique client identifier
    void*       pUserData;      // Opaque pointer for handler use
};

class CIpcPipeServer
{
public:
    CIpcPipeServer();
    ~CIpcPipeServer();

    // Initialize the server. Creates the Named Pipe with appropriate security.
    // pfnHandler: callback invoked for each incoming request.
    // pUserContext: opaque pointer passed to the handler.
    BOOL Initialize(
        _In_ PFN_IPC_REQUEST_HANDLER pfnHandler,
        _In_opt_ void* pUserContext
    );

    // Start accepting connections. Spawns worker threads.
    BOOL Start();

    // Stop the server and disconnect all clients.
    void Stop();

    // Send a response to a specific client.
    BOOL SendResponse(
        _In_ IPC_CLIENT_CONTEXT* pClientCtx,
        _In_ UINT16 responseType,
        _In_ UINT32 seqId,
        _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
        _In_ DWORD payloadLen
    );

    // Send an async notification to a specific client (e.g., AUTH_PROGRESS).
    BOOL SendNotification(
        _In_ IPC_CLIENT_CONTEXT* pClientCtx,
        _In_ UINT16 notificationType,
        _In_ UINT32 seqId,
        _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
        _In_ DWORD payloadLen
    );

    // Send a notification to ALL connected clients.
    void BroadcastNotification(
        _In_ UINT16 notificationType,
        _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
        _In_ DWORD payloadLen
    );

    // Returns the number of currently connected clients.
    DWORD GetClientCount() const;

private:
    PFN_IPC_REQUEST_HANDLER m_pfnHandler;
    void*                   m_pUserContext;
    HANDLE                  m_hStopEvent;
    HANDLE                  m_hListenerThread;
    BOOL                    m_bRunning;

    IPC_CLIENT_CONTEXT      m_clients[IPC_PIPE::MAX_INSTANCES];
    DWORD                   m_clientCount;
    CRITICAL_SECTION        m_csClients;

    DWORD                   m_nextClientId;

    // Create a pipe instance with the proper security descriptor.
    HANDLE CreatePipeInstance();

    // Create security descriptor: allow SYSTEM and INTERACTIVE sessions only.
    BOOL CreatePipeSecurity(_Out_ PSECURITY_DESCRIPTOR* ppSD, _Out_ PSECURITY_ATTRIBUTES* ppSA);
    void FreePipeSecurity(_In_ PSECURITY_DESCRIPTOR pSD, _In_ PSECURITY_ATTRIBUTES pSA);

    // Listener thread: accepts new connections.
    static DWORD WINAPI ListenerThreadProc(_In_ LPVOID pParam);
    DWORD ListenerThread();

    // Client handler thread: reads messages from a connected client.
    static DWORD WINAPI ClientThreadProc(_In_ LPVOID pParam);

    struct CLIENT_THREAD_PARAMS
    {
        CIpcPipeServer*    pServer;
        IPC_CLIENT_CONTEXT* pClientCtx;
    };

    void HandleClient(_In_ IPC_CLIENT_CONTEXT* pClientCtx);

    // Add/remove client from the active list.
    void AddClient(_In_ IPC_CLIENT_CONTEXT* pClientCtx);
    void RemoveClient(_In_ IPC_CLIENT_CONTEXT* pClientCtx);
};
