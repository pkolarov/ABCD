// ipc_protocol.h
// DDS Bridge IPC Protocol - shared between CP DLL and Bridge Service
//
// TLV message envelope and type definitions for Named Pipe communication.
// Forked from CrayonicBridgeIPC -- retains all Crayonic message types for BLE
// badge compatibility and adds DDS-specific message types (0x0060-0x007F).
//

#pragma once

#include <windows.h>
#include <cstdint>

#pragma pack(push, 1)

// ============================================================================
// TLV Message Envelope
// ============================================================================
//
// All IPC messages use this envelope:
//
//  +----------+----------+----------+-------------------------+
//  | MSG_TYPE  | SEQ_ID   | LENGTH   | PAYLOAD (JSON or binary)|
//  | 2 bytes   | 4 bytes  | 4 bytes  | LENGTH bytes            |
//  +----------+----------+----------+-------------------------+
//

struct IPC_MESSAGE_HEADER
{
    UINT16 msgType;     // Message type code (see IPC_MSG_TYPE)
    UINT32 seqId;       // Sequence ID for request/response correlation
    UINT32 length;      // Payload length in bytes (0 if no payload)
};

static_assert(sizeof(IPC_MESSAGE_HEADER) == 10, "IPC_MESSAGE_HEADER must be 10 bytes packed");

// ============================================================================
// Message Type Codes
// ============================================================================

namespace IPC_MSG
{
    // --- Requests (CP -> Service) : Crayonic BLE badge path ---

    constexpr UINT16 GET_STATUS         = 0x0001;  // Query service and device status
    constexpr UINT16 LIST_USERS         = 0x0002;  // List enrolled users for tile enumeration
    constexpr UINT16 START_AUTH_FIDO    = 0x0010;  // Begin FIDO2 GetAssertion
    constexpr UINT16 START_AUTH_PIV     = 0x0011;  // Begin PIV authentication
    constexpr UINT16 CANCEL_AUTH        = 0x001F;  // Cancel an in-progress authentication
    constexpr UINT16 GET_CERT           = 0x0020;  // Retrieve PIV certificate
    constexpr UINT16 GET_SERIALIZATION  = 0x0030;  // Get serialized credential blob for LSA
    constexpr UINT16 ENROLL_USER        = 0x0040;  // Enroll badge + store encrypted password
    constexpr UINT16 UNENROLL_USER      = 0x0041;  // Remove enrollment for a user

    // --- Responses (Service -> CP) : Crayonic BLE badge path ---

    constexpr UINT16 STATUS             = 0x8001;  // Device status response
    constexpr UINT16 USER_LIST          = 0x8002;  // Enrolled user list
    constexpr UINT16 AUTH_PROGRESS      = 0x8010;  // Auth progress (processing, touch sensor, etc.)
    constexpr UINT16 AUTH_COMPLETE      = 0x8011;  // Auth result with serialized credential
    constexpr UINT16 AUTH_ERROR         = 0x801F;  // Authentication failed
    constexpr UINT16 CERT_DATA          = 0x8020;  // PIV certificate data
    constexpr UINT16 ENROLL_PROGRESS    = 0x8040;  // Enrollment step notification
    constexpr UINT16 ENROLL_RESULT      = 0x8041;  // Enrollment success/failure

    // --- Requests (CP -> Auth Bridge) : DDS cloud auth path (0x0060-0x007F) ---

    constexpr UINT16 DDS_START_AUTH     = 0x0060;  // Begin DDS FIDO2 authentication via cloud
    constexpr UINT16 DDS_LIST_USERS     = 0x0062;  // List DDS-enrolled users for a device

    // --- Responses (Auth Bridge -> CP) : DDS cloud auth path ---

    constexpr UINT16 DDS_AUTH_PROGRESS  = 0x8060;  // DDS auth progress update
    constexpr UINT16 DDS_AUTH_COMPLETE  = 0x8061;  // DDS auth result with credentials + session
    constexpr UINT16 DDS_AUTH_ERROR     = 0x806F;  // DDS authentication error
    constexpr UINT16 DDS_USER_LIST      = 0x8062;  // DDS enrolled user list

    // --- Helpers ---

    inline bool IsResponse(UINT16 type) { return (type & 0x8000) != 0; }
    inline bool IsRequest(UINT16 type) { return (type & 0x8000) == 0; }
}

// ============================================================================
// Auth Progress States
// ============================================================================

namespace IPC_AUTH_STATE
{
    constexpr UINT32 PROCESSING         = 1;    // Device is processing
    constexpr UINT32 USER_PRESENCE      = 2;    // User needs to touch fingerprint sensor
    constexpr UINT32 PIN_REQUIRED       = 3;    // PIN entry required
    constexpr UINT32 PIN_INVALID        = 4;    // PIN was incorrect
}

// ============================================================================
// Auth Method Identifiers
// ============================================================================

namespace IPC_AUTH_METHOD
{
    constexpr UINT32 FIDO2              = 1;
    constexpr UINT32 PIV                = 2;
    constexpr UINT32 DDS                = 3;
}

// ============================================================================
// Error Codes
// ============================================================================

namespace IPC_ERROR
{
    constexpr UINT32 SUCCESS            = 0;
    constexpr UINT32 DEVICE_NOT_FOUND   = 1;
    constexpr UINT32 DEVICE_BUSY        = 2;
    constexpr UINT32 AUTH_TIMEOUT       = 3;
    constexpr UINT32 AUTH_FAILED        = 4;
    constexpr UINT32 USER_CANCELLED     = 5;
    constexpr UINT32 PIN_BLOCKED        = 6;
    constexpr UINT32 FINGERPRINT_FAILED = 7;
    constexpr UINT32 NO_CREDENTIAL      = 8;
    constexpr UINT32 SERVICE_ERROR      = 9;
    constexpr UINT32 VAULT_ERROR        = 10;
    constexpr UINT32 CTAP_ERROR         = 11;
    constexpr UINT32 PIV_ERROR          = 12;
    constexpr UINT32 DDS_API_ERROR      = 13;
    constexpr UINT32 DDS_TOKEN_EXPIRED  = 14;
    constexpr UINT32 AUTH_CANCELLED     = 15;
}

// ============================================================================
// Named Pipe Configuration
// ============================================================================

namespace IPC_PIPE
{
    // NOTE: Avoid names that collide with Windows NTSTATUS / WinSock macros
    // (STATUS_TIMEOUT = 0x102, CONNECT_TIMEOUT, etc.)
    constexpr const wchar_t* PIPE_NAME              = L"\\\\.\\pipe\\DdsBridge";
    constexpr DWORD          BUFFER_SIZE            = 8192;
    constexpr DWORD          MAX_INSTANCES          = 10;
    constexpr DWORD          PIPE_CONNECT_MS        = 5000;    // 5 seconds
    constexpr DWORD          PIPE_STATUS_MS         = 2000;    // 2 seconds
    constexpr DWORD          AUTH_TIMEOUT_MS        = 60000;   // 60 seconds
    constexpr DWORD          KEEPALIVE_TIMEOUT_MS   = 30000;   // 30 seconds
}

#pragma pack(pop)

// ============================================================================
// Serialization Functions
// ============================================================================

// Serialize a message header + payload into a buffer for pipe transmission.
// Returns the total number of bytes written, or 0 on failure.
// The caller must ensure pOutBuffer has at least sizeof(IPC_MESSAGE_HEADER) + payloadLen bytes.
DWORD IpcSerializeMessage(
    _Out_writes_bytes_(outBufferSize) BYTE* pOutBuffer,
    _In_ DWORD outBufferSize,
    _In_ UINT16 msgType,
    _In_ UINT32 seqId,
    _In_reads_bytes_opt_(payloadLen) const BYTE* pPayload,
    _In_ DWORD payloadLen
);

// Deserialize a message header from a buffer received from a pipe.
// On success, returns TRUE, fills pHeader, and sets ppPayload to point
// within pBuffer at the payload start (or NULL if length is 0).
BOOL IpcDeserializeHeader(
    _In_reads_bytes_(bufferLen) const BYTE* pBuffer,
    _In_ DWORD bufferLen,
    _Out_ IPC_MESSAGE_HEADER* pHeader,
    _Outptr_result_maybenull_ const BYTE** ppPayload
);

// Generate a unique sequence ID (thread-safe, monotonically increasing).
UINT32 IpcNextSeqId();
