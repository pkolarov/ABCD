// ipc_messages.h
// DDS Bridge IPC - Concrete message payload structures.
//
// These structures define the binary payload format for each IPC message type.
// All strings are null-terminated wide strings (UTF-16LE) with fixed max length.
//
// Retains all Crayonic BLE badge message structs and adds DDS-specific structs.
//

#pragma once

#include "ipc_protocol.h"

// Maximum string field lengths (in characters, including null terminator)
constexpr DWORD IPC_MAX_SID_LEN          = 128;
constexpr DWORD IPC_MAX_DISPLAY_NAME_LEN = 256;
constexpr DWORD IPC_MAX_DOMAIN_LEN       = 256;
constexpr DWORD IPC_MAX_USERNAME_LEN     = 256;
constexpr DWORD IPC_MAX_PASSWORD_LEN     = 256;
constexpr DWORD IPC_MAX_RPID_LEN         = 256;
constexpr DWORD IPC_MAX_STATUS_MSG_LEN   = 512;
constexpr DWORD IPC_MAX_DEVICE_NAME_LEN  = 128;
constexpr DWORD IPC_MAX_ERROR_MSG_LEN    = 512;
constexpr DWORD IPC_MAX_CERT_DER_LEN     = 4096;
constexpr DWORD IPC_MAX_SUBJECT_LEN      = 256;
constexpr DWORD IPC_MAX_USERS            = 16;

// DDS-specific field lengths
constexpr DWORD IPC_MAX_URN_LEN          = 256;
constexpr DWORD IPC_MAX_CREDENTIAL_ID_LEN = 256;
constexpr DWORD IPC_MAX_SESSION_TOKEN_LEN = 4096;

#pragma pack(push, 1)

// ============================================================================
// Request Payloads (CP -> Service) : Crayonic BLE badge path
// ============================================================================

// GET_STATUS (0x0001) - No payload required.

// LIST_USERS (0x0002) - No payload required.

// START_AUTH_FIDO (0x0010)
struct IPC_REQ_START_AUTH_FIDO
{
    WCHAR sid[IPC_MAX_SID_LEN];         // Windows user SID (e.g., "S-1-5-21-...")
    WCHAR rpId[IPC_MAX_RPID_LEN];      // Relying party ID (e.g., "crayonic.local.login")
};

// START_AUTH_PIV (0x0011)
struct IPC_REQ_START_AUTH_PIV
{
    WCHAR sid[IPC_MAX_SID_LEN];         // Windows user SID
    BYTE  challenge[32];                // Challenge nonce for signing
    DWORD challengeLen;                 // Actual challenge length (up to 32)
};

// CANCEL_AUTH (0x001F)
struct IPC_REQ_CANCEL_AUTH
{
    UINT32 targetSeqId;                 // SeqId of the auth request to cancel
};

// GET_CERT (0x0020)
struct IPC_REQ_GET_CERT
{
    WCHAR sid[IPC_MAX_SID_LEN];         // Windows user SID
    BYTE  slot;                         // PIV slot (0x9A = Authentication)
};

// GET_SERIALIZATION (0x0030)
struct IPC_REQ_GET_SERIALIZATION
{
    WCHAR sid[IPC_MAX_SID_LEN];         // Windows user SID
};

// ============================================================================
// Response Payloads (Service -> CP) : Crayonic BLE badge path
// ============================================================================

// STATUS (0x8001)
struct IPC_RESP_STATUS
{
    BOOL  serviceRunning;               // TRUE if service is operational
    BOOL  deviceConnected;              // TRUE if a KeyVault device is connected
    WCHAR deviceName[IPC_MAX_DEVICE_NAME_LEN]; // Connected device name (e.g., "KeyVault-A1B2")
    INT32 batteryLevel;                 // Battery percentage (0-100), or -1 if unknown
    UINT32 transport;                   // 0 = none, 1 = BLE, 2 = USB
};

// USER_LIST (0x8002)
// Variable-length: header + N user entries
struct IPC_USER_ENTRY
{
    WCHAR sid[IPC_MAX_SID_LEN];                   // Windows user SID
    WCHAR displayName[IPC_MAX_DISPLAY_NAME_LEN];  // Display name for tile
    UINT32 authMethod;                             // IPC_AUTH_METHOD::FIDO2 or PIV
};

struct IPC_RESP_USER_LIST
{
    UINT32 userCount;                   // Number of IPC_USER_ENTRY following this header
    // Followed by userCount * IPC_USER_ENTRY structs
};

// AUTH_PROGRESS (0x8010)
struct IPC_RESP_AUTH_PROGRESS
{
    UINT32 state;                       // IPC_AUTH_STATE value
    WCHAR  message[IPC_MAX_STATUS_MSG_LEN]; // Status message for UI display
};

// AUTH_COMPLETE (0x8011) - FIDO2 result (password derivation model)
struct IPC_RESP_AUTH_COMPLETE_FIDO
{
    BOOL   success;
    WCHAR  domain[IPC_MAX_DOMAIN_LEN];       // Domain or computer name
    WCHAR  username[IPC_MAX_USERNAME_LEN];   // Username
    WCHAR  password[IPC_MAX_PASSWORD_LEN];   // Decrypted password (plaintext, zeroed after use)
    BOOL   isDomainJoined;                   // TRUE if machine is domain-joined
};

// AUTH_COMPLETE (0x8011) - PIV result (certificate model)
struct IPC_RESP_AUTH_COMPLETE_PIV
{
    BOOL   success;
    DWORD  certDerLen;                       // Length of DER-encoded certificate
    BYTE   certDer[IPC_MAX_CERT_DER_LEN];   // X.509 certificate (DER)
    DWORD  signatureLen;                     // Length of signature
    BYTE   signature[512];                   // Signature over challenge
    WCHAR  subject[IPC_MAX_SUBJECT_LEN];     // Certificate subject
};

// AUTH_ERROR (0x801F)
struct IPC_RESP_AUTH_ERROR
{
    UINT32 errorCode;                        // IPC_ERROR code
    WCHAR  message[IPC_MAX_ERROR_MSG_LEN];   // Error description for UI/logging
};

// CERT_DATA (0x8020)
struct IPC_RESP_CERT_DATA
{
    DWORD  certDerLen;                       // Length of DER-encoded certificate
    BYTE   certDer[IPC_MAX_CERT_DER_LEN];   // X.509 certificate (DER)
    WCHAR  subject[IPC_MAX_SUBJECT_LEN];     // Certificate subject (CN)
    WCHAR  issuer[IPC_MAX_SUBJECT_LEN];      // Certificate issuer (CN)
};

// ENROLL_USER (0x0040)
// Sent by the Enrollment Tray App to create a new FIDO2 credential and store
// the Windows password encrypted with the badge's hmac-secret output.
// The password field is transmitted over the local named pipe (ACL'd to
// SYSTEM + current user only) and SecureZeroMemory'd immediately after use.
struct IPC_REQ_ENROLL_USER
{
    WCHAR sid[IPC_MAX_SID_LEN];                   // Windows user SID
    WCHAR displayName[IPC_MAX_DISPLAY_NAME_LEN];  // "DOMAIN\username" or "username"
    WCHAR password[IPC_MAX_PASSWORD_LEN];         // Windows password (plaintext, ephemeral)
    WCHAR rpId[IPC_MAX_RPID_LEN];                 // e.g. "crayonic.local.login"
};

// UNENROLL_USER (0x0041)
struct IPC_REQ_UNENROLL_USER
{
    WCHAR sid[IPC_MAX_SID_LEN];
};

// ENROLL_PROGRESS (0x8040)
struct IPC_RESP_ENROLL_PROGRESS
{
    UINT32 step;                                  // 1=scanning, 2=touch sensor, 3=processing
    WCHAR  message[IPC_MAX_STATUS_MSG_LEN];
};

// ENROLL_RESULT (0x8041)
struct IPC_RESP_ENROLL_RESULT
{
    BOOL  success;
    WCHAR displayName[IPC_MAX_DISPLAY_NAME_LEN];  // enrolled user on success
    WCHAR message[IPC_MAX_STATUS_MSG_LEN];         // success/error description
};

namespace IPC_ENROLL_STEP
{
    constexpr UINT32 SCANNING       = 1;
    constexpr UINT32 TOUCH_SENSOR   = 2;
    constexpr UINT32 PROCESSING     = 3;
}

// ============================================================================
// DDS Request Payloads (CP -> Auth Bridge)
// ============================================================================

// DDS_START_AUTH (0x0060)
// Begin DDS cloud-mediated FIDO2 authentication for a specific credential.
struct IPC_REQ_DDS_START_AUTH
{
    WCHAR device_urn[IPC_MAX_URN_LEN];       // DDS device URN (e.g., "urn:dds:device:xxx")
    WCHAR credential_id[IPC_MAX_CREDENTIAL_ID_LEN]; // FIDO2 credential ID to authenticate with
    WCHAR rp_id[IPC_MAX_RPID_LEN];                  // Relying party ID
};

// DDS_LIST_USERS (0x0062)
// Request the list of DDS-enrolled users for a given device.
struct IPC_REQ_DDS_LIST_USERS
{
    WCHAR device_urn[IPC_MAX_URN_LEN];       // DDS device URN to query
};

// ============================================================================
// DDS Response Payloads (Auth Bridge -> CP)
// ============================================================================

// DDS_AUTH_PROGRESS (0x8060)
struct IPC_RESP_DDS_AUTH_PROGRESS
{
    UINT32 state;                                    // Progress state code
    WCHAR  message[IPC_MAX_STATUS_MSG_LEN];          // Status message for UI display
};

// DDS_AUTH_COMPLETE (0x8061)
// Successful DDS authentication result with Windows credentials and session info.
struct IPC_RESP_DDS_AUTH_COMPLETE
{
    BOOL     success;                                // TRUE if auth succeeded
    WCHAR    domain[IPC_MAX_DOMAIN_LEN];             // Windows domain or computer name
    WCHAR    username[IPC_MAX_USERNAME_LEN];          // Windows username
    WCHAR    password[IPC_MAX_PASSWORD_LEN];          // Windows password (plaintext, zeroed after use)
    char     session_token[IPC_MAX_SESSION_TOKEN_LEN]; // DDS session/access token (UTF-8)
    WCHAR    subject_urn[IPC_MAX_URN_LEN];   // DDS subject URN of authenticated user
    UINT64   expires_at;                             // Token expiry (Unix epoch seconds, UTC)
};

// DDS_AUTH_ERROR (0x806F)
struct IPC_RESP_DDS_AUTH_ERROR
{
    UINT32 error_code;                               // IPC_ERROR code or DDS-specific error
    WCHAR  message[IPC_MAX_ERROR_MSG_LEN];           // Error description for UI/logging
};

// DDS_USER_LIST (0x8062)
// Variable-length: header + N DDS user entries.
struct IPC_DDS_USER_ENTRY
{
    WCHAR display_name[IPC_MAX_DISPLAY_NAME_LEN];    // User display name for tile
    WCHAR subject_urn[IPC_MAX_URN_LEN];      // DDS subject URN
    WCHAR credential_id[IPC_MAX_CREDENTIAL_ID_LEN];  // FIDO2 credential ID
};

struct IPC_RESP_DDS_USER_LIST
{
    UINT32 count;                                    // Number of IPC_DDS_USER_ENTRY following
    // Followed by count * IPC_DDS_USER_ENTRY structs
};

#pragma pack(pop)
