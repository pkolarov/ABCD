// test_ipc_messages.cpp
// Tests for DDS IPC message serialization, struct layouts, and type constants.
//
// Included by test_main.cpp -- do NOT compile separately.
//
// On macOS / cross-platform CI the Windows headers are not available, so we
// re-define the minimal types needed to verify struct layouts and constants
// without pulling in <windows.h>.
//

#ifndef _WIN32
// ---- Stand-in types so ipc_protocol.h / ipc_messages.h can be parsed ----
#include <cstdint>
#include <cstring>

typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef int32_t  INT32;
typedef uint32_t DWORD;
typedef int      BOOL;
typedef uint8_t  BYTE;
typedef wchar_t  WCHAR;
typedef void*    LPVOID;
typedef unsigned long HINTERNET;
typedef unsigned short INTERNET_PORT;
typedef unsigned long LONG;

// SAL annotations -- no-op outside MSVC
#define _Out_writes_bytes_(s)
#define _In_
#define _In_reads_bytes_opt_(s)
#define _In_reads_bytes_(s)
#define _Out_
#define _Outptr_result_maybenull_

#ifndef TRUE
#define TRUE  1
#endif
#ifndef FALSE
#define FALSE 0
#endif

// Stub InterlockedIncrement for the header
inline LONG InterlockedIncrement(volatile LONG* p) { return ++(*p); }

#endif // !_WIN32

// Now include the actual protocol headers
#include "../DdsBridgeIPC/ipc_protocol.h"
#include "../DdsBridgeIPC/ipc_messages.h"

// ============================================================================
// Tests
// ============================================================================

DDS_TEST(ipc_header_size_is_10_bytes)
{
    DDS_ASSERT(sizeof(IPC_MESSAGE_HEADER) == 10,
               "IPC_MESSAGE_HEADER must be exactly 10 bytes (2+4+4 packed)");
}

DDS_TEST(ipc_header_field_offsets)
{
    // Verify packed layout: msgType at 0, seqId at 2, length at 6
    IPC_MESSAGE_HEADER h;
    memset(&h, 0, sizeof(h));

    const uint8_t* base = reinterpret_cast<const uint8_t*>(&h);
    const uint8_t* pMsgType = reinterpret_cast<const uint8_t*>(&h.msgType);
    const uint8_t* pSeqId   = reinterpret_cast<const uint8_t*>(&h.seqId);
    const uint8_t* pLength  = reinterpret_cast<const uint8_t*>(&h.length);

    DDS_ASSERT((pMsgType - base) == 0,  "msgType offset must be 0");
    DDS_ASSERT((pSeqId   - base) == 2,  "seqId offset must be 2");
    DDS_ASSERT((pLength  - base) == 6,  "length offset must be 6");
}

DDS_TEST(dds_start_auth_message_type)
{
    DDS_ASSERT(IPC_MSG::DDS_START_AUTH == 0x0060,
               "DDS_START_AUTH must be 0x0060");
}

DDS_TEST(dds_auth_complete_message_type)
{
    DDS_ASSERT(IPC_MSG::DDS_AUTH_COMPLETE == 0x8061,
               "DDS_AUTH_COMPLETE must be 0x8061");
}

DDS_TEST(dds_list_users_message_type)
{
    DDS_ASSERT(IPC_MSG::DDS_LIST_USERS == 0x0062,
               "DDS_LIST_USERS must be 0x0062");
}

DDS_TEST(dds_user_list_message_type)
{
    DDS_ASSERT(IPC_MSG::DDS_USER_LIST == 0x8062,
               "DDS_USER_LIST must be 0x8062");
}

DDS_TEST(dds_start_auth_is_request)
{
    DDS_ASSERT(IPC_MSG::IsRequest(IPC_MSG::DDS_START_AUTH),
               "DDS_START_AUTH must be a request (high bit clear)");
    DDS_ASSERT(!IPC_MSG::IsResponse(IPC_MSG::DDS_START_AUTH),
               "DDS_START_AUTH must not be a response");
}

DDS_TEST(dds_auth_complete_is_response)
{
    DDS_ASSERT(IPC_MSG::IsResponse(IPC_MSG::DDS_AUTH_COMPLETE),
               "DDS_AUTH_COMPLETE must be a response (high bit set)");
    DDS_ASSERT(!IPC_MSG::IsRequest(IPC_MSG::DDS_AUTH_COMPLETE),
               "DDS_AUTH_COMPLETE must not be a request");
}

DDS_TEST(dds_list_users_roundtrip_types)
{
    // Verify the request/response pair is correctly categorized
    DDS_ASSERT(IPC_MSG::IsRequest(IPC_MSG::DDS_LIST_USERS),
               "DDS_LIST_USERS must be a request");
    DDS_ASSERT(IPC_MSG::IsResponse(IPC_MSG::DDS_USER_LIST),
               "DDS_USER_LIST must be a response");

    // The response type is the request type OR'd with 0x8000
    UINT16 expectedResponse = IPC_MSG::DDS_LIST_USERS | 0x8000;
    DDS_ASSERT(IPC_MSG::DDS_USER_LIST == expectedResponse,
               "DDS_USER_LIST must be DDS_LIST_USERS | 0x8000");
}

DDS_TEST(dds_start_auth_struct_has_required_fields)
{
    IPC_REQ_DDS_START_AUTH req;
    memset(&req, 0, sizeof(req));

    // Verify the struct has the expected fields by writing to them
    req.device_urn[0]    = L'u';
    req.credential_id[0] = L'c';
    req.rp_id[0]         = L'r';

    DDS_ASSERT(req.device_urn[0] == L'u',    "device_urn field must be accessible");
    DDS_ASSERT(req.credential_id[0] == L'c', "credential_id field must be accessible");
    DDS_ASSERT(req.rp_id[0] == L'r',         "rp_id field must be accessible");
}

DDS_TEST(dds_auth_complete_struct_has_required_fields)
{
    IPC_RESP_DDS_AUTH_COMPLETE resp;
    memset(&resp, 0, sizeof(resp));

    resp.success      = TRUE;
    resp.domain[0]    = L'd';
    resp.username[0]  = L'u';
    resp.password[0]  = L'p';
    resp.session_token[0] = 's';
    resp.subject_urn[0]   = L'x';
    resp.expires_at   = 1700000000ULL;

    DDS_ASSERT(resp.success == TRUE,            "success field must be settable");
    DDS_ASSERT(resp.domain[0] == L'd',          "domain field must be accessible");
    DDS_ASSERT(resp.username[0] == L'u',        "username field must be accessible");
    DDS_ASSERT(resp.password[0] == L'p',        "password field must be accessible");
    DDS_ASSERT(resp.session_token[0] == 's',    "session_token field must be accessible");
    DDS_ASSERT(resp.subject_urn[0] == L'x',     "subject_urn field must be accessible");
    DDS_ASSERT(resp.expires_at == 1700000000ULL,"expires_at field must be accessible");
}

DDS_TEST(dds_user_list_struct_layout)
{
    IPC_RESP_DDS_USER_LIST listHeader;
    memset(&listHeader, 0, sizeof(listHeader));
    listHeader.count = 3;
    DDS_ASSERT(listHeader.count == 3, "count field must be settable");

    IPC_DDS_USER_ENTRY entry;
    memset(&entry, 0, sizeof(entry));
    entry.display_name[0]  = L'A';
    entry.subject_urn[0]   = L'B';
    entry.credential_id[0] = L'C';

    DDS_ASSERT(entry.display_name[0] == L'A',  "display_name field must be accessible");
    DDS_ASSERT(entry.subject_urn[0] == L'B',   "subject_urn field must be accessible");
    DDS_ASSERT(entry.credential_id[0] == L'C', "credential_id field must be accessible");
}

DDS_TEST(dds_auth_error_struct)
{
    IPC_RESP_DDS_AUTH_ERROR err;
    memset(&err, 0, sizeof(err));

    err.error_code = IPC_ERROR::DDS_API_ERROR;
    err.message[0] = L'E';

    DDS_ASSERT(err.error_code == 13, "DDS_API_ERROR must be 13");
    DDS_ASSERT(err.message[0] == L'E', "message field must be accessible");
}

DDS_TEST(dds_error_code_constants)
{
    DDS_ASSERT(IPC_ERROR::SUCCESS           == 0,  "SUCCESS must be 0");
    DDS_ASSERT(IPC_ERROR::DDS_API_ERROR     == 13, "DDS_API_ERROR must be 13");
    DDS_ASSERT(IPC_ERROR::DDS_TOKEN_EXPIRED == 14, "DDS_TOKEN_EXPIRED must be 14");
}

// AD-14 — pinned numeric values for the AD-coexistence error codes. The
// IPC contract is shared with the credential provider DLL, so the values
// must remain stable across MSI upgrades.
DDS_TEST(ad_coexistence_error_code_constants)
{
    DDS_ASSERT(IPC_ERROR::STALE_VAULT_PASSWORD       == 16,
               "STALE_VAULT_PASSWORD must be 16");
    DDS_ASSERT(IPC_ERROR::AD_PASSWORD_CHANGE_REQUIRED == 17,
               "AD_PASSWORD_CHANGE_REQUIRED must be 17");
    DDS_ASSERT(IPC_ERROR::AD_PASSWORD_EXPIRED        == 18,
               "AD_PASSWORD_EXPIRED must be 18");
    DDS_ASSERT(IPC_ERROR::PRE_ENROLLMENT_REQUIRED    == 19,
               "PRE_ENROLLMENT_REQUIRED must be 19");
    DDS_ASSERT(IPC_ERROR::UNSUPPORTED_HOST           == 20,
               "UNSUPPORTED_HOST must be 20");
    DDS_ASSERT(IPC_ERROR::ACCOUNT_NOT_FOUND          == 21,
               "ACCOUNT_NOT_FOUND must be 21");
}

// AD-14 — pinned message-type values and request-side bit semantics.
DDS_TEST(dds_report_logon_result_message_type)
{
    DDS_ASSERT(IPC_MSG::DDS_REPORT_LOGON_RESULT == 0x0064,
               "DDS_REPORT_LOGON_RESULT must be 0x0064");
    DDS_ASSERT(IPC_MSG::IsRequest(IPC_MSG::DDS_REPORT_LOGON_RESULT),
               "DDS_REPORT_LOGON_RESULT must be a request (high bit clear)");
    DDS_ASSERT(!IPC_MSG::IsResponse(IPC_MSG::DDS_REPORT_LOGON_RESULT),
               "DDS_REPORT_LOGON_RESULT must not be a response");
}

DDS_TEST(dds_clear_stale_message_type)
{
    DDS_ASSERT(IPC_MSG::DDS_CLEAR_STALE == 0x0065,
               "DDS_CLEAR_STALE must be 0x0065");
    DDS_ASSERT(IPC_MSG::IsRequest(IPC_MSG::DDS_CLEAR_STALE),
               "DDS_CLEAR_STALE must be a request (high bit clear)");
}

DDS_TEST(dds_report_logon_result_struct_layout)
{
    IPC_REQ_DDS_REPORT_LOGON_RESULT req;
    memset(&req, 0, sizeof(req));

    req.credential_id[0] = L'a';
    req.ntStatus         = static_cast<INT32>(0xC000006DL); // STATUS_LOGON_FAILURE

    DDS_ASSERT(req.credential_id[0] == L'a',
               "credential_id field must be accessible");
    DDS_ASSERT(req.ntStatus == static_cast<INT32>(0xC000006DL),
               "ntStatus field must round-trip a negative NTSTATUS");
}

DDS_TEST(dds_clear_stale_struct_layout)
{
    IPC_REQ_DDS_CLEAR_STALE req;
    memset(&req, 0, sizeof(req));

    req.credential_id[0] = L'z';
    DDS_ASSERT(req.credential_id[0] == L'z',
               "credential_id field must be accessible");
}

DDS_TEST(auth_method_dds_constant)
{
    DDS_ASSERT(IPC_AUTH_METHOD::DDS == 3, "DDS auth method must be 3");
}

DDS_TEST(dds_message_range)
{
    // DDS-specific messages should be in the 0x0060-0x007F range (requests)
    // and 0x8060-0x807F range (responses)
    DDS_ASSERT(IPC_MSG::DDS_START_AUTH    >= 0x0060 && IPC_MSG::DDS_START_AUTH    <= 0x007F,
               "DDS_START_AUTH must be in DDS request range 0x0060-0x007F");
    DDS_ASSERT(IPC_MSG::DDS_LIST_USERS    >= 0x0060 && IPC_MSG::DDS_LIST_USERS    <= 0x007F,
               "DDS_LIST_USERS must be in DDS request range 0x0060-0x007F");
    DDS_ASSERT(IPC_MSG::DDS_AUTH_COMPLETE >= 0x8060 && IPC_MSG::DDS_AUTH_COMPLETE <= 0x807F,
               "DDS_AUTH_COMPLETE must be in DDS response range 0x8060-0x807F");
    DDS_ASSERT(IPC_MSG::DDS_AUTH_ERROR    >= 0x8060 && IPC_MSG::DDS_AUTH_ERROR    <= 0x807F,
               "DDS_AUTH_ERROR must be in DDS response range 0x8060-0x807F");
    DDS_ASSERT(IPC_MSG::DDS_USER_LIST     >= 0x8060 && IPC_MSG::DDS_USER_LIST     <= 0x807F,
               "DDS_USER_LIST must be in DDS response range 0x8060-0x807F");
}

#ifdef _WIN32
// These serialization tests only run on Windows where ipc_protocol.cpp compiles

DDS_TEST(ipc_serialize_header_only)
{
    BYTE buf[64];
    memset(buf, 0xFF, sizeof(buf));

    DWORD written = IpcSerializeMessage(buf, sizeof(buf),
                                        IPC_MSG::DDS_START_AUTH, 42,
                                        nullptr, 0);

    DDS_ASSERT(written == sizeof(IPC_MESSAGE_HEADER),
               "Header-only message should be exactly 10 bytes");

    IPC_MESSAGE_HEADER hdr;
    const BYTE* payload = nullptr;
    BOOL ok = IpcDeserializeHeader(buf, written, &hdr, &payload);

    DDS_ASSERT(ok == TRUE,            "Deserialization must succeed");
    DDS_ASSERT(hdr.msgType == 0x0060, "msgType must round-trip");
    DDS_ASSERT(hdr.seqId == 42,       "seqId must round-trip");
    DDS_ASSERT(hdr.length == 0,       "length must be 0 for no payload");
    DDS_ASSERT(payload == nullptr,    "payload pointer must be NULL");
}

DDS_TEST(ipc_serialize_with_payload)
{
    const char* json = "{\"test\":true}";
    DWORD jsonLen = (DWORD)strlen(json);

    BYTE buf[256];
    DWORD written = IpcSerializeMessage(buf, sizeof(buf),
                                        IPC_MSG::DDS_AUTH_COMPLETE, 99,
                                        (const BYTE*)json, jsonLen);

    DDS_ASSERT(written == sizeof(IPC_MESSAGE_HEADER) + jsonLen,
               "Total size must be header + payload");

    IPC_MESSAGE_HEADER hdr;
    const BYTE* payload = nullptr;
    BOOL ok = IpcDeserializeHeader(buf, written, &hdr, &payload);

    DDS_ASSERT(ok == TRUE,               "Deserialization must succeed");
    DDS_ASSERT(hdr.msgType == 0x8061,    "msgType must round-trip");
    DDS_ASSERT(hdr.seqId == 99,          "seqId must round-trip");
    DDS_ASSERT(hdr.length == jsonLen,    "length must match payload");
    DDS_ASSERT(payload != nullptr,       "payload pointer must be set");
    DDS_ASSERT(memcmp(payload, json, jsonLen) == 0, "payload must round-trip");
}

DDS_TEST(ipc_deserialize_rejects_short_buffer)
{
    BYTE buf[4] = {0};
    IPC_MESSAGE_HEADER hdr;
    const BYTE* payload = nullptr;

    BOOL ok = IpcDeserializeHeader(buf, sizeof(buf), &hdr, &payload);
    DDS_ASSERT(ok == FALSE,
               "Deserialization must fail for buffer shorter than header");
}

DDS_TEST(ipc_deserialize_rejects_truncated_payload)
{
    // Craft a header that claims a 1000-byte payload in a 20-byte buffer
    BYTE buf[20];
    memset(buf, 0, sizeof(buf));

    IPC_MESSAGE_HEADER fake;
    fake.msgType = IPC_MSG::DDS_START_AUTH;
    fake.seqId   = 1;
    fake.length  = 1000;  // lies about payload size
    memcpy(buf, &fake, sizeof(fake));

    IPC_MESSAGE_HEADER hdr;
    const BYTE* payload = nullptr;
    BOOL ok = IpcDeserializeHeader(buf, sizeof(buf), &hdr, &payload);

    DDS_ASSERT(ok == FALSE,
               "Deserialization must reject payload length exceeding buffer");
}

#endif // _WIN32
