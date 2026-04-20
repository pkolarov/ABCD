// DdsNodeHttpClient.h
// WinHTTP-based client for calling the dds-node REST API.
//
// The dds-node process runs on the same machine and exposes a local
// HTTP API for session management and user enrollment queries.
//

#pragma once

#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <cstdint>

#pragma comment(lib, "winhttp.lib")

// Result of a POST /v1/session/assert call
struct DdsAssertResult
{
    bool        success;
    std::string sessionId;         // "sess-..." session identifier
    std::string tokenCborB64;      // Base64-encoded signed session token (CBOR)
    uint64_t    expiresAt;         // Unix epoch seconds (UTC)
    std::string errorMessage;      // Non-empty on failure
};

// One enrolled user as returned by GET /v1/enrolled-users
struct DdsEnrolledUser
{
    std::string subjectUrn;        // DDS Vouchsafe URN (was "userSid")
    std::string displayName;
    std::string credentialId;      // Base64url-encoded FIDO2 credential ID
    bool        vouched = false;
};

// Result of a GET /v1/enrolled-users call
struct DdsEnrolledUsersResult
{
    bool        success;
    std::vector<DdsEnrolledUser> users;
    std::string errorMessage;
};

// Result of POST /v1/enroll/user
struct DdsEnrollResult
{
    bool        success;
    std::string urn;
    std::string jti;
    std::string errorMessage;
};

// Result of POST /v1/admin/setup
struct DdsAdminSetupResult
{
    bool        success;
    std::string adminUrn;
    std::string errorMessage;
};

// Result of POST /v1/admin/vouch
struct DdsAdminVouchResult
{
    bool        success;
    std::string vouchJti;
    std::string subjectUrn;
    std::string adminUrn;
    std::string errorMessage;
};

// Result of GET /v1/session/challenge or /v1/admin/challenge
struct DdsChallengeResult
{
    bool        success;
    std::string challengeId;      // Opaque server ID to echo back in the assertion POST
    std::string challengeB64url;  // Base64url-encoded 32-byte nonce for clientDataJSON
    uint64_t    expiresAt;        // Unix epoch seconds when the challenge expires
    std::string errorMessage;
};

// Result of POST /v1/windows/claim-account
struct DdsWindowsClaimResult
{
    bool                     success;
    std::string              subjectUrn;
    std::string              username;
    std::string              fullName;
    std::string              description;
    std::vector<std::string> groups;
    bool                     hasPasswordNeverExpires{ false };
    bool                     passwordNeverExpires{ false };
    std::string              errorMessage;
};

class CDdsNodeHttpClient
{
public:
    CDdsNodeHttpClient();
    ~CDdsNodeHttpClient();

    // Set the base URL. Call before any request methods.
    //
    // Supported schemes:
    //   http://host:port       — loopback TCP (legacy, default)
    //   pipe:<name>            — Windows named pipe (H-7 step-2b).
    //                            Accepts either a bare name
    //                            (pipe:dds-api → \\.\pipe\dds-api) or
    //                            a full pipe path
    //                            (pipe:\\.\pipe\dds-api).
    //
    // Port-only overload affects the TCP path only.
    void SetBaseUrl(const std::string& baseUrl);
    void SetPort(DWORD port);

    // POST /v1/session/assert
    //
    // Sends the FIDO2 assertion proof to dds-node for server-side
    // verification. On success, dds-node returns a session token.
    //
    // assertionJson: JSON-encoded assertion data (authenticatorData,
    //                clientDataJSON, signature, userHandle).
    DdsAssertResult PostSessionAssert(const std::string& assertionJson);

    // GET /v1/enrolled-users?device_urn=<urn>
    //
    // Retrieves the list of users enrolled on this device from dds-node.
    DdsEnrolledUsersResult GetEnrolledUsers(const std::string& deviceUrn);

    // POST /v1/enroll/user
    //
    // Enrolls a user with FIDO2 attestation. enrollJson must contain:
    //   label, credential_id, attestation_object_b64, client_data_hash_b64,
    //   rp_id, display_name, authenticator_type
    DdsEnrollResult PostEnrollUser(const std::string& enrollJson);

    // POST /v1/admin/setup
    //
    // Registers an admin identity. Same JSON format as PostEnrollUser.
    DdsAdminSetupResult PostAdminSetup(const std::string& setupJson);

    // POST /v1/admin/vouch
    //
    // Admin vouches for an enrolled user via FIDO2 assertion proof.
    DdsAdminVouchResult PostAdminVouch(const std::string& vouchJson);

    // GET /v1/session/challenge
    //
    // Fetches a short-lived (300 s) single-use challenge nonce for
    // /v1/session/assert. The challenge_id must be echoed back in the assertion.
    DdsChallengeResult GetSessionChallenge();

    // GET /v1/admin/challenge
    //
    // Fetches a short-lived (300 s) single-use challenge nonce for
    // /v1/admin/vouch. The challenge_id must be echoed back in the vouch POST.
    DdsChallengeResult GetAdminChallenge();

    // POST /v1/windows/claim-account
    //
    // Resolves the local Windows account that the holder of a freshly
    // issued DDS session token is authorized to claim on this endpoint.
    DdsWindowsClaimResult PostWindowsClaim(const std::string& claimJson);

private:
    // **H-7 step-2b (security review)**: transport dispatch. The
    // dds-node HTTP API can bind either TCP loopback (legacy) or a
    // Windows named pipe (current target). Named pipe is the
    // preferred transport because the node's pipe listener extracts
    // the caller's primary user SID via GetNamedPipeClientProcessId
    // + OpenProcessToken + GetTokenInformation and gates admin
    // endpoints on it. On TCP callers are anonymous.
    enum class Transport
    {
        Tcp,
        Pipe,
    };

    std::wstring m_host;            // TCP host (e.g. "127.0.0.1")
    INTERNET_PORT m_port;            // TCP port (e.g. 5551)
    Transport    m_transport;       // Selected transport mode
    std::wstring m_pipeName;         // Bare pipe name, e.g. "dds-api"
                                     // (without the "\\.\pipe\" prefix)

    // Dispatch entry point: routes to SendRequestWinHttp or
    // SendRequestPipe based on m_transport. Returns the HTTP status
    // code, or 0 on connection/transport error. responseBody receives
    // the UTF-8 response body.
    DWORD SendRequest(
        const wchar_t* verb,
        const wchar_t* path,
        const std::string* requestBody,     // nullptr for GET
        std::string& responseBody
    );

    // WinHTTP implementation (TCP loopback).
    DWORD SendRequestWinHttp(
        const wchar_t* verb,
        const wchar_t* path,
        const std::string* requestBody,
        std::string& responseBody
    );

    // Named-pipe implementation. Opens \\.\pipe\<m_pipeName>, writes a
    // minimal HTTP/1.1 request, reads the response until EOF
    // (server sets Connection: close), parses the status line and
    // body. No keep-alive, no streaming — each call is one request
    // per pipe connection.
    DWORD SendRequestPipe(
        const wchar_t* verb,
        const wchar_t* path,
        const std::string* requestBody,
        std::string& responseBody
    );

    // ---- Minimal JSON helpers (no external dependencies) ----

    // Shared helper: parse the JSON body returned by challenge endpoints.
    DdsChallengeResult ParseChallengeResponse(DWORD httpStatus, const std::string& responseBody);

    // Extract a string value for a given key from a flat JSON object.
    // Only handles simple cases (no nested objects for the extracted key).
    static std::string JsonGetString(const std::string& json, const std::string& key);

    // Extract a boolean value for a given key.
    static bool JsonGetBool(const std::string& json, const std::string& key, bool defaultVal);

    // Extract an unquoted uint64 value for a given key (e.g. "expires_at":1712957100).
    static uint64_t JsonGetUint64(const std::string& json, const std::string& key);

    // Extract an array of flat JSON objects. Returns the raw strings of
    // each {...} element. Caller parses individual fields with JsonGetString.
    static std::vector<std::string> JsonGetObjectArray(const std::string& json, const std::string& key);

    // Extract an array of strings.
    static std::vector<std::string> JsonGetStringArray(const std::string& json, const std::string& key);

    // URL-encode a narrow string for query parameters.
    static std::wstring Utf8ToWide(const std::string& s);
};
