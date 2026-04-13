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

    // Set the base URL. Default is http://127.0.0.1:5551.
    // Call before any request methods. Port-only overload also available.
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

    // POST /v1/windows/claim-account
    //
    // Resolves the local Windows account that the holder of a freshly
    // issued DDS session token is authorized to claim on this endpoint.
    DdsWindowsClaimResult PostWindowsClaim(const std::string& claimJson);

private:
    std::wstring m_host;
    INTERNET_PORT m_port;

    // Open a WinHTTP session, connect, send request, and read response.
    // Returns the HTTP status code, or 0 on connection/transport error.
    // responseBody receives the UTF-8 response body.
    DWORD SendRequest(
        const wchar_t* verb,
        const wchar_t* path,
        const std::string* requestBody,     // nullptr for GET
        std::string& responseBody
    );

    // ---- Minimal JSON helpers (no external dependencies) ----

    // Extract a string value for a given key from a flat JSON object.
    // Only handles simple cases (no nested objects for the extracted key).
    static std::string JsonGetString(const std::string& json, const std::string& key);

    // Extract a boolean value for a given key.
    static bool JsonGetBool(const std::string& json, const std::string& key, bool defaultVal);

    // Extract an array of flat JSON objects. Returns the raw strings of
    // each {...} element. Caller parses individual fields with JsonGetString.
    static std::vector<std::string> JsonGetObjectArray(const std::string& json, const std::string& key);

    // Extract an array of strings.
    static std::vector<std::string> JsonGetStringArray(const std::string& json, const std::string& key);

    // URL-encode a narrow string for query parameters.
    static std::wstring Utf8ToWide(const std::string& s);
};
