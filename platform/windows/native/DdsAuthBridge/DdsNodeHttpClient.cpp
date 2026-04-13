// DdsNodeHttpClient.cpp
// WinHTTP-based client for the dds-node REST API.
//

#include "DdsNodeHttpClient.h"
#include "FileLog.h"
#include <sstream>
#include <algorithm>

// ============================================================================
// Construction / Configuration
// ============================================================================

CDdsNodeHttpClient::CDdsNodeHttpClient()
    : m_host(L"127.0.0.1")
    , m_port(5551)
{
}

CDdsNodeHttpClient::~CDdsNodeHttpClient()
{
}

void CDdsNodeHttpClient::SetBaseUrl(const std::string& baseUrl)
{
    // Parse "http://host:port" -- minimal parsing for localhost use.
    // Expected forms: "http://127.0.0.1:5551", "http://localhost:5551"
    std::string url = baseUrl;

    // Strip scheme
    size_t schemeEnd = url.find("://");
    if (schemeEnd != std::string::npos)
        url = url.substr(schemeEnd + 3);

    // Strip trailing slash
    while (!url.empty() && url.back() == '/')
        url.pop_back();

    // Split host:port
    size_t colon = url.find(':');
    if (colon != std::string::npos)
    {
        m_host = Utf8ToWide(url.substr(0, colon));
        m_port = static_cast<INTERNET_PORT>(atoi(url.substr(colon + 1).c_str()));
    }
    else
    {
        m_host = Utf8ToWide(url);
        m_port = 5551;
    }
}

void CDdsNodeHttpClient::SetPort(DWORD port)
{
    m_port = static_cast<INTERNET_PORT>(port);
}

// ============================================================================
// POST /v1/session/assert
// ============================================================================

DdsAssertResult CDdsNodeHttpClient::PostSessionAssert(const std::string& assertionJson)
{
    DdsAssertResult result = {};
    result.success = false;

    FileLog::Writef("DdsNodeHttpClient: POST /v1/session/assert (bodyLen=%zu)\n",
                    assertionJson.size());

    std::string responseBody;
    DWORD httpStatus = SendRequest(L"POST", L"/v1/session/assert",
                                   &assertionJson, responseBody);

    if (httpStatus == 0)
    {
        result.errorMessage = "Connection to dds-node failed (is it running?)";
        FileLog::Write("DdsNodeHttpClient: POST /v1/session/assert -- connection failed\n");
        return result;
    }

    FileLog::Writef("DdsNodeHttpClient: POST /v1/session/assert -> HTTP %lu (bodyLen=%zu)\n",
                    httpStatus, responseBody.size());

    if (httpStatus == 200)
    {
        result.success = true;
        result.sessionId    = JsonGetString(responseBody, "session_id");
        result.tokenCborB64 = JsonGetString(responseBody, "token_cbor_b64");
        // Parse expires_at as a number (the JSON helper only does strings,
        // so extract the raw digits after the key).
        result.expiresAt = 0;
        {
            std::string needle = "\"expires_at\"";
            size_t pos = responseBody.find(needle);
            if (pos != std::string::npos) {
                pos += needle.size();
                pos = responseBody.find(':', pos);
                if (pos != std::string::npos) {
                    pos++;
                    while (pos < responseBody.size() && responseBody[pos] == ' ') pos++;
                    result.expiresAt = strtoull(responseBody.c_str() + pos, nullptr, 10);
                }
            }
        }
    }
    else
    {
        result.success = false;
        result.errorMessage = JsonGetString(responseBody, "error");
        if (result.errorMessage.empty())
        {
            char buf[64];
            sprintf_s(buf, "dds-node returned HTTP %lu", httpStatus);
            result.errorMessage = buf;
        }
    }

    return result;
}

// ============================================================================
// GET /v1/enrolled-users
// ============================================================================

DdsEnrolledUsersResult CDdsNodeHttpClient::GetEnrolledUsers(const std::string& deviceUrn)
{
    DdsEnrolledUsersResult result = {};
    result.success = false;

    // Build path with query parameter
    std::wstring path = L"/v1/enrolled-users";
    if (!deviceUrn.empty())
    {
        path += L"?device_urn=";
        // Simple URL-encode: just replace spaces and special chars.
        // For a URN this is typically already URL-safe.
        path += Utf8ToWide(deviceUrn);
    }

    FileLog::Writef("DdsNodeHttpClient: GET /v1/enrolled-users (device_urn='%s')\n",
                    deviceUrn.c_str());

    std::string responseBody;
    DWORD httpStatus = SendRequest(L"GET", path.c_str(), nullptr, responseBody);

    if (httpStatus == 0)
    {
        result.errorMessage = "Connection to dds-node failed (is it running?)";
        FileLog::Write("DdsNodeHttpClient: GET /v1/enrolled-users -- connection failed\n");
        return result;
    }

    FileLog::Writef("DdsNodeHttpClient: GET /v1/enrolled-users -> HTTP %lu (bodyLen=%zu)\n",
                    httpStatus, responseBody.size());

    if (httpStatus == 200)
    {
        result.success = true;

        // Parse the JSON array of user objects
        auto userObjects = JsonGetObjectArray(responseBody, "users");
        for (const auto& obj : userObjects)
        {
            DdsEnrolledUser user;
            user.subjectUrn   = JsonGetString(obj, "subject_urn");
            user.displayName  = JsonGetString(obj, "display_name");
            user.credentialId = JsonGetString(obj, "credential_id");
            user.subjectUrn   = JsonGetString(obj, "subject_urn");
            user.vouched      = (obj.find("\"vouched\":true") != std::string::npos);
            result.users.push_back(std::move(user));
        }
    }
    else
    {
        result.errorMessage = JsonGetString(responseBody, "error");
        if (result.errorMessage.empty())
        {
            char buf[64];
            sprintf_s(buf, "dds-node returned HTTP %lu", httpStatus);
            result.errorMessage = buf;
        }
    }

    return result;
}

// ============================================================================
// POST /v1/enroll/user
// ============================================================================

DdsEnrollResult CDdsNodeHttpClient::PostEnrollUser(const std::string& enrollJson)
{
    DdsEnrollResult result = {};
    result.success = false;

    FileLog::Writef("DdsNodeHttpClient: POST /v1/enroll/user (bodyLen=%zu)\n",
                    enrollJson.size());

    std::string responseBody;
    DWORD httpStatus = SendRequest(L"POST", L"/v1/enroll/user",
                                   &enrollJson, responseBody);

    if (httpStatus == 0)
    {
        result.errorMessage = "Connection to dds-node failed (is it running?)";
        return result;
    }

    FileLog::Writef("DdsNodeHttpClient: POST /v1/enroll/user -> HTTP %lu\n", httpStatus);

    if (httpStatus == 200)
    {
        result.success = true;
        result.urn = JsonGetString(responseBody, "urn");
        result.jti = JsonGetString(responseBody, "jti");
    }
    else
    {
        result.errorMessage = JsonGetString(responseBody, "error");
        if (result.errorMessage.empty())
        {
            char buf[64];
            sprintf_s(buf, "dds-node returned HTTP %lu", httpStatus);
            result.errorMessage = buf;
        }
    }

    return result;
}

// ============================================================================
// POST /v1/admin/setup
// ============================================================================

DdsAdminSetupResult CDdsNodeHttpClient::PostAdminSetup(const std::string& setupJson)
{
    DdsAdminSetupResult result = {};
    result.success = false;

    FileLog::Writef("DdsNodeHttpClient: POST /v1/admin/setup (bodyLen=%zu)\n",
                    setupJson.size());

    std::string responseBody;
    DWORD httpStatus = SendRequest(L"POST", L"/v1/admin/setup",
                                   &setupJson, responseBody);

    if (httpStatus == 0)
    {
        result.errorMessage = "Connection to dds-node failed (is it running?)";
        return result;
    }

    FileLog::Writef("DdsNodeHttpClient: POST /v1/admin/setup -> HTTP %lu\n", httpStatus);

    if (httpStatus == 200)
    {
        result.success = true;
        result.adminUrn = JsonGetString(responseBody, "urn");
    }
    else
    {
        result.errorMessage = JsonGetString(responseBody, "error");
        if (result.errorMessage.empty())
        {
            char buf[64];
            sprintf_s(buf, "dds-node returned HTTP %lu", httpStatus);
            result.errorMessage = buf;
        }
    }

    return result;
}

// ============================================================================
// POST /v1/admin/vouch
// ============================================================================

DdsAdminVouchResult CDdsNodeHttpClient::PostAdminVouch(const std::string& vouchJson)
{
    DdsAdminVouchResult result = {};
    result.success = false;

    FileLog::Writef("DdsNodeHttpClient: POST /v1/admin/vouch (bodyLen=%zu)\n",
                    vouchJson.size());

    std::string responseBody;
    DWORD httpStatus = SendRequest(L"POST", L"/v1/admin/vouch",
                                   &vouchJson, responseBody);

    if (httpStatus == 0)
    {
        result.errorMessage = "Connection to dds-node failed (is it running?)";
        return result;
    }

    FileLog::Writef("DdsNodeHttpClient: POST /v1/admin/vouch -> HTTP %lu\n", httpStatus);

    if (httpStatus == 200)
    {
        result.success = true;
        result.vouchJti = JsonGetString(responseBody, "vouch_jti");
        result.subjectUrn = JsonGetString(responseBody, "subject_urn");
        result.adminUrn = JsonGetString(responseBody, "admin_urn");
    }
    else
    {
        result.errorMessage = JsonGetString(responseBody, "error");
        if (result.errorMessage.empty())
        {
            char buf[64];
            sprintf_s(buf, "dds-node returned HTTP %lu", httpStatus);
            result.errorMessage = buf;
        }
    }

    return result;
}

// ============================================================================
// POST /v1/windows/claim-account
// ============================================================================

DdsWindowsClaimResult CDdsNodeHttpClient::PostWindowsClaim(const std::string& claimJson)
{
    DdsWindowsClaimResult result = {};
    result.success = false;

    FileLog::Writef("DdsNodeHttpClient: POST /v1/windows/claim-account (bodyLen=%zu)\n",
                    claimJson.size());

    std::string responseBody;
    DWORD httpStatus = SendRequest(L"POST", L"/v1/windows/claim-account",
                                   &claimJson, responseBody);

    if (httpStatus == 0)
    {
        result.errorMessage = "Connection to dds-node failed (is it running?)";
        return result;
    }

    FileLog::Writef("DdsNodeHttpClient: POST /v1/windows/claim-account -> HTTP %lu\n", httpStatus);

    if (httpStatus == 200)
    {
        result.success = true;
        result.subjectUrn = JsonGetString(responseBody, "subject_urn");
        result.username = JsonGetString(responseBody, "username");
        result.fullName = JsonGetString(responseBody, "full_name");
        result.description = JsonGetString(responseBody, "description");
        result.groups = JsonGetStringArray(responseBody, "groups");

        std::string pneNeedle = "\"password_never_expires\"";
        size_t pos = responseBody.find(pneNeedle);
        if (pos != std::string::npos)
        {
            result.hasPasswordNeverExpires = true;
            result.passwordNeverExpires = JsonGetBool(responseBody, "password_never_expires", false);
        }
    }
    else
    {
        result.errorMessage = JsonGetString(responseBody, "error");
        if (result.errorMessage.empty())
        {
            char buf[64];
            sprintf_s(buf, "dds-node returned HTTP %lu", httpStatus);
            result.errorMessage = buf;
        }
    }

    return result;
}

// ============================================================================
// WinHTTP transport
// ============================================================================

DWORD CDdsNodeHttpClient::SendRequest(
    const wchar_t* verb,
    const wchar_t* path,
    const std::string* requestBody,
    std::string& responseBody)
{
    responseBody.clear();
    DWORD httpStatus = 0;

    // Open session
    HINTERNET hSession = WinHttpOpen(
        L"DdsAuthBridge/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (!hSession)
    {
        FileLog::Writef("DdsNodeHttpClient: WinHttpOpen failed: %lu\n", GetLastError());
        return 0;
    }

    // Set timeouts: connect=2s, send=5s, receive=10s
    WinHttpSetTimeouts(hSession, 2000, 2000, 5000, 10000);

    // Connect
    HINTERNET hConnect = WinHttpConnect(hSession, m_host.c_str(), m_port, 0);
    if (!hConnect)
    {
        FileLog::Writef("DdsNodeHttpClient: WinHttpConnect failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hSession);
        return 0;
    }

    // Open request (HTTP, not HTTPS -- dds-node is localhost)
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, verb, path,
        NULL,                           // HTTP/1.1
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);                             // No WINHTTP_FLAG_SECURE for localhost
    if (!hRequest)
    {
        FileLog::Writef("DdsNodeHttpClient: WinHttpOpenRequest failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 0;
    }

    // Add Content-Type header for POST
    if (requestBody != nullptr)
    {
        WinHttpAddRequestHeaders(hRequest,
            L"Content-Type: application/json\r\n",
            (DWORD)-1,
            WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);
    }

    // Send
    BOOL bResult = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        requestBody ? (LPVOID)requestBody->data() : WINHTTP_NO_REQUEST_DATA,
        requestBody ? static_cast<DWORD>(requestBody->size()) : 0,
        requestBody ? static_cast<DWORD>(requestBody->size()) : 0,
        0);

    if (!bResult)
    {
        FileLog::Writef("DdsNodeHttpClient: WinHttpSendRequest failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 0;
    }

    // Receive response
    bResult = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResult)
    {
        FileLog::Writef("DdsNodeHttpClient: WinHttpReceiveResponse failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return 0;
    }

    // Read status code
    DWORD statusSize = sizeof(httpStatus);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &httpStatus, &statusSize, WINHTTP_NO_HEADER_INDEX);

    // Read response body
    DWORD bytesAvailable = 0;
    do
    {
        bytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable))
            break;

        if (bytesAvailable == 0)
            break;

        // Cap single read at 64 KB
        DWORD toRead = min(bytesAvailable, (DWORD)65536);
        std::vector<char> buf(toRead);
        DWORD bytesRead = 0;

        if (WinHttpReadData(hRequest, buf.data(), toRead, &bytesRead))
        {
            responseBody.append(buf.data(), bytesRead);
        }
        else
        {
            break;
        }

        // Safety: don't read more than 1 MB total
        if (responseBody.size() > 1024 * 1024)
            break;

    } while (bytesAvailable > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return httpStatus;
}

// ============================================================================
// Minimal JSON helpers
//
// These handle the simple flat-object JSON that dds-node returns.
// No external JSON library dependency.
// ============================================================================

std::string CDdsNodeHttpClient::JsonGetString(const std::string& json, const std::string& key)
{
    // Look for "key":"value" or "key": "value"
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return "";

    // Skip past key and colon
    pos += needle.size();
    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return "";
    pos++; // skip ':'

    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
           json[pos] == '\r' || json[pos] == '\n'))
        pos++;

    if (pos >= json.size() || json[pos] != '"')
        return "";

    pos++; // skip opening quote

    // Read until unescaped closing quote
    std::string result;
    while (pos < json.size() && json[pos] != '"')
    {
        if (json[pos] == '\\' && pos + 1 < json.size())
        {
            pos++; // skip backslash
            switch (json[pos])
            {
            case '"':  result += '"';  break;
            case '\\': result += '\\'; break;
            case '/':  result += '/';  break;
            case 'n':  result += '\n'; break;
            case 'r':  result += '\r'; break;
            case 't':  result += '\t'; break;
            default:   result += json[pos]; break;
            }
        }
        else
        {
            result += json[pos];
        }
        pos++;
    }

    return result;
}

bool CDdsNodeHttpClient::JsonGetBool(const std::string& json, const std::string& key, bool defaultVal)
{
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return defaultVal;

    pos += needle.size();
    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return defaultVal;
    pos++;

    // Skip whitespace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        pos++;

    if (pos + 4 <= json.size() && json.substr(pos, 4) == "true")
        return true;
    if (pos + 5 <= json.size() && json.substr(pos, 5) == "false")
        return false;

    return defaultVal;
}

std::vector<std::string> CDdsNodeHttpClient::JsonGetObjectArray(const std::string& json, const std::string& key)
{
    std::vector<std::string> results;

    // Find "key": [...]
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return results;

    pos += needle.size();
    pos = json.find('[', pos);
    if (pos == std::string::npos)
        return results;
    pos++; // skip '['

    // Extract each {...} object
    while (pos < json.size())
    {
        // Skip whitespace and commas
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
               json[pos] == '\r' || json[pos] == '\n' || json[pos] == ','))
            pos++;

        if (pos >= json.size() || json[pos] == ']')
            break;

        if (json[pos] != '{')
            break;

        // Find matching closing brace (no nested objects expected)
        size_t start = pos;
        int depth = 0;
        while (pos < json.size())
        {
            if (json[pos] == '{') depth++;
            else if (json[pos] == '}') { depth--; if (depth == 0) { pos++; break; } }
            else if (json[pos] == '"')
            {
                // Skip string content (handle escaped quotes)
                pos++;
                while (pos < json.size() && json[pos] != '"')
                {
                    if (json[pos] == '\\') pos++;
                    pos++;
                }
            }
            pos++;
        }

        results.push_back(json.substr(start, pos - start));
    }

    return results;
}

std::vector<std::string> CDdsNodeHttpClient::JsonGetStringArray(const std::string& json, const std::string& key)
{
    std::vector<std::string> results;

    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return results;

    pos += needle.size();
    pos = json.find('[', pos);
    if (pos == std::string::npos)
        return results;
    pos++;

    while (pos < json.size())
    {
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
               json[pos] == '\r' || json[pos] == '\n' || json[pos] == ','))
            pos++;

        if (pos >= json.size() || json[pos] == ']')
            break;
        if (json[pos] != '"')
            break;

        pos++;
        std::string value;
        while (pos < json.size() && json[pos] != '"')
        {
            if (json[pos] == '\\' && pos + 1 < json.size())
            {
                pos++;
                switch (json[pos])
                {
                case '"':  value += '"';  break;
                case '\\': value += '\\'; break;
                case '/':  value += '/';  break;
                case 'n':  value += '\n'; break;
                case 'r':  value += '\r'; break;
                case 't':  value += '\t'; break;
                default:   value += json[pos]; break;
                }
            }
            else
            {
                value += json[pos];
            }
            pos++;
        }
        results.push_back(std::move(value));
        if (pos < json.size() && json[pos] == '"')
            pos++;
    }

    return results;
}

std::wstring CDdsNodeHttpClient::Utf8ToWide(const std::string& s)
{
    if (s.empty()) return L"";

    int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
    if (needed <= 0) return L"";

    std::wstring result(needed, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &result[0], needed);
    return result;
}
