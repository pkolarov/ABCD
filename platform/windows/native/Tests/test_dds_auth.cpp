// test_dds_auth.cpp
// Mock-based tests for the DDS auth flow.
//
// Included by test_main.cpp -- do NOT compile separately.
//
// Since CDdsNodeHttpClient depends on WinHTTP (Windows-only), these tests
// verify URL formatting, JSON payload construction, and JSON response
// parsing logic using standalone reimplementations of the helper methods.
// This lets us run layout/logic tests on any platform (including macOS CI).
//

#include <string>
#include <vector>
#include <cstring>

// ============================================================================
// Standalone copies of CDdsNodeHttpClient's JSON helpers for testing.
// These are intentionally duplicated from DdsNodeHttpClient.cpp so the test
// file is self-contained and compilable without WinHTTP headers.
// ============================================================================

namespace TestJsonHelpers
{

static std::string JsonGetString(const std::string& json, const std::string& key)
{
    std::string needle = "\"" + key + "\"";
    size_t pos = json.find(needle);
    if (pos == std::string::npos)
        return "";

    pos += needle.size();
    pos = json.find(':', pos);
    if (pos == std::string::npos)
        return "";
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
           json[pos] == '\r' || json[pos] == '\n'))
        pos++;

    if (pos >= json.size() || json[pos] != '"')
        return "";
    pos++;

    std::string result;
    while (pos < json.size() && json[pos] != '"')
    {
        if (json[pos] == '\\' && pos + 1 < json.size())
        {
            pos++;
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

static bool JsonGetBool(const std::string& json, const std::string& key, bool defaultVal)
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

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        pos++;

    if (pos + 4 <= json.size() && json.substr(pos, 4) == "true")
        return true;
    if (pos + 5 <= json.size() && json.substr(pos, 5) == "false")
        return false;
    return defaultVal;
}

static std::vector<std::string> JsonGetObjectArray(const std::string& json, const std::string& key)
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
        if (json[pos] != '{')
            break;

        size_t start = pos;
        int depth = 0;
        while (pos < json.size())
        {
            if (json[pos] == '{') depth++;
            else if (json[pos] == '}') { depth--; if (depth == 0) { pos++; break; } }
            else if (json[pos] == '"')
            {
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

} // namespace TestJsonHelpers

// ============================================================================
// URL formatting tests
// ============================================================================

DDS_TEST(dds_node_default_base_url)
{
    // The default base URL is http://127.0.0.1:5551
    // Verify the expected endpoint paths
    std::string baseUrl = "http://127.0.0.1:5551";
    std::string assertPath = "/v1/session/assert";
    std::string enrolledPath = "/v1/enrolled-users";

    std::string fullAssert = baseUrl + assertPath;
    std::string fullEnrolled = baseUrl + enrolledPath;

    DDS_ASSERT(fullAssert == "http://127.0.0.1:5551/v1/session/assert",
               "Session assert URL must be correctly formed");
    DDS_ASSERT(fullEnrolled == "http://127.0.0.1:5551/v1/enrolled-users",
               "Enrolled users URL must be correctly formed");
}

DDS_TEST(dds_node_enrolled_users_query_param)
{
    // When deviceUrn is provided, it should be appended as a query parameter
    std::string basePath = "/v1/enrolled-users";
    std::string deviceUrn = "urn:dds:device:abc123";

    std::string fullPath = basePath + "?device_urn=" + deviceUrn;

    DDS_ASSERT(fullPath == "/v1/enrolled-users?device_urn=urn:dds:device:abc123",
               "device_urn query parameter must be appended correctly");
}

DDS_TEST(dds_node_url_parsing_strips_scheme)
{
    // Simulate SetBaseUrl logic: strip scheme, parse host:port
    std::string url = "http://127.0.0.1:5551";

    size_t schemeEnd = url.find("://");
    if (schemeEnd != std::string::npos)
        url = url.substr(schemeEnd + 3);

    while (!url.empty() && url.back() == '/')
        url.pop_back();

    size_t colon = url.find(':');
    std::string host;
    int port = 5551;
    if (colon != std::string::npos)
    {
        host = url.substr(0, colon);
        port = atoi(url.substr(colon + 1).c_str());
    }
    else
    {
        host = url;
    }

    DDS_ASSERT(host == "127.0.0.1", "Host must be parsed correctly");
    DDS_ASSERT(port == 5551,        "Port must be parsed correctly");
}

DDS_TEST(dds_node_url_parsing_custom_port)
{
    std::string url = "http://localhost:9090/";

    size_t schemeEnd = url.find("://");
    if (schemeEnd != std::string::npos)
        url = url.substr(schemeEnd + 3);

    while (!url.empty() && url.back() == '/')
        url.pop_back();

    size_t colon = url.find(':');
    std::string host;
    int port = 5551;
    if (colon != std::string::npos)
    {
        host = url.substr(0, colon);
        port = atoi(url.substr(colon + 1).c_str());
    }

    DDS_ASSERT(host == "localhost", "Host must be 'localhost'");
    DDS_ASSERT(port == 9090,       "Port must be 9090");
}

// ============================================================================
// JSON payload construction tests for /v1/session/assert
// ============================================================================

DDS_TEST(session_assert_json_payload)
{
    // Construct the JSON payload that PostSessionAssert sends
    std::string authenticatorData = "AQIDBA==";
    std::string clientDataJSON    = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0=";
    std::string signature         = "MEUCIQC+";
    std::string userHandle        = "dXNlcjEyMw==";

    // Build the assertion JSON as the caller would
    std::string json = "{";
    json += "\"authenticatorData\":\"" + authenticatorData + "\",";
    json += "\"clientDataJSON\":\"" + clientDataJSON + "\",";
    json += "\"signature\":\"" + signature + "\",";
    json += "\"userHandle\":\"" + userHandle + "\"";
    json += "}";

    // Verify all fields are present and extractable
    std::string gotAuth = TestJsonHelpers::JsonGetString(json, "authenticatorData");
    std::string gotCdj  = TestJsonHelpers::JsonGetString(json, "clientDataJSON");
    std::string gotSig  = TestJsonHelpers::JsonGetString(json, "signature");
    std::string gotUh   = TestJsonHelpers::JsonGetString(json, "userHandle");

    DDS_ASSERT(gotAuth == authenticatorData, "authenticatorData must round-trip in JSON");
    DDS_ASSERT(gotCdj  == clientDataJSON,    "clientDataJSON must round-trip in JSON");
    DDS_ASSERT(gotSig  == signature,         "signature must round-trip in JSON");
    DDS_ASSERT(gotUh   == userHandle,        "userHandle must round-trip in JSON");
}

DDS_TEST(session_assert_response_success)
{
    // Simulate a successful response from dds-node
    std::string response = "{\"session_token\":\"eyJhbGciOiJSUzI1NiJ9.test\",\"success\":true}";

    std::string token = TestJsonHelpers::JsonGetString(response, "session_token");
    DDS_ASSERT(token == "eyJhbGciOiJSUzI1NiJ9.test",
               "session_token must be extracted from success response");
}

DDS_TEST(session_assert_response_error)
{
    // Simulate an error response from dds-node
    std::string response = "{\"error\":\"invalid_assertion\",\"success\":false}";

    std::string error = TestJsonHelpers::JsonGetString(response, "error");
    DDS_ASSERT(error == "invalid_assertion",
               "error message must be extracted from error response");
}

// ============================================================================
// JSON parsing tests for enrolled-users response
// ============================================================================

DDS_TEST(enrolled_users_parse_empty_list)
{
    std::string response = "{\"users\":[]}";

    auto users = TestJsonHelpers::JsonGetObjectArray(response, "users");
    DDS_ASSERT(users.size() == 0, "Empty user array must yield 0 entries");
}

DDS_TEST(enrolled_users_parse_single_user)
{
    std::string response =
        "{\"users\":[{\"user_sid\":\"S-1-5-21-123\","
        "\"display_name\":\"Alice\","
        "\"credential_id\":\"Y3JlZC0x\"}]}";

    auto users = TestJsonHelpers::JsonGetObjectArray(response, "users");
    DDS_ASSERT(users.size() == 1, "Must parse exactly 1 user");

    if (users.size() >= 1)
    {
        std::string sid  = TestJsonHelpers::JsonGetString(users[0], "user_sid");
        std::string name = TestJsonHelpers::JsonGetString(users[0], "display_name");
        std::string cred = TestJsonHelpers::JsonGetString(users[0], "credential_id");

        DDS_ASSERT(sid  == "S-1-5-21-123", "user_sid must be parsed correctly");
        DDS_ASSERT(name == "Alice",        "display_name must be parsed correctly");
        DDS_ASSERT(cred == "Y3JlZC0x",    "credential_id must be parsed correctly");
    }
}

DDS_TEST(enrolled_users_parse_multiple_users)
{
    std::string response =
        "{\"users\":["
        "{\"user_sid\":\"S-1-5-21-100\",\"display_name\":\"Alice\",\"credential_id\":\"c1\"},"
        "{\"user_sid\":\"S-1-5-21-200\",\"display_name\":\"Bob\",\"credential_id\":\"c2\"},"
        "{\"user_sid\":\"S-1-5-21-300\",\"display_name\":\"Charlie\",\"credential_id\":\"c3\"}"
        "]}";

    auto users = TestJsonHelpers::JsonGetObjectArray(response, "users");
    DDS_ASSERT(users.size() == 3, "Must parse exactly 3 users");

    if (users.size() >= 3)
    {
        DDS_ASSERT(TestJsonHelpers::JsonGetString(users[0], "display_name") == "Alice",
                   "First user must be Alice");
        DDS_ASSERT(TestJsonHelpers::JsonGetString(users[1], "display_name") == "Bob",
                   "Second user must be Bob");
        DDS_ASSERT(TestJsonHelpers::JsonGetString(users[2], "display_name") == "Charlie",
                   "Third user must be Charlie");
    }
}

DDS_TEST(enrolled_users_parse_missing_key)
{
    // Response without the "users" key
    std::string response = "{\"count\":0}";

    auto users = TestJsonHelpers::JsonGetObjectArray(response, "users");
    DDS_ASSERT(users.size() == 0, "Missing 'users' key must yield 0 entries");
}

DDS_TEST(json_get_bool_parsing)
{
    std::string json = "{\"success\":true,\"active\":false}";

    bool success = TestJsonHelpers::JsonGetBool(json, "success", false);
    bool active  = TestJsonHelpers::JsonGetBool(json, "active", true);
    bool missing = TestJsonHelpers::JsonGetBool(json, "nonexistent", true);

    DDS_ASSERT(success == true,  "success must parse as true");
    DDS_ASSERT(active  == false, "active must parse as false");
    DDS_ASSERT(missing == true,  "missing key must return default value");
}

DDS_TEST(json_get_string_with_escapes)
{
    std::string json = "{\"msg\":\"hello\\nworld\\t!\"}";

    std::string val = TestJsonHelpers::JsonGetString(json, "msg");
    DDS_ASSERT(val == "hello\nworld\t!", "Escaped characters must be unescaped");
}

DDS_TEST(json_get_string_missing_key)
{
    std::string json = "{\"foo\":\"bar\"}";

    std::string val = TestJsonHelpers::JsonGetString(json, "baz");
    DDS_ASSERT(val.empty(), "Missing key must return empty string");
}
