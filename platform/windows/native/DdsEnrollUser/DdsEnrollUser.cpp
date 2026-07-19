// DdsEnrollUser.cpp
// Console wrapper around RunEnrollmentFlowEx. Reads the Windows password
// from stdin (UTF-8, single line, trailing CRLF/LF stripped), drives the
// existing FIDO2 enrollment ceremony, and emits NDJSON status lines on
// stdout so the PowerShell wizard (DdsConsole.ps1) can render progress
// and error pages.
//
// The Windows WebAuthn API still shows the OS-level "Touch your security
// key" prompt — that part is mandatory and out of our control. What we
// suppress are the legacy MessageBox dialogs that the tray agent uses;
// the wizard provides those instead, on its own pages.
//
// Exit codes:
//   0 — vault saved, enrollment posted to dds-node successfully
//   1 — vault saved, but POST /v1/enroll/user failed (queue / retry later)
//   2 — error before vault was saved (no enrollment to clean up)
//   3 — user cancelled
//
// CLI:
//   dds-enroll-user.exe --password-stdin   (only mode supported in v1)

#include "EnrollmentFlow.h"
#include "WebAuthnHelper.h"
#include "DdsNodeHttpClient.h"
#include "Configuration.h"
#include "FileLog.h"

#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <iostream>
#include <atomic>

#pragma comment(lib, "advapi32.lib")   // registry (admin credential id)

// ---------------------------------------------------------------------------
// Hidden message-only window for the WebAuthn API to anchor its dialogs.
// ---------------------------------------------------------------------------
static HWND CreateHiddenOwner()
{
    static const wchar_t* kClass = L"DdsEnrollUserHiddenWnd";
    WNDCLASSEXW wcx = {};
    wcx.cbSize        = sizeof(wcx);
    wcx.lpfnWndProc   = DefWindowProcW;
    wcx.hInstance     = GetModuleHandleW(NULL);
    wcx.lpszClassName = kClass;
    RegisterClassExW(&wcx); // OK if it fails because already registered

    return CreateWindowExW(
        0, kClass, L"DDS Enroll User",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        NULL, NULL, GetModuleHandleW(NULL), NULL);
}

// ---------------------------------------------------------------------------
// Read one line of UTF-8 from stdin, strip trailing newline(s), return as
// std::wstring (UTF-16LE).
// ---------------------------------------------------------------------------
static bool ReadPasswordLineFromStdin(std::wstring& out)
{
    // Lock to byte mode so we can read raw UTF-8.
    _setmode(_fileno(stdin), _O_BINARY);

    std::string line;
    line.reserve(256);
    int c;
    while ((c = fgetc(stdin)) != EOF)
    {
        if (c == '\n') break;
        line.push_back(static_cast<char>(c));
    }
    if (line.empty() && c == EOF) return false;
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
        line.pop_back();

    int wlen = MultiByteToWideChar(CP_UTF8, 0, line.c_str(),
                                   static_cast<int>(line.size()),
                                   nullptr, 0);
    if (wlen <= 0)
    {
        out.clear();
        // Wipe the byte buffer ASAP.
        SecureZeroMemory(line.data(), line.size());
        return true; // empty password is technically allowed; caller decides
    }
    out.resize(static_cast<size_t>(wlen));
    MultiByteToWideChar(CP_UTF8, 0, line.c_str(),
                        static_cast<int>(line.size()),
                        out.data(), wlen);
    SecureZeroMemory(line.data(), line.size());
    return true;
}

// ---------------------------------------------------------------------------
// Emit a NDJSON line on stdout. We flush after every line so the wizard
// can render in real time.
// ---------------------------------------------------------------------------
static void EmitNdjson(const std::string& line)
{
    std::cout << line << "\n";
    std::cout.flush();
}

// ---------------------------------------------------------------------------
// Admin-vouch ceremony helpers (mirrors DdsTrayAgent/AdminFlow.cpp; the units
// they call — CWebAuthnHelper, CDdsNodeHttpClient, CDdsConfiguration — are
// already linked into this exe via WebAuthnHelper.cpp + DdsCommon).
// ---------------------------------------------------------------------------

static std::string VouchBase64UrlEncode(const uint8_t* data, size_t len)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len * 4 + 2) / 3);
    for (size_t i = 0; i < len; i += 3)
    {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        out.push_back(table[(n >> 18) & 0x3F]);
        out.push_back(table[(n >> 12) & 0x3F]);
        if (i + 1 < len) out.push_back(table[(n >> 6) & 0x3F]);
        if (i + 2 < len) out.push_back(table[n & 0x3F]);
    }
    for (auto& c : out) { if (c == '+') c = '-'; else if (c == '/') c = '_'; }
    return out;
}

static std::vector<uint8_t> VouchBase64UrlDecode(const std::string& input)
{
    std::string b64 = input;
    for (auto& c : b64) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
    while (b64.size() % 4 != 0) b64.push_back('=');
    static const int T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> out;
    out.reserve(b64.size() * 3 / 4);
    for (size_t i = 0; i + 3 < b64.size(); i += 4)
    {
        int a = T[(unsigned char)b64[i]];
        int b = T[(unsigned char)b64[i+1]];
        int c = T[(unsigned char)b64[i+2]];
        int d = T[(unsigned char)b64[i+3]];
        if (a < 0 || b < 0) break;
        out.push_back((uint8_t)((a << 2) | (b >> 4)));
        if (c >= 0) out.push_back((uint8_t)(((b & 0xF) << 4) | (c >> 2)));
        if (d >= 0) out.push_back((uint8_t)(((c & 3) << 6) | d));
    }
    return out;
}

// Load the admin credential id written by Admin Setup
// (HKLM\SOFTWARE\DDS\AuthBridge\AdminCredentialId, base64url).
static bool LoadAdminCredentialIdFromRegistry(std::vector<uint8_t>& outCredId)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\DDS\\AuthBridge", 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;
    char buf[512] = {};
    DWORD bufLen = sizeof(buf);
    DWORD type = 0;
    LONG ret = RegQueryValueExA(hKey, "AdminCredentialId", NULL, &type,
        reinterpret_cast<LPBYTE>(buf), &bufLen);
    RegCloseKey(hKey);
    if (ret != ERROR_SUCCESS || type != REG_SZ || bufLen == 0)
        return false;
    outCredId = VouchBase64UrlDecode(std::string(buf));
    return !outCredId.empty();
}

static std::string VouchJsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char b[8]; sprintf_s(b, sizeof(b), "\\u%04x", c); out += b;
                } else { out += c; }
        }
    }
    return out;
}

static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), n, nullptr, nullptr);
    return s;
}

// Admin-vouch a subject URN for a purpose, using the admin key on THIS
// machine. Argv-driven, purpose-carrying, headless (NDJSON) equivalent of
// RunAdminApproveFlow — used by the console's "Authorize this machine to
// publish" button (subject = node URN, purpose = dds:policy-publisher-*).
// NDJSON phases: start, challenge, touch_prompt, asserted,
//   vouched{subject_urn,admin_urn,jti} | error{at,message}.
// Returns 0 on success, 2 on error.
static int RunAdminVouchNdjson(HWND hwnd,
                               const std::wstring& subjectUrnW,
                               const std::wstring& purposeW,
                               const std::wstring& credentialIdW,
                               bool revoke)
{
    std::string subjectUrn = WideToUtf8(subjectUrnW);
    std::string purpose    = WideToUtf8(purposeW);

    FileLog::Writef("DdsEnrollUser: %s subject='%s' purpose='%s'\n",
                    revoke ? "revoke-vouch" : "vouch",
                    subjectUrn.c_str(), purpose.c_str());
    EmitNdjson("{\"phase\":\"start\"}");

    CDdsConfiguration config;
    config.Load();
    std::string rpId = config.RpId();

    std::vector<uint8_t> adminCredId;
    if (!credentialIdW.empty())
        adminCredId = VouchBase64UrlDecode(WideToUtf8(credentialIdW));
    else if (!LoadAdminCredentialIdFromRegistry(adminCredId))
    {
        EmitNdjson("{\"phase\":\"error\",\"at\":\"admin_cred\",\"message\":\"No admin key on this machine. Run Admin Setup here first, or authorize from the admin's PC.\"}");
        return 2;
    }
    if (adminCredId.empty())
    {
        EmitNdjson("{\"phase\":\"error\",\"at\":\"admin_cred\",\"message\":\"Admin credential id is empty or invalid.\"}");
        return 2;
    }

    CDdsNodeHttpClient httpClient;
    if (!config.ApiAddr().empty()) httpClient.SetBaseUrl(config.ApiAddr());
    else                           httpClient.SetPort(config.DdsNodePort());
    if (!config.HmacSecretPath().empty()) httpClient.LoadHmacSecret(config.HmacSecretPath());

    DdsChallengeResult challenge = httpClient.GetAdminChallenge();
    if (!challenge.success)
    {
        EmitNdjson("{\"phase\":\"error\",\"at\":\"challenge\",\"message\":\""
            + VouchJsonEscape(challenge.errorMessage) + "\"}");
        return 2;
    }
    EmitNdjson("{\"phase\":\"challenge\"}");

    EmitNdjson("{\"phase\":\"touch_prompt\"}");
    auto assertResult = CWebAuthnHelper::GetAssertionProof(
        hwnd, rpId, adminCredId, challenge.challengeB64url);
    if (!assertResult.success)
    {
        EmitNdjson("{\"phase\":\"error\",\"at\":\"assertion\",\"message\":\""
            + VouchJsonEscape(assertResult.errorMessage) + "\"}");
        return 2;
    }
    EmitNdjson("{\"phase\":\"asserted\"}");

    std::string credIdB64   = VouchBase64UrlEncode(adminCredId.data(), adminCredId.size());
    std::string authDataB64 = VouchBase64UrlEncode(assertResult.authenticatorData.data(), assertResult.authenticatorData.size());
    std::string sigB64      = VouchBase64UrlEncode(assertResult.signature.data(), assertResult.signature.size());
    std::string cdhB64      = VouchBase64UrlEncode(assertResult.clientDataHash.data(), assertResult.clientDataHash.size());

    std::string vouchJson = "{";
    vouchJson += "\"subject_urn\":\"" + VouchJsonEscape(subjectUrn) + "\",";
    vouchJson += "\"credential_id\":\"" + credIdB64 + "\",";
    vouchJson += "\"challenge_id\":\"" + VouchJsonEscape(challenge.challengeId) + "\",";
    vouchJson += "\"authenticator_data\":\"" + authDataB64 + "\",";
    vouchJson += "\"client_data_hash\":\"" + cdhB64 + "\",";
    vouchJson += "\"signature\":\"" + sigB64 + "\",";
    // For revoke, an empty purpose means "all vouches for the subject",
    // encoded as JSON null so the server's Option<String> is None.
    if (revoke && purpose.empty())
        vouchJson += "\"purpose\":null";
    else
        vouchJson += "\"purpose\":\"" + VouchJsonEscape(purpose) + "\"";
    vouchJson += "}";

    if (revoke)
    {
        DdsAdminRevokeVouchResult r = httpClient.PostAdminRevokeVouch(vouchJson);
        if (!r.success)
        {
            EmitNdjson("{\"phase\":\"error\",\"at\":\"revoke\",\"message\":\""
                + VouchJsonEscape(r.errorMessage) + "\"}");
            return 2;
        }
        FileLog::Writef("DdsEnrollUser: revoke-vouch OK subject='%s'\n", subjectUrn.c_str());
        // Forward the raw response (revoked[], foreign[], demoted, published)
        // as an escaped string field the console re-parses with ConvertFrom-Json.
        EmitNdjson("{\"phase\":\"revoked\",\"body\":\"" + VouchJsonEscape(r.responseBody) + "\"}");
        return 0;
    }

    DdsAdminVouchResult vouchResult = httpClient.PostAdminVouch(vouchJson);
    if (!vouchResult.success)
    {
        EmitNdjson("{\"phase\":\"error\",\"at\":\"vouch\",\"message\":\""
            + VouchJsonEscape(vouchResult.errorMessage) + "\"}");
        return 2;
    }

    FileLog::Writef("DdsEnrollUser: vouch OK jti='%s' subject='%s' admin='%s'\n",
                    vouchResult.vouchJti.c_str(), vouchResult.subjectUrn.c_str(),
                    vouchResult.adminUrn.c_str());
    EmitNdjson("{\"phase\":\"vouched\",\"subject_urn\":\"" + VouchJsonEscape(vouchResult.subjectUrn)
        + "\",\"admin_urn\":\"" + VouchJsonEscape(vouchResult.adminUrn)
        + "\",\"jti\":\"" + VouchJsonEscape(vouchResult.vouchJti) + "\"}");
    return 0;
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------
struct CliArgs
{
    bool         passwordStdin = false;
    bool         newUser       = false;   // --new-user (bare enroll)
    std::wstring label;                    // --label <username>
    std::wstring displayName;              // --display-name "<Full Name>"
    bool         vouch         = false;   // --vouch (admin vouch a subject+purpose)
    bool         revokeVouch   = false;   // --revoke-vouch (admin offboard a subject)
    std::wstring subjectUrn;               // --subject-urn <urn>
    std::wstring purpose;                  // --purpose <dds:...>
    std::wstring credentialId;             // --credential-id <b64url> (else registry)
    bool         help          = false;
};

static CliArgs ParseArgs(int argc, wchar_t** argv)
{
    CliArgs args = {};
    for (int i = 1; i < argc; ++i)
    {
        std::wstring a = argv[i];
        if      (a == L"--password-stdin") args.passwordStdin = true;
        else if (a == L"--new-user")       args.newUser = true;
        else if (a == L"--vouch")          args.vouch = true;
        else if (a == L"--revoke-vouch")   args.revokeVouch = true;
        else if (a == L"--label" && i + 1 < argc)         args.label = argv[++i];
        else if (a == L"--display-name" && i + 1 < argc)  args.displayName = argv[++i];
        else if (a == L"--subject-urn" && i + 1 < argc)   args.subjectUrn = argv[++i];
        else if (a == L"--purpose" && i + 1 < argc)       args.purpose = argv[++i];
        else if (a == L"--credential-id" && i + 1 < argc) args.credentialId = argv[++i];
        else if (a == L"--help" || a == L"-h" || a == L"/?") args.help = true;
    }
    return args;
}

static void PrintHelp()
{
    std::cerr <<
        "DdsEnrollUser — non-interactive FIDO2 enrollment helper\n"
        "\n"
        "  Runs the FIDO2 enrollment ceremony and emits NDJSON status to\n"
        "  stdout (instead of modal dialogs) for DdsConsole.ps1. Two modes:\n"
        "\n"
        "  --password-stdin\n"
        "      Passwordless sign-in for the CURRENT Windows account. Reads\n"
        "      that account's password from stdin (one UTF-8 line), does the\n"
        "      two-touch ceremony, and wraps the password into the vault.\n"
        "\n"
        "  --new-user --label <username> --display-name \"<Full Name>\"\n"
        "      Register a BRAND-NEW person's key from an admin session (their\n"
        "      key, their touch). No existing Windows account or password is\n"
        "      needed: does MakeCredential + POST /v1/enroll/user only. The\n"
        "      DDS user is named <Full Name>; its Windows account is created\n"
        "      later by the first-logon claim. One touch.\n"
        "\n"
        "  --vouch --subject-urn <urn> --purpose <dds:...> [--credential-id <b64url>]\n"
        "      Admin-vouch a subject for a purpose using the admin key on THIS\n"
        "      machine (admin's touch, UV required). Used to authorize this\n"
        "      node to publish policy (subject = node URN, purpose =\n"
        "      dds:policy-publisher-windows). The admin credential id is read\n"
        "      from the registry unless --credential-id is given.\n"
        "\n"
        "  --revoke-vouch --subject-urn <urn> [--purpose <dds:...>] [--credential-id <b64url>]\n"
        "      Offboard a subject: revoke the vouches THIS admin issued for it\n"
        "      (admin's touch, UV required). Omit --purpose to revoke every\n"
        "      vouch this admin issued for the subject (full offboarding);\n"
        "      pass --purpose dds:admin to demote a sub-admin. Emits a\n"
        "      'revoked' NDJSON line whose 'body' field is the server's JSON\n"
        "      response (revoked[], foreign[], demoted, published).\n"
        "\n"
        "Usage:\n"
        "  dds-enroll-user.exe --password-stdin\n"
        "  dds-enroll-user.exe --new-user --label jsmith --display-name \"Jane Smith\"\n"
        "  dds-enroll-user.exe --vouch --subject-urn urn:vouchsafe:dds-node.abc --purpose dds:policy-publisher-windows\n"
        "  dds-enroll-user.exe --revoke-vouch --subject-urn urn:vouchsafe:jane.abc\n"
        "\n"
        "Exit codes:\n"
        "  0  success (enrollment posted / vouch accepted)\n"
        "  1  (password-stdin only) vault saved, but POST failed (retry later)\n"
        "  2  error\n"
        "  3  user cancelled\n";
}

// ---------------------------------------------------------------------------
// wmain
// ---------------------------------------------------------------------------
int wmain(int argc, wchar_t** argv)
{
    CliArgs args = ParseArgs(argc, argv);
    if (args.help)
    {
        PrintHelp();
        return 0;
    }
    // Exactly one mode must be selected.
    int modes = (args.passwordStdin ? 1 : 0) + (args.newUser ? 1 : 0)
              + (args.vouch ? 1 : 0) + (args.revokeVouch ? 1 : 0);
    if (modes != 1)
    {
        std::cerr << "error: specify exactly one of --password-stdin, --new-user, --vouch, or --revoke-vouch.\n\n";
        PrintHelp();
        return 2;
    }
    if (args.newUser && (args.label.empty() || args.displayName.empty()))
    {
        std::cerr << "error: --new-user requires --label and --display-name.\n\n";
        PrintHelp();
        return 2;
    }
    if (args.vouch && (args.subjectUrn.empty() || args.purpose.empty()))
    {
        std::cerr << "error: --vouch requires --subject-urn and --purpose.\n\n";
        PrintHelp();
        return 2;
    }
    // --revoke-vouch requires only a subject; an empty --purpose means
    // "revoke every vouch this admin issued for the subject".
    if (args.revokeVouch && args.subjectUrn.empty())
    {
        std::cerr << "error: --revoke-vouch requires --subject-urn.\n\n";
        PrintHelp();
        return 2;
    }

    FileLog::Init();
    FileLog::Write("DdsEnrollUser: starting\n");

    HWND hwnd = CreateHiddenOwner();
    // hwnd may be NULL on rare failures; the WebAuthn API handles NULL by
    // anchoring on the foreground window, which is acceptable here.

    // Admin-vouch / revoke-vouch modes are self-contained (no
    // EnrollmentFlow machinery) — same FIDO2 UV ceremony, different
    // endpoint + response.
    if (args.vouch || args.revokeVouch)
    {
        int rc = RunAdminVouchNdjson(hwnd, args.subjectUrn, args.purpose,
                                     args.credentialId, args.revokeVouch);
        if (hwnd) DestroyWindow(hwnd);
        return rc;
    }

    EnrollmentFlowOptions opts;
    opts.hwnd        = hwnd;
    opts.interactive = false;
    opts.onPhase     = [](const std::string& json) { EmitNdjson(json); };

    if (args.newUser)
    {
        // Bare enrollment: a brand-new person, no existing account/password.
        opts.bareEnroll          = true;
        opts.label               = args.label;
        opts.displayNameOverride = args.displayName;
    }
    else
    {
        if (!ReadPasswordLineFromStdin(opts.presetPassword))
        {
            EmitNdjson("{\"phase\":\"error\",\"at\":\"password\","
                       "\"message\":\"Failed to read password from stdin.\"}");
            if (hwnd) DestroyWindow(hwnd);
            return 2;
        }
        if (opts.presetPassword.empty())
        {
            EmitNdjson("{\"phase\":\"error\",\"at\":\"password\","
                       "\"message\":\"Empty password from stdin.\"}");
            if (hwnd) DestroyWindow(hwnd);
            return 2;
        }
    }

    EnrollmentFlowResult r = RunEnrollmentFlowEx(opts);

    // Wipe sensitive material from our local copy (empty in --new-user mode).
    if (!opts.presetPassword.empty())
        SecureZeroMemory(opts.presetPassword.data(),
                         opts.presetPassword.size() * sizeof(wchar_t));

    if (hwnd) DestroyWindow(hwnd);

    if (r.success && r.serverPosted) return 0;
    if (r.success)                   return 1; // vault OK, post failed (self-service)
    if (r.errorPhase == "password" && r.errorMessage == "User cancelled.")
        return 3;
    return 2;
}
