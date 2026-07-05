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
#include "FileLog.h"

#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <atomic>

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
// Argument parsing
// ---------------------------------------------------------------------------
struct CliArgs
{
    bool         passwordStdin = false;
    bool         newUser       = false;   // --new-user (bare enroll)
    std::wstring label;                    // --label <username>
    std::wstring displayName;              // --display-name "<Full Name>"
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
        else if (a == L"--label" && i + 1 < argc)        args.label = argv[++i];
        else if (a == L"--display-name" && i + 1 < argc) args.displayName = argv[++i];
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
        "Usage:\n"
        "  dds-enroll-user.exe --password-stdin\n"
        "  dds-enroll-user.exe --new-user --label jsmith --display-name \"Jane Smith\"\n"
        "\n"
        "Exit codes:\n"
        "  0  enrollment posted to dds-node\n"
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
    if (args.newUser == args.passwordStdin)
    {
        std::cerr << "error: specify exactly one of --password-stdin or --new-user.\n\n";
        PrintHelp();
        return 2;
    }
    if (args.newUser && (args.label.empty() || args.displayName.empty()))
    {
        std::cerr << "error: --new-user requires --label and --display-name.\n\n";
        PrintHelp();
        return 2;
    }

    FileLog::Init();
    FileLog::Write("DdsEnrollUser: starting\n");

    HWND hwnd = CreateHiddenOwner();
    // hwnd may be NULL on rare failures; the WebAuthn API handles NULL by
    // anchoring on the foreground window, which is acceptable here.

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
