// DdsTrayAgent.cpp
// System tray application for DDS FIDO2 enrollment and admin approval.
//
// Runs as a hidden window with a Shell_NotifyIconW tray icon.
// Context menu provides: Enroll FIDO2 Key, Admin Setup, Approve Enrollments, Exit.

#include "resource.h"
#include "EnrollmentFlow.h"
#include "AdminFlow.h"
#include "RefreshVaultFlow.h"
#include "PasswordChangeMonitor.h"
#include "CredentialVault.h"
#include "DdsNodeHttpClient.h"
#include "Configuration.h"
#include "FileLog.h"

#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <wtsapi32.h>
#include <strsafe.h>
#include <sddl.h>       // ConvertSidToStringSidW
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static HINSTANCE g_hInstance = NULL;
static HWND      g_hWnd = NULL;
static NOTIFYICONDATAW g_nid = {};
static const wchar_t* WINDOW_CLASS = L"DdsTrayAgentWndClass";
static const wchar_t* WINDOW_TITLE = L"DDS Tray Agent";

// ---------------------------------------------------------------------------
// Installed product version — stamped by the MSI at HKLM\SOFTWARE\DDS\Version.
// Falls back to "dev" when running out of a build tree before install.
// ---------------------------------------------------------------------------
static void GetInstalledVersion(wchar_t* buf, DWORD bufWchars)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\DDS", 0, KEY_READ, &hKey)
            == ERROR_SUCCESS)
    {
        DWORD type = 0;
        DWORD cb   = bufWchars * sizeof(wchar_t);
        LONG  rc   = RegQueryValueExW(hKey, L"Version", NULL, &type,
                                      reinterpret_cast<LPBYTE>(buf), &cb);
        RegCloseKey(hKey);
        if (rc == ERROR_SUCCESS && type == REG_SZ && bufWchars > 0)
        {
            buf[bufWchars - 1] = L'\0'; // defensive: registry strings may not be NUL-terminated
            return;
        }
    }
    wcscpy_s(buf, bufWchars, L"dev");
}

// ---------------------------------------------------------------------------
// Tray icon management
// ---------------------------------------------------------------------------

static void AddTrayIcon(HWND hwnd)
{
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hwnd;
    g_nid.uID = IDI_TRAYICON;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIconW(g_hInstance, MAKEINTRESOURCEW(IDI_TRAYICON));
    if (g_nid.hIcon == NULL)
    {
        // Fall back to a standard application icon if custom icon not found
        g_nid.hIcon = LoadIconW(NULL, IDI_APPLICATION);
    }
    wchar_t ver[64];
    GetInstalledVersion(ver, ARRAYSIZE(ver));
    // szTip is bounded to 128 wchars in NOTIFYICONDATAW; StringCchPrintf
    // truncates safely if the version string is unexpectedly long.
    StringCchPrintfW(g_nid.szTip, ARRAYSIZE(g_nid.szTip),
                     L"DDS Enrollment Agent  v%s", ver);
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}

static void RemoveTrayIcon()
{
    Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

// ---------------------------------------------------------------------------
// Context menu
// ---------------------------------------------------------------------------

static void ShowTrayMenu(HWND hwnd)
{
    HMENU hMenu = CreatePopupMenu();
    if (hMenu == NULL) return;

    AppendMenuW(hMenu, MF_STRING, IDM_ENROLL,          L"Enroll FIDO2 Key...");
    AppendMenuW(hMenu, MF_STRING, IDM_REFRESH_VAULT,   L"Refresh Stored Password...");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, IDM_ADMIN_SETUP,     L"Admin Setup...");
    AppendMenuW(hMenu, MF_STRING, IDM_ADMIN_APPROVE,   L"Approve Enrollments...");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, IDM_STATUS,         L"Status");
    AppendMenuW(hMenu, MF_STRING, IDM_ABOUT,           L"About DDS...");
    AppendMenuW(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuW(hMenu, MF_STRING, IDM_EXIT,            L"Exit");

    // Required for the menu to dismiss when clicking outside
    SetForegroundWindow(hwnd);

    POINT pt;
    GetCursorPos(&pt);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);

    // Required after TrackPopupMenu
    PostMessage(hwnd, WM_NULL, 0, 0);

    DestroyMenu(hMenu);
}

// ---------------------------------------------------------------------------
// Status display
// ---------------------------------------------------------------------------

static void ShowStatus(HWND hwnd)
{
    // Quick status check: try to reach dds-node
    CDdsNodeHttpClient httpClient;
    CDdsConfiguration config;
    config.Load();
    // A-2: prefer ApiAddr (carries the pipe:<name> scheme for H-7
    // step-2b's named-pipe transport). Bootstrap-DdsDomain.ps1
    // generates node.toml with `api_addr = "pipe:dds-api"` only — no
    // TCP listener — so SetPort alone gives WinHTTP error 12029.
    if (!config.ApiAddr().empty()) {
        httpClient.SetBaseUrl(config.ApiAddr());
    } else {
        httpClient.SetPort(config.DdsNodePort());
    }
    // A-3 fail-closed: load the per-install HMAC secret so the tray
    // agent can verify response-body MACs the same way the Auth Bridge
    // does. Without this, every reply is dropped with
    // "MAC verification failed over pipe ... — dropping response".
    if (!config.HmacSecretPath().empty()) {
        httpClient.LoadHmacSecret(config.HmacSecretPath());
    }

    DdsEnrolledUsersResult result = httpClient.GetEnrolledUsers(config.DeviceUrn());

    wchar_t ver[64];
    GetInstalledVersion(ver, ARRAYSIZE(ver));

    wchar_t msg[512];
    if (result.success)
    {
        swprintf_s(msg,
            L"DDS Tray Agent  v%s\n\n"
            L"Node connection: OK\n"
            L"Enrolled users: %zu\n"
            L"Port: %lu\n"
            L"RP ID: %hs",
            ver,
            result.users.size(),
            (unsigned long)config.DdsNodePort(),
            config.RpId().c_str());
    }
    else
    {
        swprintf_s(msg,
            L"DDS Tray Agent  v%s\n\n"
            L"Node connection: FAILED\n"
            L"Error: %hs\n"
            L"Port: %lu",
            ver,
            result.errorMessage.c_str(),
            (unsigned long)config.DdsNodePort());
    }

    MessageBoxW(hwnd, msg, L"DDS Status", MB_OK | MB_ICONINFORMATION);
}

// ---------------------------------------------------------------------------
// Onboarding nudge — if this machine is provisioned but the current user
// has no vault entry, show a balloon notification at most once per day so
// the user discovers the FIDO2 enrollment wizard. Click → launches
// DdsConsole.ps1 -Mode EnrollUser.
//
// Triggered once shortly after tray startup. The PasswordChangeMonitor's
// existing 60s poll loop is *not* re-used here — we only want to fire
// the nudge once per session, not every 60s.
// ---------------------------------------------------------------------------

static UINT_PTR g_nudgeTimerId = 0;
static const UINT NUDGE_TIMER_ID = 0x4444;

static bool GetCurrentUserSidW(std::wstring& outSid)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return false;
    DWORD len = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
    std::vector<BYTE> buf(len);
    BOOL ok = GetTokenInformation(hToken, TokenUser, buf.data(), len, &len);
    CloseHandle(hToken);
    if (!ok) return false;
    LPWSTR sidStr = NULL;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buf.data())->User.Sid, &sidStr))
        return false;
    outSid = sidStr;
    LocalFree(sidStr);
    return true;
}

static bool IsMachineProvisioned()
{
    // Cheap check: %ProgramData%\DDS\node-data\domain.toml present.
    wchar_t pd[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH)) return false;
    std::wstring p = pd;
    p += L"\\DDS\\node-data\\domain.toml";
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

static bool ShouldShowNudgeToday()
{
    // Persist a yyyymmdd stamp under HKCU\Software\DDS\LastEnrollNudge.
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t today[16];
    StringCchPrintfW(today, ARRAYSIZE(today), L"%04u%02u%02u",
                     st.wYear, st.wMonth, st.wDay);

    HKEY hKey = NULL;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\DDS", 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE,
                        NULL, &hKey, NULL) != ERROR_SUCCESS)
    {
        return true; // can't read — fail open to nudging once
    }
    wchar_t buf[16] = {};
    DWORD type = 0, cb = sizeof(buf);
    LONG rc = RegQueryValueExW(hKey, L"LastEnrollNudge", NULL, &type,
                               reinterpret_cast<LPBYTE>(buf), &cb);
    bool show = true;
    if (rc == ERROR_SUCCESS && type == REG_SZ && wcscmp(buf, today) == 0)
    {
        show = false;
    }
    if (show)
    {
        RegSetValueExW(hKey, L"LastEnrollNudge", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(today),
                       static_cast<DWORD>((wcslen(today) + 1) * sizeof(wchar_t)));
    }
    RegCloseKey(hKey);
    return show;
}

static void ShowEnrollNudgeBalloon(HWND hwnd)
{
    NOTIFYICONDATAW nid = g_nid;
    nid.uFlags |= NIF_INFO;
    StringCchCopyW(nid.szInfoTitle, ARRAYSIZE(nid.szInfoTitle),
                   L"Set up passwordless sign-in");
    StringCchCopyW(nid.szInfo, ARRAYSIZE(nid.szInfo),
                   L"Click here to register a security key for your account.");
    nid.dwInfoFlags = NIIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &nid);
    FileLog::Write("DdsTrayAgent: nudge balloon shown\n");
}

static void LaunchOnboardingWizardEnrollUser()
{
    // Locate DdsConsole.ps1 next to ourselves (\Program Files\DDS\bin\).
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring binDir(exePath);
    size_t slash = binDir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) binDir.resize(slash);
    std::wstring scriptPath = binDir + L"\\DdsConsole.ps1";

    std::wstring args = L"-NoProfile -ExecutionPolicy Bypass -File \"";
    args += scriptPath;
    args += L"\" -Mode EnrollUser";

    SHELLEXECUTEINFOW sei = {};
    sei.cbSize = sizeof(sei);
    sei.fMask  = SEE_MASK_NOASYNC;
    sei.lpVerb = L"open";
    sei.lpFile = L"powershell.exe";
    sei.lpParameters = args.c_str();
    sei.nShow = SW_SHOWNORMAL;
    ShellExecuteExW(&sei);
}

static void CheckAndShowEnrollNudge(HWND hwnd)
{
    if (!IsMachineProvisioned()) return;

    std::wstring sid;
    if (!GetCurrentUserSidW(sid)) return;

    CCredentialVault vault;
    vault.Load();
    auto entries = vault.FindByUserSid(sid);
    if (!entries.empty()) return;  // already enrolled

    if (!ShouldShowNudgeToday()) return;

    ShowEnrollNudgeBalloon(hwnd);
}

// ---------------------------------------------------------------------------
// Window procedure
// ---------------------------------------------------------------------------

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_TRAYICON:
        if (LOWORD(lParam) == WM_RBUTTONUP || LOWORD(lParam) == WM_CONTEXTMENU)
        {
            ShowTrayMenu(hwnd);
        }
        else if (LOWORD(lParam) == WM_LBUTTONDBLCLK)
        {
            ShowStatus(hwnd);
        }
        else if (LOWORD(lParam) == /*NIN_BALLOONUSERCLICK*/ (WM_USER + 5))
        {
            // Click on the "Set up passwordless sign-in" balloon → wizard.
            LaunchOnboardingWizardEnrollUser();
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDM_ENROLL:
            RunEnrollmentFlow(hwnd);
            break;
        case IDM_REFRESH_VAULT:
            RunRefreshVaultFlow(hwnd);
            break;
        case IDM_ADMIN_SETUP:
            RunAdminSetupFlow(hwnd);
            break;
        case IDM_ADMIN_APPROVE:
            RunAdminApproveFlow(hwnd);
            break;
        case IDM_STATUS:
            ShowStatus(hwnd);
            break;
        case IDM_ABOUT: {
            wchar_t ver[64];
            GetInstalledVersion(ver, ARRAYSIZE(ver));
            wchar_t aboutMsg[256];
            StringCchPrintfW(aboutMsg, ARRAYSIZE(aboutMsg),
                             L"DDS Windows Platform\n\n"
                             L"Installed version: %s\n\n"
                             L"Source of truth: HKLM\\SOFTWARE\\DDS\\Version",
                             ver);
            MessageBoxW(hwnd, aboutMsg, L"About DDS",
                        MB_OK | MB_ICONINFORMATION);
            break;
        }
        case IDM_EXIT:
            RemoveTrayIcon();
            PostQuitMessage(0);
            break;
        }
        return 0;

    case WM_WTSSESSION_CHANGE:
        PasswordChangeMonitor::HandleSessionChange(hwnd, wParam, lParam);
        return 0;

    case WM_TIMER:
        if (wParam == NUDGE_TIMER_ID)
        {
            // One-shot: kill the timer immediately, then probe.
            KillTimer(hwnd, NUDGE_TIMER_ID);
            g_nudgeTimerId = 0;
            CheckAndShowEnrollNudge(hwnd);
            return 0;
        }
        if (PasswordChangeMonitor::HandleTimer(hwnd, wParam))
            return 0;
        break;

    case WM_DESTROY:
        PasswordChangeMonitor::Stop(hwnd);
        RemoveTrayIcon();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ---------------------------------------------------------------------------
// WinMain
// ---------------------------------------------------------------------------

int APIENTRY wWinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE /*hPrevInstance*/,
    _In_ LPWSTR /*lpCmdLine*/,
    _In_ int /*nCmdShow*/)
{
    g_hInstance = hInstance;

    // Prevent multiple instances
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Global\\DdsTrayAgentMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        if (hMutex) CloseHandle(hMutex);
        return 0;
    }

    // Initialize common controls (for listbox, etc.)
    INITCOMMONCONTROLSEX icex = {};
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icex);

    // Initialize logger
    FileLog::Init();
    FileLog::Write("DdsTrayAgent: starting\n");

    // Register window class
    WNDCLASSEXW wcx = {};
    wcx.cbSize = sizeof(wcx);
    wcx.lpfnWndProc = WndProc;
    wcx.hInstance = hInstance;
    wcx.lpszClassName = WINDOW_CLASS;
    wcx.hIcon = LoadIconW(hInstance, MAKEINTRESOURCEW(IDI_TRAYICON));
    if (wcx.hIcon == NULL)
        wcx.hIcon = LoadIconW(NULL, IDI_APPLICATION);

    if (!RegisterClassExW(&wcx))
    {
        FileLog::Write("DdsTrayAgent: RegisterClassExW failed\n");
        return 1;
    }

    // Create hidden message-only window
    g_hWnd = CreateWindowExW(
        0,
        WINDOW_CLASS,
        WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        HWND_MESSAGE, // Message-only window
        NULL,
        hInstance,
        NULL);

    if (g_hWnd == NULL)
    {
        FileLog::Write("DdsTrayAgent: CreateWindowExW failed\n");
        return 1;
    }

    // Add tray icon
    AddTrayIcon(g_hWnd);

    // Start password-change monitor (WTS session events + 60s poll).
    // The autostart Run-key launches us with --minimized at logon; either
    // way the monitor is what we need running in the background.
    PasswordChangeMonitor::Start(g_hWnd);

    // Arm the one-shot onboarding-nudge probe ~30s after startup. The delay
    // is intentional: at logon the dds-node service may still be coming up
    // and the user is likely focused on something else — we wait until the
    // session has settled before showing the balloon.
    g_nudgeTimerId = SetTimer(g_hWnd, NUDGE_TIMER_ID, 30 * 1000, NULL);

    FileLog::Write("DdsTrayAgent: tray icon added, entering message loop\n");

    // Message loop
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    FileLog::Write("DdsTrayAgent: exiting\n");

    if (hMutex) CloseHandle(hMutex);
    return (int)msg.wParam;
}
