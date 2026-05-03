// DdsTrayAgent.cpp
// System tray application for DDS FIDO2 enrollment and admin approval.
//
// Runs as a hidden window with a Shell_NotifyIconW tray icon.
// Context menu provides: Enroll FIDO2 Key, Admin Setup, Approve Enrollments, Exit.

#include "resource.h"
#include "EnrollmentFlow.h"
#include "AdminFlow.h"
#include "RefreshVaultFlow.h"
#include "DdsNodeHttpClient.h"
#include "Configuration.h"
#include "FileLog.h"

#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>

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
    wcscpy_s(g_nid.szTip, L"DDS Enrollment Agent");
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

    wchar_t msg[512];
    if (result.success)
    {
        swprintf_s(msg,
            L"DDS Tray Agent\n\n"
            L"Node connection: OK\n"
            L"Enrolled users: %zu\n"
            L"Port: %lu\n"
            L"RP ID: %hs",
            result.users.size(),
            (unsigned long)config.DdsNodePort(),
            config.RpId().c_str());
    }
    else
    {
        swprintf_s(msg,
            L"DDS Tray Agent\n\n"
            L"Node connection: FAILED\n"
            L"Error: %hs\n"
            L"Port: %lu",
            result.errorMessage.c_str(),
            (unsigned long)config.DdsNodePort());
    }

    MessageBoxW(hwnd, msg, L"DDS Status", MB_OK | MB_ICONINFORMATION);
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
        case IDM_EXIT:
            RemoveTrayIcon();
            PostQuitMessage(0);
            break;
        }
        return 0;

    case WM_DESTROY:
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
