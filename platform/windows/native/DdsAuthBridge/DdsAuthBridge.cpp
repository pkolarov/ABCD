// DdsAuthBridge.cpp
// Windows Service entry point for the DDS Auth Bridge.
//
// Forked from CrayonicBridgeService.cpp with service name/description
// updated and BLE references removed.
//
// CLI flags:
//   (none)           Run as Windows service (registered via SCM)
//   --console / -c   Run interactively in a console (debug)
//   --install        Register as an auto-start Windows service
//   --uninstall      Remove the service registration
//   --start          Start the service via SCM
//   --stop           Stop the service via SCM
//

#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include "DdsAuthBridgeMain.h"
#include "EventLogger.h"

#define SERVICE_NAME         _T("DdsAuthBridge")
#define SERVICE_DISPLAY_NAME _T("DDS Auth Bridge Service")
#define SERVICE_DESCRIPTION  _T("Bridges FIDO2 authentication between the DDS Credential Provider and dds-node, providing passwordless Windows logon.")

// ============================================================================
// Service management helpers
// ============================================================================

static bool ServiceInstall()
{
    wchar_t exePath[MAX_PATH]{};
    if (!GetModuleFileNameW(nullptr, exePath, MAX_PATH))
    {
        _tprintf(_T("GetModuleFileName failed: %lu\n"), GetLastError());
        return false;
    }

    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hScm) { _tprintf(_T("OpenSCManager failed: %lu\n"), GetLastError()); return false; }

    SC_HANDLE hSvc = CreateServiceW(
        hScm, SERVICE_NAME, SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,          // start at boot
        SERVICE_ERROR_NORMAL,
        exePath,
        nullptr, nullptr, nullptr,
        nullptr, nullptr);           // run as LocalSystem

    if (!hSvc && GetLastError() == ERROR_SERVICE_EXISTS)
    {
        _tprintf(_T("Service already installed.\n"));
        CloseServiceHandle(hScm);
        return true;
    }

    if (!hSvc)
    {
        _tprintf(_T("CreateService failed: %lu\n"), GetLastError());
        CloseServiceHandle(hScm);
        return false;
    }

    // Set description
    SERVICE_DESCRIPTIONW desc{ (LPWSTR)SERVICE_DESCRIPTION };
    ChangeServiceConfig2W(hSvc, SERVICE_CONFIG_DESCRIPTION, &desc);

    // Register EventLog source
    CEventLogger::RegisterEventSource(exePath);

    _tprintf(_T("Service installed: %s\n"), SERVICE_NAME);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return true;
}

static bool ServiceUninstall()
{
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) { _tprintf(_T("OpenSCManager failed: %lu\n"), GetLastError()); return false; }

    SC_HANDLE hSvc = OpenServiceW(hScm, SERVICE_NAME, SERVICE_STOP | DELETE);
    if (!hSvc)
    {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
            _tprintf(_T("Service not installed.\n"));
        else
            _tprintf(_T("OpenService failed: %lu\n"), GetLastError());
        CloseServiceHandle(hScm);
        return false;
    }

    // Stop it first if running
    SERVICE_STATUS ss{};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);

    if (!DeleteService(hSvc))
        _tprintf(_T("DeleteService failed: %lu\n"), GetLastError());
    else
        _tprintf(_T("Service uninstalled: %s\n"), SERVICE_NAME);

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hScm);
    return true;
}

static bool ServiceStart()
{
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) { _tprintf(_T("OpenSCManager failed: %lu\n"), GetLastError()); return false; }

    SC_HANDLE hSvc = OpenServiceW(hScm, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!hSvc) { _tprintf(_T("OpenService failed: %lu\n"), GetLastError()); CloseServiceHandle(hScm); return false; }

    if (!StartServiceW(hSvc, 0, nullptr))
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) _tprintf(_T("Service already running.\n"));
        else _tprintf(_T("StartService failed: %lu\n"), err);
        CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
        return err == ERROR_SERVICE_ALREADY_RUNNING;
    }

    // Wait up to 10 s for SERVICE_RUNNING
    SERVICE_STATUS_PROCESS ssp{};
    DWORD needed = 0;
    for (int i = 0; i < 20; i++)
    {
        Sleep(500);
        if (!QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                                   (LPBYTE)&ssp, sizeof(ssp), &needed)) break;
        if (ssp.dwCurrentState == SERVICE_RUNNING) break;
    }
    _tprintf(_T("Service state: %lu\n"), ssp.dwCurrentState);

    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return ssp.dwCurrentState == SERVICE_RUNNING;
}

static bool ServiceStop()
{
    SC_HANDLE hScm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hScm) { _tprintf(_T("OpenSCManager failed: %lu\n"), GetLastError()); return false; }

    SC_HANDLE hSvc = OpenServiceW(hScm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) { _tprintf(_T("OpenService failed: %lu\n"), GetLastError()); CloseServiceHandle(hScm); return false; }

    SERVICE_STATUS ss{};
    if (!ControlService(hSvc, SERVICE_CONTROL_STOP, &ss))
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_NOT_ACTIVE) _tprintf(_T("Service not running.\n"));
        else _tprintf(_T("ControlService(STOP) failed: %lu\n"), err);
    }
    else
    {
        _tprintf(_T("Stop signal sent. Service state: %lu\n"), ss.dwCurrentState);
    }

    CloseServiceHandle(hSvc); CloseServiceHandle(hScm);
    return true;
}

// Global service state
SERVICE_STATUS        g_ServiceStatus = {};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

// The main bridge service instance
static CDdsAuthBridgeMain* g_pBridgeService = nullptr;

// Forward declarations
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

// ============================================================================
// Service Entry Point
// ============================================================================

int _tmain(int argc, TCHAR* argv[])
{
    OutputDebugString(_T("DdsAuthBridge: Main: Entry"));

    // CLI flag dispatch
    if (argc > 1 && (_tcscmp(argv[1], _T("--install"))   == 0)) return ServiceInstall()   ? 0 : 1;
    if (argc > 1 && (_tcscmp(argv[1], _T("--uninstall")) == 0)) return ServiceUninstall() ? 0 : 1;
    if (argc > 1 && (_tcscmp(argv[1], _T("--start"))     == 0)) return ServiceStart()     ? 0 : 1;
    if (argc > 1 && (_tcscmp(argv[1], _T("--stop"))      == 0)) return ServiceStop()      ? 0 : 1;

    // Check for --console flag for development/debugging
    if (argc > 1 && (_tcscmp(argv[1], _T("--console")) == 0 || _tcscmp(argv[1], _T("-c")) == 0))
    {
        OutputDebugString(_T("DdsAuthBridge: Running in console mode"));

        // Run as a console application for debugging
        g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (g_ServiceStopEvent == NULL)
        {
            return GetLastError();
        }

        g_pBridgeService = new (std::nothrow) CDdsAuthBridgeMain();
        if (g_pBridgeService == nullptr)
        {
            CloseHandle(g_ServiceStopEvent);
            return ERROR_OUTOFMEMORY;
        }

        if (!g_pBridgeService->Initialize(g_ServiceStopEvent))
        {
            _tprintf(_T("Failed to initialize DDS Auth Bridge.\n"));
            delete g_pBridgeService;
            CloseHandle(g_ServiceStopEvent);
            return 1;
        }

        if (!g_pBridgeService->Start())
        {
            _tprintf(_T("Failed to start DDS Auth Bridge.\n"));
            g_pBridgeService->Shutdown();
            delete g_pBridgeService;
            CloseHandle(g_ServiceStopEvent);
            return 1;
        }

        _tprintf(_T("DdsAuthBridge running in console mode. Press Ctrl+C to stop.\n"));

        // Install Ctrl+C handler that signals the stop event
        SetConsoleCtrlHandler([](DWORD ctrlType) -> BOOL {
            if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_BREAK_EVENT ||
                ctrlType == CTRL_CLOSE_EVENT)
            {
                if (g_ServiceStopEvent != INVALID_HANDLE_VALUE)
                    SetEvent(g_ServiceStopEvent);
                return TRUE;
            }
            return FALSE;
        }, TRUE);

        // Wait only on the stop event (NOT stdin -- stdin is unreliable when
        // the process is launched non-interactively from a script)
        WaitForSingleObject(g_ServiceStopEvent, INFINITE);

        _tprintf(_T("Shutting down...\n"));
        g_pBridgeService->Shutdown();
        delete g_pBridgeService;
        g_pBridgeService = nullptr;
        CloseHandle(g_ServiceStopEvent);

        return 0;
    }

    // Normal service dispatch
    SERVICE_TABLE_ENTRY ServiceTable[] =
    {
        { (LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE)
    {
        OutputDebugString(_T("DdsAuthBridge: Main: StartServiceCtrlDispatcher returned error"));
        return GetLastError();
    }

    OutputDebugString(_T("DdsAuthBridge: Main: Exit"));
    return 0;
}

// ============================================================================
// ServiceMain
// ============================================================================

VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    OutputDebugString(_T("DdsAuthBridge: ServiceMain: Entry"));

    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (g_StatusHandle == NULL)
    {
        OutputDebugString(_T("DdsAuthBridge: ServiceMain: RegisterServiceCtrlHandler failed"));
        return;
    }

    // Report SERVICE_START_PENDING
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Create stop event
    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL)
    {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    // Initialize the bridge service
    g_pBridgeService = new (std::nothrow) CDdsAuthBridgeMain();
    if (g_pBridgeService == nullptr || !g_pBridgeService->Initialize(g_ServiceStopEvent))
    {
        CEventLogger::LogError(4001, L"DdsAuthBridge: Failed to initialize");
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        g_ServiceStatus.dwServiceSpecificExitCode = 1;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        if (g_pBridgeService) { delete g_pBridgeService; g_pBridgeService = nullptr; }
        CloseHandle(g_ServiceStopEvent);
        return;
    }

    // Start the bridge service
    if (!g_pBridgeService->Start())
    {
        CEventLogger::LogError(4001, L"DdsAuthBridge: Failed to start");
        g_pBridgeService->Shutdown();
        delete g_pBridgeService;
        g_pBridgeService = nullptr;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        CloseHandle(g_ServiceStopEvent);
        return;
    }

    // Report SERVICE_RUNNING
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    CEventLogger::LogInfo(1000, L"DdsAuthBridge service started");

    // Start the worker thread
    HANDLE hWorker = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    if (hWorker != NULL)
    {
        WaitForSingleObject(hWorker, INFINITE);
        CloseHandle(hWorker);
    }

    // Shutdown
    OutputDebugString(_T("DdsAuthBridge: ServiceMain: Shutting down"));

    g_pBridgeService->Shutdown();
    delete g_pBridgeService;
    g_pBridgeService = nullptr;

    CloseHandle(g_ServiceStopEvent);

    CEventLogger::LogInfo(1001, L"DdsAuthBridge service stopped");

    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    OutputDebugString(_T("DdsAuthBridge: ServiceMain: Exit"));
}

// ============================================================================
// ServiceCtrlHandler
// ============================================================================

VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    switch (ctrlCode)
    {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        OutputDebugString(_T("DdsAuthBridge: ServiceCtrlHandler: STOP/SHUTDOWN requested"));

        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwCheckPoint = 1;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

        SetEvent(g_ServiceStopEvent);
        break;

    default:
        break;
    }
}

// ============================================================================
// ServiceWorkerThread
// ============================================================================

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
    OutputDebugString(_T("DdsAuthBridge: WorkerThread: Entry"));

    // Wait for stop event -- all actual work is done by the bridge service components
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    OutputDebugString(_T("DdsAuthBridge: WorkerThread: Exit"));
    return 0;
}
