// EventLogger.h
// Windows Application Event Log wrapper for the DDS Auth Bridge Service.
//

#pragma once

#include <windows.h>

// Event ID definitions
namespace EVENT_ID
{
    constexpr DWORD SVC_STARTED             = 1000;
    constexpr DWORD SVC_STOPPED             = 1001;
    constexpr DWORD AUTH_SUCCEEDED          = 3000;
    constexpr DWORD AUTH_FAILED             = 3001;
    constexpr DWORD AUTH_TIMEOUT            = 3002;
    constexpr DWORD DDS_NODE_UNREACHABLE    = 4000;
    constexpr DWORD SERVICE_START_FAILED    = 4001;
    constexpr DWORD USER_ENROLLED           = 5000;
    constexpr DWORD USER_UNENROLLED         = 5001;
}

class CEventLogger
{
public:
    static void LogInfo(_In_ DWORD eventId, _In_ PCWSTR pszMessage);
    static void LogWarning(_In_ DWORD eventId, _In_ PCWSTR pszMessage);
    static void LogError(_In_ DWORD eventId, _In_ PCWSTR pszMessage);

    // Register this EXE as an Event Log source (called during --install).
    static void RegisterEventSource(_In_ PCWSTR pszExePath);

private:
    static void LogEvent(_In_ WORD wType, _In_ DWORD eventId, _In_ PCWSTR pszMessage);
    static constexpr const wchar_t* EVENT_SOURCE = L"DdsAuthBridge";
};
