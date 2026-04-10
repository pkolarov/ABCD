// EventLogger.cpp
// Windows Application Event Log wrapper implementation for DDS Auth Bridge.
//

#include "EventLogger.h"

void CEventLogger::LogInfo(_In_ DWORD eventId, _In_ PCWSTR pszMessage)
{
    LogEvent(EVENTLOG_INFORMATION_TYPE, eventId, pszMessage);
}

void CEventLogger::LogWarning(_In_ DWORD eventId, _In_ PCWSTR pszMessage)
{
    LogEvent(EVENTLOG_WARNING_TYPE, eventId, pszMessage);
}

void CEventLogger::LogError(_In_ DWORD eventId, _In_ PCWSTR pszMessage)
{
    LogEvent(EVENTLOG_ERROR_TYPE, eventId, pszMessage);
}

void CEventLogger::LogEvent(_In_ WORD wType, _In_ DWORD eventId, _In_ PCWSTR pszMessage)
{
    HANDLE hEventLog = ::RegisterEventSourceW(NULL, EVENT_SOURCE);
    if (hEventLog == NULL)
    {
        // Fall back to OutputDebugString
        OutputDebugStringW(pszMessage);
        return;
    }

    const wchar_t* pStrings[1] = { pszMessage };

    ReportEventW(
        hEventLog,
        wType,
        0,          // Category
        eventId,
        NULL,       // User SID
        1,          // Number of strings
        0,          // Data size
        pStrings,
        NULL        // Raw data
    );

    DeregisterEventSource(hEventLog);
}

void CEventLogger::RegisterEventSource(_In_ PCWSTR pszExePath)
{
    // Write registry key for Event Log source so messages appear in Event Viewer
    const wchar_t* kRegPath =
        L"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\DdsAuthBridge";

    HKEY hKey = nullptr;
    DWORD disposition = 0;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegPath, 0, nullptr,
                         REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                         nullptr, &hKey, &disposition) != ERROR_SUCCESS)
        return;

    RegSetValueExW(hKey, L"EventMessageFile", 0, REG_SZ,
                   (const BYTE*)pszExePath,
                   (DWORD)((wcslen(pszExePath) + 1) * sizeof(wchar_t)));

    DWORD types = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
    RegSetValueExW(hKey, L"TypesSupported", 0, REG_DWORD,
                   (const BYTE*)&types, sizeof(DWORD));

    RegCloseKey(hKey);
}
