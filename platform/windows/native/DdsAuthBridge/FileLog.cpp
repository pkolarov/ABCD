// FileLog.cpp — see FileLog.h.

#include "FileLog.h"
#include <shlobj.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

namespace
{
    CRITICAL_SECTION g_cs;
    BOOL             g_initialised  = FALSE;
    wchar_t          g_path[MAX_PATH] = L"";
}

namespace FileLog
{

void Init()
{
    if (g_initialised) return;

    InitializeCriticalSection(&g_cs);
    g_initialised = TRUE;

    // Resolve %ProgramData%\DDS\authbridge.log
    wchar_t programData[MAX_PATH] = {0};
    if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programData) != S_OK)
    {
        wcscpy_s(programData, L"C:\\ProgramData");
    }

    wchar_t dir[MAX_PATH];
    swprintf_s(dir, L"%s\\DDS", programData);
    CreateDirectoryW(dir, NULL);

    swprintf_s(g_path, L"%s\\authbridge.log", dir);

    // Truncate-and-rotate: if the file is bigger than ~2 MB, rename it
    // to authbridge.log.old before opening, so logs don't grow unbounded.
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (GetFileAttributesExW(g_path, GetFileExInfoStandard, &fad))
    {
        ULONGLONG size = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        if (size > 2 * 1024 * 1024)
        {
            wchar_t oldPath[MAX_PATH];
            swprintf_s(oldPath, L"%s.old", g_path);
            DeleteFileW(oldPath);
            MoveFileW(g_path, oldPath);
        }
    }

    Write("==== authbridge.log opened ====\n");
}

const wchar_t* Path() { return g_path; }

void Write(const char* msg)
{
    if (!g_initialised || g_path[0] == L'\0' || msg == nullptr) return;

    SYSTEMTIME st{};
    GetLocalTime(&st);

    EnterCriticalSection(&g_cs);
    FILE* f = nullptr;
    if (_wfopen_s(&f, g_path, L"ab") == 0 && f)
    {
        fprintf(f, "[%04u-%02u-%02u %02u:%02u:%02u.%03u PID=%lu] %s",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                GetCurrentProcessId(), msg);
        fclose(f);
    }
    LeaveCriticalSection(&g_cs);

    // Mirror to debugger so existing OutputDebugString readers still work.
    OutputDebugStringA(msg);
}

void Writef(const char* fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    Write(buf);
}

} // namespace FileLog
