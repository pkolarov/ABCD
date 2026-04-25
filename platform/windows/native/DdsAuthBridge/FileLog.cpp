// FileLog.cpp — see FileLog.h.

#include "FileLog.h"
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#pragma comment(lib, "advapi32.lib")

namespace
{
    CRITICAL_SECTION g_cs;
    BOOL             g_initialised  = FALSE;
    wchar_t          g_path[MAX_PATH] = L"";

    // A-4 (security review): %ProgramData%\DDS inherits BUILTIN\Users:Read
    // on most Windows SKUs. Set an explicit, non-inherited DACL granting
    // FullControl only to LocalSystem and the local Administrators group.
    // Mirrors the L-16 helper in DdsPolicyAgent's AppliedStateStore. SDDL:
    //   PAI  -> SDDL_PROTECTED + SDDL_AUTO_INHERITED
    //   OICI -> object inherit + container inherit (apply to children)
    //   FA   -> file all access (== full control)
    //   SY   -> LocalSystem
    //   BA   -> BUILTIN\Administrators
    void ApplyRestrictedDacl(const wchar_t* path)
    {
        if (path == nullptr || path[0] == L'\0') return;
        const wchar_t* sddl =
            L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        PSECURITY_DESCRIPTOR pSD = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SDDL_REVISION_1, &pSD, nullptr))
            return;

        BOOL daclPresent = FALSE, daclDefaulted = FALSE;
        PACL pDacl = nullptr;
        if (GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted) &&
            daclPresent)
        {
            SetNamedSecurityInfoW(
                const_cast<LPWSTR>(path),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                nullptr, nullptr, pDacl, nullptr);
        }
        LocalFree(pSD);
    }
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

    // A-4 (security review): tighten DACL on the log directory before
    // anything else writes inside it. Inheritance is enabled (OICI) so
    // authbridge.log and any sibling diagnostics created later pick up
    // the same restriction without a per-file pass. Best-effort: a stale
    // pre-existing wide-open ACL on `%ProgramData%\DDS` from an earlier
    // build is corrected here on first start of the new bits.
    ApplyRestrictedDacl(dir);

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
