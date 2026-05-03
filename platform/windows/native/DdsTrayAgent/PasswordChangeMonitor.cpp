// PasswordChangeMonitor.cpp — see header for design overview.

#include "PasswordChangeMonitor.h"
#include "RefreshVaultFlow.h"
#include "CredentialVault.h"
#include "FileLog.h"

#include <windows.h>
#include <wtsapi32.h>
#include <lm.h>          // NetUserGetInfo, USER_INFO_11
#include <sddl.h>        // ConvertSidToStringSidW
#include <shlobj.h>      // SHGetFolderPathW, CSIDL_LOCAL_APPDATA
#include <dsgetdc.h>     // DsGetDcNameW
#include <string>
#include <vector>
#include <ctime>
#include <cstdio>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "netapi32.lib")

namespace
{
    constexpr UINT_PTR kPollTimerId  = 0xDD51;
    constexpr UINT     kPollInterval = 60 * 1000;   // 60s
    // Tolerance for clock drift between successive NetUserGetInfo calls.
    // password_age is whole seconds and the read isn't atomic with our
    // clock; require a >300s jump to count as a real password change.
    constexpr time_t   kChangeThresholdSeconds = 300;

    bool g_wtsRegistered = false;
    bool g_promptInFlight = false;   // suppress overlapping prompts

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    bool GetCurrentUsername(std::wstring& out)
    {
        wchar_t name[256];
        DWORD len = ARRAYSIZE(name);
        if (!GetUserNameW(name, &len)) return false;
        out = name;
        return true;
    }

    bool GetCurrentUserSid(std::wstring& outSid)
    {
        HANDLE hToken = NULL;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return false;
        DWORD len = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &len);
        std::vector<BYTE> buf(len);
        BOOL ok = GetTokenInformation(hToken, TokenUser, buf.data(), len, &len);
        CloseHandle(hToken);
        if (!ok) return false;
        TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
        LPWSTR sidStr = NULL;
        if (!ConvertSidToStringSidW(tu->User.Sid, &sidStr)) return false;
        outSid = sidStr;
        LocalFree(sidStr);
        return true;
    }

    // Resolve the server name to pass to NetUserGetInfo. For domain users
    // we need a DC name; NULL works for SAM-local accounts.
    std::wstring ResolveServer()
    {
        PDOMAIN_CONTROLLER_INFOW dcInfo = NULL;
        DWORD r = DsGetDcNameW(NULL, NULL, NULL, NULL,
                               DS_RETURN_DNS_NAME | DS_DIRECTORY_SERVICE_PREFERRED,
                               &dcInfo);
        if (r == NO_ERROR && dcInfo && dcInfo->DomainControllerName)
        {
            std::wstring s = dcInfo->DomainControllerName; // "\\dc.example.com"
            NetApiBufferFree(dcInfo);
            return s;
        }
        if (dcInfo) NetApiBufferFree(dcInfo);
        return L"";  // local SAM
    }

    // Returns 0 on failure. Otherwise the absolute "password set time"
    // as seconds-since-epoch (now - password_age).
    time_t QueryPasswordSetTime()
    {
        std::wstring user;
        if (!GetCurrentUsername(user)) return 0;

        std::wstring server = ResolveServer();
        const wchar_t* serverArg = server.empty() ? NULL : server.c_str();

        LPUSER_INFO_11 info = NULL;
        NET_API_STATUS s = NetUserGetInfo(serverArg, user.c_str(), 11,
                                          reinterpret_cast<LPBYTE*>(&info));
        if (s != NERR_Success || info == NULL)
        {
            // Fall back to local SAM if the DC query failed.
            if (serverArg != NULL)
            {
                s = NetUserGetInfo(NULL, user.c_str(), 11,
                                   reinterpret_cast<LPBYTE*>(&info));
            }
            if (s != NERR_Success || info == NULL)
            {
                FileLog::Writef("PasswordChangeMonitor: NetUserGetInfo failed (%lu)\n",
                                (unsigned long)s);
                return 0;
            }
        }

        DWORD ageSec = info->usri11_password_age;
        NetApiBufferFree(info);

        time_t now = time(NULL);
        return now - static_cast<time_t>(ageSec);
    }

    // -------------------------------------------------------------------
    // Persisted "last seen set_time" — per-user state file
    // -------------------------------------------------------------------

    bool StatePath(std::wstring& outPath)
    {
        wchar_t base[MAX_PATH];
        if (FAILED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base)))
            return false;
        std::wstring dir = std::wstring(base) + L"\\DDS";
        CreateDirectoryW(dir.c_str(), NULL);  // OK if exists
        outPath = dir + L"\\pwd_state.txt";
        return true;
    }

    time_t LoadStoredSetTime()
    {
        std::wstring path;
        if (!StatePath(path)) return 0;
        FILE* f = NULL;
        if (_wfopen_s(&f, path.c_str(), L"r") != 0 || !f) return 0;
        long long v = 0;
        int n = fscanf_s(f, "%lld", &v);
        fclose(f);
        return (n == 1) ? static_cast<time_t>(v) : 0;
    }

    void StoreSetTime(time_t t)
    {
        std::wstring path;
        if (!StatePath(path)) return;
        FILE* f = NULL;
        if (_wfopen_s(&f, path.c_str(), L"w") != 0 || !f) return;
        fprintf(f, "%lld\n", static_cast<long long>(t));
        fclose(f);
    }

    // -------------------------------------------------------------------
    // Vault gate: only prompt users who have a DDS enrollment.
    // -------------------------------------------------------------------

    bool UserHasVaultEntry()
    {
        std::wstring sid;
        if (!GetCurrentUserSid(sid)) return false;
        CCredentialVault vault;
        if (!vault.Load()) return false;
        return !vault.FindByUserSid(sid).empty();
    }

    // -------------------------------------------------------------------
    // The detection step: query, compare, prompt if changed.
    // -------------------------------------------------------------------

    void CheckOnce(HWND hwnd, const char* trigger)
    {
        if (g_promptInFlight) return;

        time_t current = QueryPasswordSetTime();
        if (current == 0) return;  // query failure already logged

        time_t stored = LoadStoredSetTime();
        if (stored == 0)
        {
            // First run for this user: seed baseline, do not prompt.
            StoreSetTime(current);
            FileLog::Writef("PasswordChangeMonitor: baseline set_time=%lld (%s)\n",
                            (long long)current, trigger);
            return;
        }

        if (current <= stored + kChangeThresholdSeconds)
            return;  // no meaningful change

        FileLog::Writef("PasswordChangeMonitor: password change detected "
                        "(stored=%lld, current=%lld, %s)\n",
                        (long long)stored, (long long)current, trigger);

        if (!UserHasVaultEntry())
        {
            // No DDS enrollment for this user — nothing to refresh.
            // Update the baseline so we don't keep re-detecting.
            StoreSetTime(current);
            return;
        }

        g_promptInFlight = true;
        int reply = MessageBoxW(hwnd,
            L"Your Windows password appears to have changed.\n\n"
            L"Update the DDS stored credential now? You will be asked for the new "
            L"password and to touch your security key.",
            L"DDS — Password Change Detected",
            MB_YESNO | MB_ICONQUESTION);

        if (reply == IDYES)
        {
            bool ok = RunRefreshVaultFlow(hwnd);
            if (ok)
            {
                StoreSetTime(current);
            }
            // On failure: leave stored value alone so we'll re-prompt later
            // (e.g. on next unlock). RefreshVaultFlow already showed an error.
        }
        else
        {
            // User declined: record the new baseline so we don't nag.
            // They can still trigger Refresh manually from the tray menu.
            StoreSetTime(current);
        }
        g_promptInFlight = false;
    }
}

// ===========================================================================
// Public API
// ===========================================================================

void PasswordChangeMonitor::Start(HWND hwnd)
{
    if (!WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION))
    {
        FileLog::Writef("PasswordChangeMonitor: WTSRegisterSessionNotification "
                        "failed (%lu)\n", (unsigned long)GetLastError());
    }
    else
    {
        g_wtsRegistered = true;
    }

    SetTimer(hwnd, kPollTimerId, kPollInterval, NULL);

    // Run an initial check shortly after startup so that a password change
    // that happened while the tray wasn't running is still caught.
    CheckOnce(hwnd, "startup");
}

void PasswordChangeMonitor::Stop(HWND hwnd)
{
    KillTimer(hwnd, kPollTimerId);
    if (g_wtsRegistered)
    {
        WTSUnRegisterSessionNotification(hwnd);
        g_wtsRegistered = false;
    }
}

bool PasswordChangeMonitor::HandleSessionChange(HWND hwnd, WPARAM wParam, LPARAM /*lParam*/)
{
    // Re-check on the events that bracket a likely password change:
    // logon (new session), unlock (user back at console after Ctrl+Alt+Del).
    if (wParam == WTS_SESSION_LOGON || wParam == WTS_SESSION_UNLOCK)
    {
        CheckOnce(hwnd, wParam == WTS_SESSION_LOGON ? "logon" : "unlock");
    }
    return true;
}

bool PasswordChangeMonitor::HandleTimer(HWND hwnd, WPARAM wParam)
{
    if (wParam != kPollTimerId) return false;
    CheckOnce(hwnd, "poll");
    return true;
}
