// PasswordChangeMonitor.h
// Detects Windows/AD password changes for the current user and prompts
// the user to refresh the DDS vault (RefreshVaultFlow).
//
// Two triggers:
//   1. WTS session events (logon, unlock) — fired by Windows
//   2. SetTimer poll on a 60s cadence — catches changes that happen
//      while the session is already unlocked
//
// Detection: NetUserGetInfo level 11 returns password_age (seconds since
// the password was last set). We compute set_time = now - password_age
// and persist it to %LOCALAPPDATA%\DDS\pwd_state.txt. When a later query
// returns a set_time that is meaningfully larger than the stored value,
// the password has been changed and we prompt the user.

#pragma once

#include <windows.h>

namespace PasswordChangeMonitor
{
    // Register WTS session notifications and start the poll timer.
    // Safe to call once after the tray window is created.
    void Start(HWND hwnd);

    // Unregister and stop. Call from WM_DESTROY.
    void Stop(HWND hwnd);

    // Forwarded from the tray's WndProc.
    // Returns true if the message was handled.
    bool HandleSessionChange(HWND hwnd, WPARAM wParam, LPARAM lParam);
    bool HandleTimer(HWND hwnd, WPARAM wParam);
}
