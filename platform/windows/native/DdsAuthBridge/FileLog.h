// FileLog.h
// Tiny thread-safe file logger writing to %ProgramData%\DDS\authbridge.log.
// Used by the DDS Auth Bridge Service so that issues can be diagnosed when
// the service is running unattended (no DebugView, no console).
//
// Usage:
//     FileLog::Init();   // call once on service start
//     FileLog::Write("HttpClient: started\n");
//     FileLog::Writef("HttpClient: got %d users\n", n);
//
// Every line is prefixed with a millisecond timestamp.

#pragma once
#include <windows.h>

namespace FileLog
{
    // Initialise the logger. Creates %ProgramData%\DDS\ if needed.
    // Safe to call multiple times.
    void Init();

    // Append a raw narrow string. Adds a timestamp prefix; does NOT add a
    // newline (caller is expected to include one).
    void Write(const char* msg);

    // printf-style. Same conventions as Write().
    void Writef(const char* fmt, ...);

    // Path to the active log file (for inclusion in error messages).
    const wchar_t* Path();
}
