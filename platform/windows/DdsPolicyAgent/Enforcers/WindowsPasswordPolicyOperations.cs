// SPDX-License-Identifier: MIT OR Apache-2.0

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Production implementation of <see cref="IPasswordPolicyOperations"/>
/// using <c>NetUserModalsGet</c> / <c>NetUserModalsSet</c> from
/// netapi32.dll. Atomic read/modify/write with no temp files.
///
/// Level 0 = password parameters (min length, max/min age, history).
/// Level 3 = lockout parameters (threshold, duration, observation window).
///
/// Complexity is not available via NetUserModals — it requires
/// <c>secedit</c> export/import. We shell out for that single knob.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPasswordPolicyOperations : IPasswordPolicyOperations
{
    public PasswordPolicyState GetCurrent()
    {
        var info0 = GetModalsLevel0();
        var info3 = GetModalsLevel3();
        var complexity = ReadComplexityViaSecedit();

        return new PasswordPolicyState(
            MinLength: info0.usrmod0_min_passwd_len,
            MaxAgeDays: SecondsTodays(info0.usrmod0_max_passwd_age),
            MinAgeDays: SecondsTodays(info0.usrmod0_min_passwd_age),
            HistorySize: info0.usrmod0_password_hist_len,
            ComplexityRequired: complexity,
            LockoutThreshold: info3.usrmod3_lockout_threshold,
            LockoutDurationMinutes: SecondsToMinutes(info3.usrmod3_lockout_duration));
    }

    public void SetMinLength(uint value)
    {
        var info = GetModalsLevel0();
        info.usrmod0_min_passwd_len = value;
        SetModalsLevel0(info);
    }

    public void SetMaxAgeDays(uint value)
    {
        var info = GetModalsLevel0();
        info.usrmod0_max_passwd_age = DaysToSeconds(value);
        SetModalsLevel0(info);
    }

    public void SetMinAgeDays(uint value)
    {
        var info = GetModalsLevel0();
        info.usrmod0_min_passwd_age = DaysToSeconds(value);
        SetModalsLevel0(info);
    }

    public void SetHistorySize(uint value)
    {
        var info = GetModalsLevel0();
        info.usrmod0_password_hist_len = value;
        SetModalsLevel0(info);
    }

    public void SetComplexityRequired(bool value)
    {
        WriteComplexityViaSecedit(value);
    }

    public void SetLockoutThreshold(uint value)
    {
        var info = GetModalsLevel3();
        info.usrmod3_lockout_threshold = value;
        SetModalsLevel3(info);
    }

    public void SetLockoutDurationMinutes(uint value)
    {
        var info = GetModalsLevel3();
        info.usrmod3_lockout_duration = MinutesToSeconds(value);
        SetModalsLevel3(info);
    }

    // ----------------------------------------------------------------
    // Read/write helpers for level 0 and level 3
    // ----------------------------------------------------------------

    private static USER_MODALS_INFO_0 GetModalsLevel0()
    {
        int r = NetUserModalsGet(null, 0, out var buf);
        if (r != 0) throw new Win32Exception(r, "NetUserModalsGet level 0 failed");
        try { return Marshal.PtrToStructure<USER_MODALS_INFO_0>(buf); }
        finally { NetApiBufferFree(buf); }
    }

    private static void SetModalsLevel0(USER_MODALS_INFO_0 info)
    {
        int size = Marshal.SizeOf<USER_MODALS_INFO_0>();
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, buf, false);
            int r = NetUserModalsSet(null, 0, buf, out var parmErr);
            if (r != 0)
                throw new Win32Exception(r, $"NetUserModalsSet level 0 failed (parm_err={parmErr})");
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    private static USER_MODALS_INFO_3 GetModalsLevel3()
    {
        int r = NetUserModalsGet(null, 3, out var buf);
        if (r != 0) throw new Win32Exception(r, "NetUserModalsGet level 3 failed");
        try { return Marshal.PtrToStructure<USER_MODALS_INFO_3>(buf); }
        finally { NetApiBufferFree(buf); }
    }

    private static void SetModalsLevel3(USER_MODALS_INFO_3 info)
    {
        int size = Marshal.SizeOf<USER_MODALS_INFO_3>();
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(info, buf, false);
            int r = NetUserModalsSet(null, 3, buf, out var parmErr);
            if (r != 0)
                throw new Win32Exception(r, $"NetUserModalsSet level 3 failed (parm_err={parmErr})");
        }
        finally { Marshal.FreeHGlobal(buf); }
    }

    // ----------------------------------------------------------------
    // secedit helpers for PasswordComplexity
    // ----------------------------------------------------------------

    private static bool? ReadComplexityViaSecedit()
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), "dds-secedit-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tmpDir);
        var cfgPath = Path.Combine(tmpDir, "secpol.inf");

        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "secedit.exe",
                Arguments = $"/export /cfg \"{cfgPath}\" /areas SECURITYPOLICY",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            var stdoutTask = proc!.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            bool exited = proc.WaitForExit(10_000);
            if (!exited)
            {
                try { proc.Kill(); } catch { /* best-effort */ }
                Task.WhenAll(stdoutTask, stderrTask).GetAwaiter().GetResult();
                return null;
            }
            Task.WhenAll(stdoutTask, stderrTask).GetAwaiter().GetResult();
            if (proc.ExitCode != 0) return null;

            foreach (var line in File.ReadAllLines(cfgPath))
            {
                var trimmed = line.Trim();
                if (trimmed.StartsWith("PasswordComplexity", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = trimmed.Split('=', 2);
                    if (parts.Length == 2 && int.TryParse(parts[1].Trim(), out var val))
                        return val != 0;
                }
            }
            return null;
        }
        catch
        {
            return null;
        }
        finally
        {
            try { Directory.Delete(tmpDir, recursive: true); } catch { }
        }
    }

    private static void WriteComplexityViaSecedit(bool enable)
    {
        var tmpDir = Path.Combine(Path.GetTempPath(), "dds-secedit-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(tmpDir);
        var cfgPath = Path.Combine(tmpDir, "secpol.inf");
        var dbPath = Path.Combine(tmpDir, "secpol.sdb");

        try
        {
            var inf = $"""
                [Unicode]
                Unicode=yes
                [System Access]
                PasswordComplexity = {(enable ? 1 : 0)}
                [Version]
                signature="$CHICAGO$"
                Revision=1
                """;
            File.WriteAllText(cfgPath, inf);

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "secedit.exe",
                Arguments = $"/configure /db \"{dbPath}\" /cfg \"{cfgPath}\" /areas SECURITYPOLICY",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            var stdoutTask = proc!.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            bool exited = proc.WaitForExit(30_000);
            if (!exited)
            {
                try { proc.Kill(); } catch { /* best-effort */ }
                Task.WhenAll(stdoutTask, stderrTask).GetAwaiter().GetResult();
                throw new InvalidOperationException("secedit /configure timed out after 30 s");
            }
            Task.WhenAll(stdoutTask, stderrTask).GetAwaiter().GetResult();
            if (proc.ExitCode != 0)
                throw new InvalidOperationException(
                    $"secedit /configure failed (exit {proc.ExitCode}): {stderrTask.Result}");
        }
        finally
        {
            try { Directory.Delete(tmpDir, recursive: true); } catch { }
        }
    }

    // ----------------------------------------------------------------
    // Unit conversion
    // ----------------------------------------------------------------

    private static uint SecondsTodays(uint seconds) =>
        seconds == uint.MaxValue ? 0 : seconds / 86400;

    private static uint DaysToSeconds(uint days) =>
        days == 0 ? uint.MaxValue : days * 86400;

    private static uint SecondsToMinutes(uint seconds) =>
        seconds / 60;

    private static uint MinutesToSeconds(uint minutes) =>
        minutes * 60;

    // ----------------------------------------------------------------
    // P/Invoke declarations — netapi32.dll
    // ----------------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_MODALS_INFO_0
    {
        public uint usrmod0_min_passwd_len;
        public uint usrmod0_max_passwd_age;
        public uint usrmod0_min_passwd_age;
        public uint usrmod0_force_logoff;
        public uint usrmod0_password_hist_len;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct USER_MODALS_INFO_3
    {
        public uint usrmod3_lockout_duration;
        public uint usrmod3_lockout_observation_window;
        public uint usrmod3_lockout_threshold;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserModalsGet(string? server, int level, out IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserModalsSet(string? server, int level, IntPtr buf, out int parmErr);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
