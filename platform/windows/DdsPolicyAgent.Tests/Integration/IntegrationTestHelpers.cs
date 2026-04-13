// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace DDS.PolicyAgent.Tests.Integration;

/// <summary>
/// Shared helpers for integration tests that touch real Windows APIs.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class IntegrationTestHelpers
{
    /// <summary>HKCU path used for non-elevated registry tests.</summary>
    public const string HkcuTestRoot = @"Software\DDS\Test";

    /// <summary>HKLM path used for elevated registry tests.</summary>
    public const string HklmTestRoot = @"SOFTWARE\Policies\DDS\Test";

    public static bool IsWindows => RuntimeInformation.IsOSPlatform(OSPlatform.Windows);

    public static bool IsElevated
    {
        get
        {
            if (!IsWindows) return false;
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    public static string SkipIfNotWindows()
        => IsWindows ? "" : "Test requires Windows";

    public static string SkipIfNotAdmin()
        => IsElevated ? "" : "Test requires elevation (run as Administrator)";
}
