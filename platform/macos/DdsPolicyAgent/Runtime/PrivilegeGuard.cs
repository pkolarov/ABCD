// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.MacOS.Runtime;

internal static class PrivilegeGuard
{
    public static void DemandRoot(string action)
    {
        if (string.Equals(
            Environment.GetEnvironmentVariable("DDS_POLICYAGENT_ASSUME_ROOT"),
            "1",
            StringComparison.Ordinal))
        {
            return;
        }

        if (string.Equals(Environment.UserName, "root", StringComparison.OrdinalIgnoreCase))
            return;

        throw new InvalidOperationException(
            $"{action} requires root privileges; run the macOS agent as a LaunchDaemon or under sudo.");
    }
}
