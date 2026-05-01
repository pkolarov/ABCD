// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Linux.Runtime;

public static class PrivilegeGuard
{
    public static bool IsPrivileged()
        => Environment.UserName == "root";
}
