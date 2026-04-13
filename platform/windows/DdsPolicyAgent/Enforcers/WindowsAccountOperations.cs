// SPDX-License-Identifier: MIT OR Apache-2.0

using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Production implementation of <see cref="IAccountOperations"/>
/// using netapi32 P/Invoke for local account management.
/// Runs as LocalSystem and manages SAM accounts directly.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsAccountOperations : IAccountOperations
{
    public bool IsDomainJoined()
    {
        int result = NetGetJoinInformation(null, out var buffer, out var joinStatus);
        if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        if (result != 0)
            throw new Win32Exception(result, "NetGetJoinInformation failed");
        return joinStatus == NetJoinStatus.NetSetupDomainName;
    }

    public bool UserExists(string username)
    {
        int result = NetUserGetInfo(null, username, 0, out var buffer);
        if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        return result == 0; // NERR_UserNotFound = 2221
    }

    public void CreateUser(string username, string? fullName, string? description)
    {
        // Generate a 32-char random password meeting complexity requirements
        var password = GenerateRandomPassword();

        var info = new USER_INFO_1
        {
            usri1_name = username,
            usri1_password = password,
            usri1_priv = UserPrivilege.USER_PRIV_USER,
            usri1_home_dir = null,
            usri1_comment = description,
            usri1_flags = UserFlags.UF_SCRIPT | UserFlags.UF_NORMAL_ACCOUNT,
            usri1_script_path = null,
        };

        int result = NetUserAdd(null, 1, ref info, out var parmErr);
        if (result != 0)
            throw new Win32Exception(result,
                $"NetUserAdd failed for '{username}' (parm_err={parmErr})");

        // Set full name via level 1008-style update using USER_INFO_1011
        if (fullName is not null)
        {
            var fullNameInfo = new USER_INFO_1011 { usri1011_full_name = fullName };
            int r = NetUserSetInfo(null, username, 1011, ref fullNameInfo, out _);
            if (r != 0)
                throw new Win32Exception(r,
                    $"NetUserSetInfo(1011) failed for '{username}'");
        }
    }

    public void DeleteUser(string username)
    {
        int result = NetUserDel(null, username);
        if (result != 0 && result != 2221) // 2221 = NERR_UserNotFound
            throw new Win32Exception(result,
                $"NetUserDel failed for '{username}'");
    }

    public void DisableUser(string username)
    {
        SetUserFlag(username, UserFlags.UF_ACCOUNTDISABLE, set: true);
    }

    public void EnableUser(string username)
    {
        SetUserFlag(username, UserFlags.UF_ACCOUNTDISABLE, set: false);
    }

    public bool IsEnabled(string username)
    {
        var flags = GetUserFlags(username);
        return (flags & UserFlags.UF_ACCOUNTDISABLE) == 0;
    }

    public IReadOnlyList<string> GetGroups(string username)
    {
        int result = NetUserGetLocalGroups(
            null, username, 0, LG_INCLUDE_INDIRECT,
            out var buffer, MAX_PREFERRED_LENGTH,
            out var entriesRead, out _);

        if (result != 0)
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            throw new Win32Exception(result,
                $"NetUserGetLocalGroups failed for '{username}'");
        }

        try
        {
            var groups = new List<string>();
            var ptr = buffer;
            for (int i = 0; i < entriesRead; i++)
            {
                var entry = Marshal.PtrToStructure<LOCALGROUP_USERS_INFO_0>(ptr)!;
                if (entry.lgrui0_name is not null)
                    groups.Add(entry.lgrui0_name);
                ptr += Marshal.SizeOf<LOCALGROUP_USERS_INFO_0>();
            }
            return groups;
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
    }

    public void AddToGroup(string username, string group)
    {
        var member = new LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname = username };
        int result = NetLocalGroupAddMembers(null, group, 3, ref member, 1);
        if (result != 0 && result != 1378) // 1378 = ERROR_MEMBER_IN_ALIAS (already member)
            throw new Win32Exception(result,
                $"NetLocalGroupAddMembers failed: '{username}' -> '{group}'");
    }

    public void RemoveFromGroup(string username, string group)
    {
        var member = new LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname = username };
        int result = NetLocalGroupDelMembers(null, group, 3, ref member, 1);
        if (result != 0 && result != 1377) // 1377 = ERROR_MEMBER_NOT_IN_ALIAS
            throw new Win32Exception(result,
                $"NetLocalGroupDelMembers failed: '{username}' from '{group}'");
    }

    public void SetPasswordNeverExpires(string username, bool neverExpires)
    {
        SetUserFlag(username, UserFlags.UF_DONT_EXPIRE_PASSWD, set: neverExpires);
    }

    // ----------------------------------------------------------------
    // Internal helpers
    // ----------------------------------------------------------------

    private UserFlags GetUserFlags(string username)
    {
        int result = NetUserGetInfo(null, username, 1, out var buffer);
        if (result != 0)
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
            throw new Win32Exception(result,
                $"NetUserGetInfo failed for '{username}'");
        }
        try
        {
            var info = Marshal.PtrToStructure<USER_INFO_1>(buffer);
            return info.usri1_flags;
        }
        finally
        {
            NetApiBufferFree(buffer);
        }
    }

    private void SetUserFlag(string username, UserFlags flag, bool set)
    {
        var current = GetUserFlags(username);
        var desired = set ? (current | flag) : (current & ~flag);
        if (current == desired) return;

        var flagInfo = new USER_INFO_1008 { usri1008_flags = desired };
        int result = NetUserSetInfo(null, username, 1008, ref flagInfo, out _);
        if (result != 0)
            throw new Win32Exception(result,
                $"NetUserSetInfo(1008) failed for '{username}'");
    }

    private static string GenerateRandomPassword()
    {
        // 24 random bytes -> base64 gives 32 chars, prepend complexity guarantors
        var bytes = RandomNumberGenerator.GetBytes(24);
        return "Aa1!" + Convert.ToBase64String(bytes);
    }

    // ----------------------------------------------------------------
    // P/Invoke declarations — netapi32.dll
    // ----------------------------------------------------------------

    private const int MAX_PREFERRED_LENGTH = -1;
    private const int LG_INCLUDE_INDIRECT = 0x0001;

    private enum NetJoinStatus
    {
        NetSetupUnknownStatus = 0,
        NetSetupUnjoined,
        NetSetupWorkgroupName,
        NetSetupDomainName,
    }

    [Flags]
    private enum UserPrivilege : uint
    {
        USER_PRIV_GUEST = 0,
        USER_PRIV_USER = 1,
        USER_PRIV_ADMIN = 2,
    }

    [Flags]
    private enum UserFlags : uint
    {
        UF_SCRIPT = 0x0001,
        UF_ACCOUNTDISABLE = 0x0002,
        UF_NORMAL_ACCOUNT = 0x0200,
        UF_DONT_EXPIRE_PASSWD = 0x10000,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct USER_INFO_1
    {
        public string? usri1_name;
        public string? usri1_password;
        public uint usri1_password_age;
        public UserPrivilege usri1_priv;
        public string? usri1_home_dir;
        public string? usri1_comment;
        public UserFlags usri1_flags;
        public string? usri1_script_path;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct USER_INFO_1008
    {
        public UserFlags usri1008_flags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct USER_INFO_1011
    {
        public string? usri1011_full_name;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LOCALGROUP_USERS_INFO_0
    {
        public string? lgrui0_name;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct LOCALGROUP_MEMBERS_INFO_3
    {
        public string? lgrmi3_domainandname;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetGetJoinInformation(
        string? server, out IntPtr nameBuffer, out NetJoinStatus status);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserAdd(
        string? server, int level, ref USER_INFO_1 buf, out int parmErr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserDel(string? server, string username);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetInfo(
        string? server, string username, int level, out IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserSetInfo(
        string? server, string username, int level, ref USER_INFO_1008 buf, out int parmErr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserSetInfo(
        string? server, string username, int level, ref USER_INFO_1011 buf, out int parmErr);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserGetLocalGroups(
        string? server, string username, int level, int flags,
        out IntPtr buffer, int prefMaxLen,
        out int entriesRead, out int totalEntries);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupAddMembers(
        string? server, string groupName, int level,
        ref LOCALGROUP_MEMBERS_INFO_3 buf, int totalEntries);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetLocalGroupDelMembers(
        string? server, string groupName, int level,
        ref LOCALGROUP_MEMBERS_INFO_3 buf, int totalEntries);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);
}
