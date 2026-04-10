// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using Microsoft.Win32;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Production implementation of <see cref="IRegistryOperations"/>
/// that calls <c>Microsoft.Win32.Registry</c>. Only instantiated on
/// Windows — the DI container guards this with a platform check.
///
/// <b>Security:</b> The enforcer validates hive + key against an
/// allowlist before calling here, so this class trusts its inputs.
/// It runs as LocalSystem and can write HKLM.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsRegistryOperations : IRegistryOperations
{
    public object? GetValue(string hive, string subKey, string? valueName)
    {
        using var key = OpenBaseKey(hive).OpenSubKey(subKey);
        return key?.GetValue(valueName);
    }

    public void SetValue(string hive, string subKey, string? valueName, object value, RegValueKind kind)
    {
        using var key = OpenBaseKey(hive).CreateSubKey(subKey, writable: true);
        key.SetValue(valueName, value, ToRegistryValueKind(kind));
    }

    public void DeleteValue(string hive, string subKey, string valueName)
    {
        using var key = OpenBaseKey(hive).OpenSubKey(subKey, writable: true);
        key?.DeleteValue(valueName, throwOnMissingValue: false);
    }

    public void DeleteKey(string hive, string subKey)
    {
        // Non-recursive: throws if subkeys exist. The enforcer
        // should refuse delete-key when the key has children.
        var parent = Path.GetDirectoryName(subKey.Replace('\\', '/'))?.Replace('/', '\\') ?? "";
        var leaf = Path.GetFileName(subKey.Replace('\\', '/'));
        using var key = OpenBaseKey(hive).OpenSubKey(parent, writable: true);
        if (key is null) return;
        try { key.DeleteSubKey(leaf, throwOnMissingSubKey: false); }
        catch (InvalidOperationException) { /* has subkeys — refuse silently */ }
    }

    public bool KeyExists(string hive, string subKey)
    {
        using var key = OpenBaseKey(hive).OpenSubKey(subKey);
        return key is not null;
    }

    private static RegistryKey OpenBaseKey(string hive) => hive switch
    {
        "LocalMachine" => Registry.LocalMachine,
        "CurrentUser" => Registry.CurrentUser,
        "Users" => Registry.Users,
        "ClassesRoot" => Registry.ClassesRoot,
        _ => throw new ArgumentException($"Unknown hive: {hive}"),
    };

    private static RegistryValueKind ToRegistryValueKind(RegValueKind k) => k switch
    {
        RegValueKind.String => RegistryValueKind.String,
        RegValueKind.ExpandString => RegistryValueKind.ExpandString,
        RegValueKind.Dword => RegistryValueKind.DWord,
        RegValueKind.Qword => RegistryValueKind.QWord,
        RegValueKind.MultiString => RegistryValueKind.MultiString,
        RegValueKind.Binary => RegistryValueKind.Binary,
        _ => RegistryValueKind.String,
    };
}
