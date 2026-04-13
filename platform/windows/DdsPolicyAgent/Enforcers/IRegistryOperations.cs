// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Registry value types, mirroring the Rust <c>RegistryValue</c>
/// enum and Win32 <c>REG_*</c> constants.
/// </summary>
public enum RegValueKind
{
    String,       // REG_SZ
    ExpandString, // REG_EXPAND_SZ
    Dword,        // REG_DWORD
    Qword,        // REG_QWORD
    MultiString,  // REG_MULTI_SZ
    Binary,       // REG_BINARY
}

/// <summary>
/// Parsed registry value — the enforcer converts the JSON
/// <c>RegistryValue</c> enum into this before calling the
/// operations interface.
/// </summary>
public sealed record ParsedRegValue(RegValueKind Kind, object Value);

/// <summary>
/// Thin abstraction over <c>Microsoft.Win32.Registry</c> so the
/// enforcer can be unit-tested on any platform. The production
/// implementation (<see cref="WindowsRegistryOperations"/>) calls
/// real Win32; tests inject a mock.
/// </summary>
public interface IRegistryOperations
{
    /// <summary>
    /// Read the current value of a registry entry. Returns null if
    /// the key or value does not exist.
    /// </summary>
    object? GetValue(string hive, string subKey, string? valueName);

    /// <summary>
    /// Set a registry value, creating the key path if necessary.
    /// </summary>
    void SetValue(string hive, string subKey, string? valueName, object value, RegValueKind kind);

    /// <summary>
    /// Delete a single named value. No-op if it doesn't exist.
    /// </summary>
    void DeleteValue(string hive, string subKey, string valueName);

    /// <summary>
    /// Delete an entire subkey (non-recursive — fails if subkeys
    /// exist, by design). No-op if it doesn't exist.
    /// </summary>
    void DeleteKey(string hive, string subKey);

    /// <summary>
    /// Check if a subkey exists.
    /// </summary>
    bool KeyExists(string hive, string subKey);

    /// <summary>
    /// Enumerate the value names under a subkey. Returns an empty list
    /// if the key does not exist.
    /// </summary>
    IReadOnlyList<string> GetValueNames(string hive, string subKey);

    /// <summary>
    /// Enumerate the child subkey names under a subkey. Returns an
    /// empty list if the key does not exist.
    /// </summary>
    IReadOnlyList<string> GetSubKeyNames(string hive, string subKey);
}
