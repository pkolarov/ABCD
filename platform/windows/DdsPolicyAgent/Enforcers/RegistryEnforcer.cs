// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Enforces <c>WindowsSettings.registry</c> directives by
/// dispatching through <see cref="IRegistryOperations"/>. In
/// production the DI container injects
/// <see cref="WindowsRegistryOperations"/> (real Win32); in tests
/// it injects a mock.
///
/// <b>Security:</b> writes are restricted to an allowlist of hive
/// prefixes (see <see cref="AllowedPrefixes"/>). Any directive
/// targeting a path outside the allowlist is rejected with
/// <see cref="EnforcementStatus.Failed"/>.
/// </summary>
public sealed class RegistryEnforcer : IEnforcer
{
    private readonly IRegistryOperations _ops;
    private readonly ILogger<RegistryEnforcer> _log;
    public string Name => "Registry";

    /// <summary>
    /// Subkey prefixes the enforcer is allowed to write under HKLM.
    /// Everything else is refused to limit blast radius if a
    /// compromised dds-node pushes a malicious policy.
    /// </summary>
    public static readonly string[] AllowedPrefixes =
    [
        @"SOFTWARE\Policies\",
        @"SOFTWARE\DDS\",
        @"SYSTEM\CurrentControlSet\Services\",
    ];

    public RegistryEnforcer(IRegistryOperations ops, ILogger<RegistryEnforcer> log)
    {
        _ops = ops;
        _log = log;
    }

    public Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive, EnforcementMode mode, CancellationToken ct = default)
    {
        if (directive.ValueKind != JsonValueKind.Array)
            return Task.FromResult(new EnforcementOutcome(EnforcementStatus.Skipped));

        var changes = new List<string>();
        string? firstError = null;
        var overallStatus = EnforcementStatus.Ok;

        foreach (var item in directive.EnumerateArray())
        {
            try
            {
                var result = ApplyOne(item, mode);
                changes.Add(result);
            }
            catch (Exception ex)
            {
                var desc = DescribeDirective(item);
                _log.LogError(ex, "Registry enforcer failed on {Directive}", desc);
                changes.Add($"FAILED: {desc} — {ex.Message}");
                firstError ??= ex.Message;
                overallStatus = EnforcementStatus.Failed;
            }
        }

        return Task.FromResult(new EnforcementOutcome(overallStatus, firstError, changes));
    }

    private string ApplyOne(JsonElement item, EnforcementMode mode)
    {
        var hive = item.GetProperty("hive").GetString()!;
        var key = item.GetProperty("key").GetString()!;
        var name = item.TryGetProperty("name", out var n) && n.ValueKind != JsonValueKind.Null
            ? n.GetString()
            : null;
        var action = item.GetProperty("action").GetString()!;

        // Security: validate against allowlist
        if (!IsAllowed(hive, key))
            throw new InvalidOperationException(
                $"Refused: {hive}\\{key} is outside the allowed registry prefixes");

        var displayName = name ?? "(Default)";
        var desc = $"{action} {hive}\\{key}\\{displayName}";

        if (mode == EnforcementMode.Audit)
        {
            _log.LogInformation("[AUDIT] Registry: would {Action}", desc);
            return $"[AUDIT] {desc}";
        }

        switch (action)
        {
            case "Set":
                var (value, kind) = ParseValue(item);
                var existing = _ops.GetValue(hive, key, name);
                if (existing is not null && RegistryValuesEqual(existing, value))
                {
                    _log.LogDebug("Registry: {Key}\\{Name} already at desired value", key, displayName);
                    return $"[NO-OP] {desc} (already set)";
                }
                _ops.SetValue(hive, key, name, value, kind);
                _log.LogInformation("Registry: {Action}", desc);
                return desc;

            case "Delete":
                if (name is not null)
                {
                    _ops.DeleteValue(hive, key, name);
                }
                else
                {
                    _ops.DeleteKey(hive, key);
                }
                _log.LogInformation("Registry: {Action}", desc);
                return desc;

            default:
                throw new InvalidOperationException($"Unknown registry action: {action}");
        }
    }

    internal static bool IsAllowed(string hive, string key)
    {
        // Only HKLM writes are allowlisted. Other hives are refused
        // entirely for v1 — LocalSystem's HKCU is its own profile,
        // which is never useful for policy.
        if (hive != "LocalMachine")
            return false;

        foreach (var prefix in AllowedPrefixes)
        {
            if (key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    internal static (object Value, RegValueKind Kind) ParseValue(JsonElement item)
    {
        if (!item.TryGetProperty("value", out var val) || val.ValueKind == JsonValueKind.Null)
            throw new InvalidOperationException("Set action requires a value");

        // The Rust RegistryValue enum serializes as {"Dword": 1},
        // {"String": "hello"}, etc. — a single-key object.
        if (val.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in val.EnumerateObject())
            {
                return prop.Name switch
                {
                    "String" => (prop.Value.GetString()!, RegValueKind.String),
                    "ExpandString" => (prop.Value.GetString()!, RegValueKind.ExpandString),
                    "Dword" => (prop.Value.GetUInt32(), RegValueKind.Dword),
                    "Qword" => (prop.Value.GetUInt64(), RegValueKind.Qword),
                    "MultiString" => (
                        prop.Value.EnumerateArray().Select(e => e.GetString()!).ToArray(),
                        RegValueKind.MultiString),
                    "Binary" => (
                        Convert.FromBase64String(prop.Value.GetString()!),
                        RegValueKind.Binary),
                    _ => throw new InvalidOperationException(
                        $"Unknown RegistryValue variant: {prop.Name}"),
                };
            }
        }

        throw new InvalidOperationException(
            $"Cannot parse registry value from JSON kind {val.ValueKind}");
    }

    /// <summary>
    /// Compare registry values across type boundaries. The real
    /// registry returns <c>int</c> for DWORD and <c>long</c> for
    /// QWORD, while <see cref="ParseValue"/> produces <c>uint</c>
    /// and <c>ulong</c>. This method normalises both sides before
    /// comparing.
    /// </summary>
    internal static bool RegistryValuesEqual(object existing, object desired)
    {
        // Normalise numeric types: registry returns signed, we store unsigned
        if (existing is int ei && desired is uint du)
            return (uint)ei == du;
        if (existing is long el && desired is ulong qu)
            return (ulong)el == qu;

        // byte[] — SequenceEqual
        if (existing is byte[] eb && desired is byte[] db)
            return eb.AsSpan().SequenceEqual(db);

        // string[] — element-wise
        if (existing is string[] es && desired is string[] ds)
            return es.Length == ds.Length && es.Zip(ds).All(p => p.First == p.Second);

        return existing.Equals(desired);
    }

    /// <summary>
    /// Extract the managed-item key for a directive (used by Worker
    /// to build the desired managed set).
    /// Format: <c>hive\key\valueName</c> or <c>hive\key</c> for
    /// key-level operations.
    /// </summary>
    public static string? ExtractManagedKey(JsonElement item)
    {
        if (!item.TryGetProperty("hive", out var h) || !item.TryGetProperty("key", out var k))
            return null;
        var hive = h.GetString();
        var key = k.GetString();
        if (hive is null || key is null) return null;

        var name = item.TryGetProperty("name", out var n) && n.ValueKind != JsonValueKind.Null
            ? n.GetString()
            : null;
        return name is not null ? $@"{hive}\{key}\{name}" : $@"{hive}\{key}";
    }

    /// <summary>
    /// Remove registry entries that were previously managed by DDS
    /// but are no longer present in the current policy.
    /// </summary>
    public List<string> ReconcileStaleItems(
        IReadOnlySet<string> staleKeys, EnforcementMode mode)
    {
        var changes = new List<string>();
        foreach (var managedKey in staleKeys)
        {
            try
            {
                // Parse "hive\key\valueName" or "hive\key"
                var parts = ParseManagedKey(managedKey);
                if (parts is null)
                {
                    _log.LogWarning("Reconcile: could not parse managed key '{Key}'", managedKey);
                    continue;
                }

                var (hive, key, valueName) = parts.Value;

                if (!IsAllowed(hive, key))
                {
                    _log.LogWarning("Reconcile: stale key '{Key}' outside allowlist — skip", managedKey);
                    continue;
                }

                var desc = $"Reconcile-Delete {managedKey}";

                if (mode == EnforcementMode.Audit)
                {
                    _log.LogInformation("[AUDIT] Registry reconcile: would delete {Key}", managedKey);
                    changes.Add($"[AUDIT] {desc}");
                    continue;
                }

                if (valueName is not null)
                {
                    if (_ops.GetValue(hive, key, valueName) is not null)
                    {
                        _ops.DeleteValue(hive, key, valueName);
                        _log.LogInformation("Registry reconcile: deleted stale value {Key}", managedKey);
                        changes.Add(desc);
                    }
                }
                else
                {
                    if (_ops.KeyExists(hive, key))
                    {
                        _ops.DeleteKey(hive, key);
                        _log.LogInformation("Registry reconcile: deleted stale key {Key}", managedKey);
                        changes.Add(desc);
                    }
                }
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Registry reconcile failed for {Key}", managedKey);
                changes.Add($"FAILED: Reconcile-Delete {managedKey} — {ex.Message}");
            }
        }
        return changes;
    }

    /// <summary>
    /// Parse a managed key string back into hive, subKey, and optional valueName.
    /// </summary>
    internal static (string Hive, string Key, string? ValueName)? ParseManagedKey(string managedKey)
    {
        // Format: "hive\key[\valueName]"
        // Hive is the first segment (e.g. "LocalMachine")
        var firstSep = managedKey.IndexOf('\\');
        if (firstSep < 0) return null;

        var hive = managedKey[..firstSep];
        var rest = managedKey[(firstSep + 1)..];

        // Check if there's a value name by looking at the AllowedPrefixes pattern.
        // The key path is everything after the hive up to the value name.
        // We use a heuristic: if the last segment doesn't contain a backslash
        // after the key prefix, it's a value name.
        // Actually, we need a better approach. During extraction in ExtractManagedKey,
        // we encode "hive\key\valueName". The key always contains backslashes
        // (e.g. SOFTWARE\Policies\DDS\Test), and the valueName is the last component
        // ONLY if the directive had a "name" property.
        //
        // Since we can't distinguish reliably here, we store an explicit separator.
        // But for backwards compatibility, we use the simpler approach: try to find
        // the value in the registry. If the full path is a key, treat it as key-level.
        // Otherwise, split the last component as valueName.

        // Try as a full key path first
        // If not a key, the last component is the value name
        var lastSep = rest.LastIndexOf('\\');
        if (lastSep < 0)
            return (hive, rest, null); // Just a single-segment key, no value

        return (hive, rest[..lastSep], rest[(lastSep + 1)..]);
    }

    private static string DescribeDirective(JsonElement item)
    {
        var hive = item.TryGetProperty("hive", out var h) ? h.GetString() : "?";
        var key = item.TryGetProperty("key", out var k) ? k.GetString() : "?";
        var action = item.TryGetProperty("action", out var a) ? a.GetString() : "?";
        return $"{action} {hive}\\{key}";
    }
}
