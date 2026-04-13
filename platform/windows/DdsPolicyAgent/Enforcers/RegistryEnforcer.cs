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

    private static string DescribeDirective(JsonElement item)
    {
        var hive = item.TryGetProperty("hive", out var h) ? h.GetString() : "?";
        var key = item.TryGetProperty("key", out var k) ? k.GetString() : "?";
        var action = item.TryGetProperty("action", out var a) ? a.GetString() : "?";
        return $"{action} {hive}\\{key}";
    }
}
