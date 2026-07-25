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
    /// Prefix marking a managed key as <i>key-level</i> (the directive
    /// carried no <c>name</c>, so the whole registry key is managed).
    /// </summary>
    /// <remarks>
    /// <b>L-15 (pre-prod review 2026-07-24)</b>. See
    /// <see cref="ExtractManagedKey"/>.
    /// </remarks>
    internal const string KeyLevelPrefix = "K:";

    /// <summary>
    /// Prefix marking a managed key as <i>value-level</i> (the last
    /// backslash-separated segment is the value name).
    /// </summary>
    internal const string ValueLevelPrefix = "V:";

    /// <summary>
    /// Extract the managed-item key for a directive (used by Worker
    /// to build the desired managed set).
    ///
    /// <para>
    /// Format: <c>V:hive\key\valueName</c> for a value-level directive,
    /// <c>K:hive\key</c> for a key-level one.
    /// </para>
    ///
    /// <para>
    /// <b>L-15 (pre-prod review 2026-07-24)</b>: the encoding used to be
    /// a bare <c>hive\key[\valueName]</c> with no discriminator, and
    /// <see cref="ParseManagedKey"/> guessed — it always treated the last
    /// segment as a value name whenever the remainder contained a
    /// backslash. Registry key paths essentially always contain
    /// backslashes (<c>SOFTWARE\Policies\DDS\Foo</c>), so a *key-level*
    /// managed item round-tripped as
    /// <c>(SOFTWARE\Policies\DDS, value "Foo")</c>. Reconcile then looked
    /// for a value that does not exist, found nothing, and deleted
    /// nothing: a retracted key-level directive was never actually
    /// reverted, so the policy stayed in force on the host after being
    /// pulled from the domain.
    /// </para>
    ///
    /// <para>
    /// The prefix removes the guess. <see cref="ParseManagedKey"/> still
    /// accepts the legacy unprefixed form so managed sets persisted by an
    /// earlier agent build keep reconciling across the upgrade (with the
    /// old, lossy heuristic — the state is genuinely ambiguous).
    /// </para>
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
        return name is not null
            ? $@"{ValueLevelPrefix}{hive}\{key}\{name}"
            : $@"{KeyLevelPrefix}{hive}\{key}";
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
    /// The <c>hive\key[\valueName]</c> body of a managed key, with any
    /// <see cref="KeyLevelPrefix"/> / <see cref="ValueLevelPrefix"/>
    /// discriminator removed.
    ///
    /// <para>
    /// <b>L-15 upgrade safety.</b> Reconciliation computes
    /// <c>stale = previouslyManaged − desired</c> by string set
    /// difference. On the first poll after an agent upgrade the
    /// persisted set still holds legacy unprefixed strings while the
    /// freshly-built desired set holds prefixed ones, so a raw string
    /// diff would classify *every* still-desired registry item as stale
    /// and delete it. Diffing on this prefix-free body makes the two
    /// encodings compare equal, so the upgrade is a no-op and the
    /// persisted set is quietly rewritten in the new form.
    /// </para>
    /// </summary>
    internal static string ManagedKeyBody(string managedKey) =>
        managedKey.StartsWith(KeyLevelPrefix, StringComparison.Ordinal)
            ? managedKey[KeyLevelPrefix.Length..]
            : managedKey.StartsWith(ValueLevelPrefix, StringComparison.Ordinal)
                ? managedKey[ValueLevelPrefix.Length..]
                : managedKey;

    /// <summary>
    /// Parse a managed key string back into hive, subKey, and optional
    /// valueName.
    ///
    /// <para>
    /// <b>L-15 (pre-prod review 2026-07-24)</b>: prefers the explicit
    /// <see cref="KeyLevelPrefix"/> / <see cref="ValueLevelPrefix"/>
    /// discriminator written by <see cref="ExtractManagedKey"/>. An
    /// unprefixed string is managed state persisted by an older agent
    /// build; it is genuinely ambiguous, so it falls back to the legacy
    /// "last segment is the value name" heuristic. That fallback is
    /// wrong for key-level items — which is the bug — but it is what the
    /// old state means, and it stops applying as soon as the current
    /// policy is re-applied and the managed set is rewritten with
    /// prefixes.
    /// </para>
    /// </summary>
    internal static (string Hive, string Key, string? ValueName)? ParseManagedKey(string managedKey)
    {
        if (managedKey.StartsWith(KeyLevelPrefix, StringComparison.Ordinal))
        {
            var body = managedKey[KeyLevelPrefix.Length..];
            var sep = body.IndexOf('\\');
            if (sep < 0) return null;
            var h = body[..sep];
            var k = body[(sep + 1)..];
            if (h.Length == 0 || k.Length == 0) return null;
            return (h, k, null);
        }

        if (managedKey.StartsWith(ValueLevelPrefix, StringComparison.Ordinal))
        {
            var body = managedKey[ValueLevelPrefix.Length..];
            var sep = body.IndexOf('\\');
            if (sep < 0) return null;
            var h = body[..sep];
            var rest = body[(sep + 1)..];
            // Value name is the final segment; the key is everything
            // before it. A value-level item must therefore have at least
            // one more separator.
            var lastSep = rest.LastIndexOf('\\');
            if (lastSep < 0) return null;
            var k = rest[..lastSep];
            var v = rest[(lastSep + 1)..];
            if (h.Length == 0 || k.Length == 0) return null;
            return (h, k, v);
        }

        // --- Legacy, unprefixed: "hive\key[\valueName]" ---------------
        var firstSep = managedKey.IndexOf('\\');
        if (firstSep < 0) return null;

        var hive = managedKey[..firstSep];
        var legacyRest = managedKey[(firstSep + 1)..];
        var legacyLastSep = legacyRest.LastIndexOf('\\');
        if (legacyLastSep < 0)
            return (hive, legacyRest, null); // Single-segment key, no value

        return (hive, legacyRest[..legacyLastSep], legacyRest[(legacyLastSep + 1)..]);
    }

    private static string DescribeDirective(JsonElement item)
    {
        var hive = item.TryGetProperty("hive", out var h) ? h.GetString() : "?";
        var key = item.TryGetProperty("key", out var k) ? k.GetString() : "?";
        var action = item.TryGetProperty("action", out var a) ? a.GetString() : "?";
        return $"{action} {hive}\\{key}";
    }
}
