// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;
using DDS.PolicyAgent.HostState;

namespace DDS.PolicyAgent.State;

/// <summary>
/// Per-policy/software application state, persisted to disk so the
/// agent can skip re-applying unchanged documents after a restart.
/// </summary>
public sealed class AppliedEntry
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    [JsonPropertyName("content_hash")]
    public string ContentHash { get; set; } = string.Empty;

    [JsonPropertyName("applied_at")]
    public ulong AppliedAt { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = "ok";

    /// <summary>
    /// AD-04: <see cref="HostState.JoinState"/> at the moment this entry
    /// was last written, serialised as the enum's string name. Empty on
    /// legacy entries (pre-AD-04) and on entries written by tests that
    /// don't supply a join-state. The worker uses this to detect
    /// transitions and force a one-time audit re-pass when the host
    /// state has changed since the last cycle.
    /// </summary>
    [JsonPropertyName("host_state_at_apply")]
    public string HostStateAtApply { get; set; } = string.Empty;
}

/// <summary>
/// Per-managed-item metadata. Replaces the prior <c>HashSet&lt;string&gt;</c>
/// shape so audit-mode reconciliation can mark items frozen rather than
/// silently dropping them. See <c>docs/windows-ad-coexistence-spec.md §7.1</c>.
/// </summary>
public sealed class ManagedItemRecord
{
    [JsonPropertyName("last_outcome")]
    public string LastOutcome { get; set; } = "applied";

    [JsonPropertyName("last_reason")]
    public string? LastReason { get; set; }

    /// <summary>
    /// JoinState at the moment this record was last written, serialised
    /// as the enum's string name (e.g. <c>"Workgroup"</c>,
    /// <c>"AdJoined"</c>, <c>"Unknown"</c>). Legacy records migrated
    /// from the old set-of-strings shape default to <c>"Unknown"</c>.
    /// </summary>
    [JsonPropertyName("host_state_at_apply")]
    public string HostStateAtApply { get; set; } = nameof(JoinState.Unknown);

    /// <summary>
    /// Set when reconciliation in audit mode would have removed the item
    /// but could not because the host is AD-joined / hybrid / probe-failed.
    /// A later workgroup transition clears this on the next reconcile.
    /// </summary>
    [JsonPropertyName("audit_frozen")]
    public bool AuditFrozen { get; set; }

    [JsonPropertyName("updated_at")]
    public ulong UpdatedAt { get; set; }
}

/// <summary>
/// Root shape of applied-state.json.
/// </summary>
public sealed class AppliedState
{
    [JsonPropertyName("policies")]
    public Dictionary<string, AppliedEntry> Policies { get; set; } = new();

    [JsonPropertyName("software")]
    public Dictionary<string, AppliedEntry> Software { get; set; } = new();

    /// <summary>
    /// Items currently managed by DDS, keyed first by enforcer category
    /// (e.g. "registry", "accounts", "software") and then by the item
    /// identifier inside that category. Each entry carries metadata so
    /// reconciliation under audit mode can mark items frozen rather
    /// than silently dropping them. See AD-04 in the AD-coexistence
    /// spec.
    /// </summary>
    [JsonPropertyName("managed_items")]
    [JsonConverter(typeof(ManagedItemsConverter))]
    public Dictionary<string, Dictionary<string, ManagedItemRecord>> ManagedItems { get; set; } = new();
}

/// <summary>
/// Reads and writes <c>applied-state.json</c> under the configured
/// state directory. Thread-safe: all mutations go through a lock.
/// </summary>
public interface IAppliedStateStore
{
    AppliedState Load();
    void Save(AppliedState state);
    bool HasChanged(string targetId, string contentHash);
    void RecordApplied(string targetId, string version, string contentHash, string status, bool isSoftware);

    /// <summary>
    /// AD-04 overload: also stamp the recorded entry with the
    /// <see cref="JoinState"/> at apply time so the worker can detect
    /// transitions across cycles. Pass <c>null</c> to fall back to the
    /// pre-AD-04 behavior of leaving <c>host_state_at_apply</c> empty
    /// (used by callers that genuinely do not know the host state — in
    /// production the worker always supplies it).
    /// </summary>
    void RecordApplied(
        string targetId, string version, string contentHash, string status,
        bool isSoftware, JoinState? hostState);

    /// <summary>
    /// Get the set of item keys DDS currently manages for a given
    /// category. Returns an empty set if nothing is tracked yet.
    /// </summary>
    IReadOnlySet<string> GetManagedItems(string category);

    /// <summary>
    /// Update the managed-item inventory for a category in a single
    /// pass that respects audit semantics.
    ///
    /// <para>
    /// Items present in <paramref name="desired"/> are upserted with
    /// <paramref name="joinState"/> + the supplied reason. Items absent
    /// from <paramref name="desired"/> but already in the inventory are:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>removed when <paramref name="auditMode"/> is false (workgroup behavior)</description></item>
    ///   <item><description>kept and marked <see cref="ManagedItemRecord.AuditFrozen"/> = true when <paramref name="auditMode"/> is true (AD/Hybrid/Unknown)</description></item>
    /// </list>
    /// <para>
    /// A later transition back to workgroup mode clears the
    /// <see cref="ManagedItemRecord.AuditFrozen"/> bit on the next
    /// reconcile that lists the item again, or removes it on the
    /// next reconcile that drops it from <paramref name="desired"/>.
    /// </para>
    /// </summary>
    void RecordManagedItems(
        string category,
        IReadOnlySet<string> desired,
        JoinState joinState,
        bool auditMode,
        string? reason);

    /// <summary>
    /// Get the recorded join-state for a previously-applied policy or
    /// software entry, parsed back into the <see cref="JoinState"/>
    /// enum. Returns <c>null</c> when the target has never been
    /// applied or the legacy entry has no <c>host_state_at_apply</c>.
    /// </summary>
    JoinState? GetHostStateAtApply(string targetId, bool isSoftware);
}

public sealed class AppliedStateStore : IAppliedStateStore
{
    private readonly string _path;
    private readonly object _lock = new();
    private AppliedState _state;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
    };

    public AppliedStateStore(string stateDir)
    {
        Directory.CreateDirectory(stateDir);
        _path = Path.Combine(stateDir, "applied-state.json");
        _state = LoadFromDisk();
    }

    public AppliedState Load()
    {
        lock (_lock)
        {
            return _state;
        }
    }

    public void Save(AppliedState state)
    {
        lock (_lock)
        {
            _state = state;
            WriteToDisk(state);
        }
    }

    /// <summary>
    /// Returns true if the agent should re-apply the document
    /// (either never seen, content hash changed, or last apply did
    /// not succeed — see B-3 in the security review).
    /// </summary>
    public bool HasChanged(string targetId, string contentHash)
    {
        lock (_lock)
        {
            if (_state.Policies.TryGetValue(targetId, out var p)
                && p.ContentHash == contentHash
                && IsSuccessfulStatus(p.Status))
                return false;
            if (_state.Software.TryGetValue(targetId, out var s)
                && s.ContentHash == contentHash
                && IsSuccessfulStatus(s.Status))
                return false;
            return true;
        }
    }

    // "skipped" is treated as terminal because the document had nothing
    // applicable on this host; re-running the same content will produce
    // the same skip. Anything else (e.g. "failed") forces a retry.
    private static bool IsSuccessfulStatus(string status)
        => status == "ok" || status == "skipped";

    public void RecordApplied(
        string targetId, string version, string contentHash, string status, bool isSoftware)
    {
        RecordApplied(targetId, version, contentHash, status, isSoftware, hostState: null);
    }

    /// <summary>
    /// AD-04 overload: also stamp <see cref="AppliedEntry.HostStateAtApply"/>
    /// so the worker can detect a JoinState transition and force a
    /// re-evaluation when the previously-applied entry was written
    /// under a different host state.
    /// </summary>
    public void RecordApplied(
        string targetId, string version, string contentHash, string status,
        bool isSoftware, JoinState? hostState)
    {
        lock (_lock)
        {
            var entry = new AppliedEntry
            {
                Version = version,
                ContentHash = contentHash,
                AppliedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Status = status,
                HostStateAtApply = hostState?.ToString() ?? string.Empty,
            };
            if (isSoftware)
                _state.Software[targetId] = entry;
            else
                _state.Policies[targetId] = entry;
            WriteToDisk(_state);
        }
    }

    public IReadOnlySet<string> GetManagedItems(string category)
    {
        lock (_lock)
        {
            if (_state.ManagedItems.TryGetValue(category, out var items))
                return new HashSet<string>(items.Keys, StringComparer.OrdinalIgnoreCase);
            return new HashSet<string>();
        }
    }

    public JoinState? GetHostStateAtApply(string targetId, bool isSoftware)
    {
        lock (_lock)
        {
            var bucket = isSoftware ? _state.Software : _state.Policies;
            if (!bucket.TryGetValue(targetId, out var entry))
                return null;
            if (string.IsNullOrEmpty(entry.HostStateAtApply))
                return null;
            return Enum.TryParse<JoinState>(entry.HostStateAtApply, out var js)
                ? js
                : null;
        }
    }

    public void RecordManagedItems(
        string category,
        IReadOnlySet<string> desired,
        JoinState joinState,
        bool auditMode,
        string? reason)
    {
        lock (_lock)
        {
            if (!_state.ManagedItems.TryGetValue(category, out var bucket))
            {
                bucket = new Dictionary<string, ManagedItemRecord>(StringComparer.OrdinalIgnoreCase);
                _state.ManagedItems[category] = bucket;
            }

            var now = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var hostName = joinState.ToString();

            // Upsert every desired item.
            foreach (var key in desired)
            {
                if (!bucket.TryGetValue(key, out var rec))
                {
                    rec = new ManagedItemRecord();
                    bucket[key] = rec;
                }
                rec.LastOutcome = auditMode ? "audit" : "applied";
                rec.LastReason = reason;
                rec.HostStateAtApply = hostName;
                // A later workgroup-mode pass that re-lists a previously-frozen
                // item must clear the freeze so the inventory reflects the
                // active management semantics again.
                if (!auditMode)
                    rec.AuditFrozen = false;
                rec.UpdatedAt = now;
            }

            // Reconcile items present-but-not-desired.
            var stale = bucket.Keys
                .Where(k => !desired.Contains(k))
                .ToList();
            foreach (var key in stale)
            {
                if (auditMode)
                {
                    var rec = bucket[key];
                    rec.AuditFrozen = true;
                    rec.LastOutcome = "audit";
                    rec.LastReason = AppliedReason.Combine(
                        reason ?? AppliedReason.AuditDueToUnknownHostState,
                        AppliedReason.WouldCleanStale);
                    rec.HostStateAtApply = hostName;
                    rec.UpdatedAt = now;
                }
                else
                {
                    bucket.Remove(key);
                }
            }

            WriteToDisk(_state);
        }
    }

    private AppliedState LoadFromDisk()
    {
        if (!File.Exists(_path))
            return new AppliedState();
        try
        {
            var json = File.ReadAllText(_path);
            return JsonSerializer.Deserialize<AppliedState>(json) ?? new AppliedState();
        }
        catch
        {
            // Corrupt file — start fresh. A future version could
            // rotate the corrupt file for forensics.
            return new AppliedState();
        }
    }

    private void WriteToDisk(AppliedState state)
    {
        var json = JsonSerializer.Serialize(state, JsonOpts);
        // Atomic-ish write: write to a temp file, then rename.
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, json);
        // L-16 (security review): apply the restricted DACL to the temp
        // file BEFORE the rename. File.Move on the same volume is a
        // metadata rename that preserves the source's DACL, so the
        // final file never observably exists with an inherited ACL.
        // Fail closed: if ACL application fails on Windows, the write
        // is aborted before the rename so applied-state.json is never
        // left in an under-protected state.
        try
        {
            RestrictAccessToSystem(tmp);
        }
        catch
        {
            try { File.Delete(tmp); } catch { /* best-effort */ }
            throw;
        }
        File.Move(tmp, _path, overwrite: true);
    }

    // L-16 (security review): applied-state.json previously inherited the
    // parent directory's ACL. A local admin-equivalent user with write
    // access to the state dir could tamper with it and mislead the agent's
    // reconciliation (e.g., mark a policy as already-applied so the real
    // policy never runs). Set an explicit, non-inherited DACL that grants
    // only SYSTEM and the local Administrators group.
    //
    // Throws on Windows if ACL application fails so the write is aborted
    // before the file becomes visible at its final path. No-op on other
    // platforms (non-Windows has no meaningful NTFS DACL model to enforce
    // here and never ships the policy agent in production).
    private static void RestrictAccessToSystem(string path)
    {
        if (!OperatingSystem.IsWindows())
            return;
        SetWindowsDacl(path);
    }

    [SupportedOSPlatform("windows")]
    private static void SetWindowsDacl(string path)
    {
        var info = new FileInfo(path);
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.SetOwner(system);
        security.SetGroup(system);
        security.AddAccessRule(new FileSystemAccessRule(
            system, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            admins, FileSystemRights.FullControl, AccessControlType.Allow));

        info.SetAccessControl(security);
    }
}

/// <summary>
/// Backward-compat reader for <see cref="AppliedState.ManagedItems"/>.
/// Pre-AD-04 builds wrote <c>{ "category": ["item1","item2"] }</c>; the
/// new shape is <c>{ "category": { "item1": {ManagedItemRecord}, ... } }</c>.
/// On read, legacy array entries are migrated to records with
/// <see cref="ManagedItemRecord.HostStateAtApply"/> = <c>"Unknown"</c>,
/// <see cref="ManagedItemRecord.AuditFrozen"/> = <c>false</c>, and
/// <see cref="ManagedItemRecord.LastOutcome"/> = <c>"legacy"</c>. The
/// next <see cref="AppliedStateStore.RecordManagedItems"/> call rewrites
/// the bucket in the new shape.
/// </summary>
internal sealed class ManagedItemsConverter
    : JsonConverter<Dictionary<string, Dictionary<string, ManagedItemRecord>>>
{
    public override Dictionary<string, Dictionary<string, ManagedItemRecord>> Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var result = new Dictionary<string, Dictionary<string, ManagedItemRecord>>();
        if (reader.TokenType == JsonTokenType.Null)
            return result;
        if (reader.TokenType != JsonTokenType.StartObject)
            throw new JsonException("expected object for managed_items");

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
                return result;
            if (reader.TokenType != JsonTokenType.PropertyName)
                throw new JsonException("expected property name in managed_items");
            var category = reader.GetString() ?? string.Empty;
            reader.Read();

            var bucket = new Dictionary<string, ManagedItemRecord>(StringComparer.OrdinalIgnoreCase);
            if (reader.TokenType == JsonTokenType.StartArray)
            {
                // Legacy shape: array of item keys.
                while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                {
                    if (reader.TokenType != JsonTokenType.String)
                        throw new JsonException("expected string in legacy managed_items array");
                    var key = reader.GetString();
                    if (key is not null)
                    {
                        bucket[key] = new ManagedItemRecord
                        {
                            LastOutcome = "legacy",
                            LastReason = null,
                            HostStateAtApply = nameof(JoinState.Unknown),
                            AuditFrozen = false,
                            UpdatedAt = 0,
                        };
                    }
                }
            }
            else if (reader.TokenType == JsonTokenType.StartObject)
            {
                // New shape: object keyed by item id.
                while (reader.Read() && reader.TokenType != JsonTokenType.EndObject)
                {
                    if (reader.TokenType != JsonTokenType.PropertyName)
                        throw new JsonException("expected item key in managed_items bucket");
                    var key = reader.GetString() ?? string.Empty;
                    reader.Read();
                    var record = JsonSerializer.Deserialize<ManagedItemRecord>(ref reader, options)
                                 ?? new ManagedItemRecord();
                    bucket[key] = record;
                }
            }
            else
            {
                throw new JsonException(
                    $"unexpected token {reader.TokenType} for managed_items category '{category}'");
            }

            result[category] = bucket;
        }

        throw new JsonException("unterminated managed_items object");
    }

    public override void Write(
        Utf8JsonWriter writer,
        Dictionary<string, Dictionary<string, ManagedItemRecord>> value,
        JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        foreach (var (category, bucket) in value)
        {
            writer.WritePropertyName(category);
            writer.WriteStartObject();
            foreach (var (key, record) in bucket)
            {
                writer.WritePropertyName(key);
                JsonSerializer.Serialize(writer, record, options);
            }
            writer.WriteEndObject();
        }
        writer.WriteEndObject();
    }
}
