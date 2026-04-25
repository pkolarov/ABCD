// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

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
    /// Items currently managed by DDS, keyed by enforcer category
    /// (e.g. "registry", "accounts", "software"). Used for
    /// reconciliation: items in this set but absent from the current
    /// policy are cleaned up.
    /// </summary>
    [JsonPropertyName("managed_items")]
    public Dictionary<string, HashSet<string>> ManagedItems { get; set; } = new();
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
    /// Get the set of items DDS currently manages for a given category.
    /// Returns an empty set if nothing is tracked yet.
    /// </summary>
    IReadOnlySet<string> GetManagedItems(string category);

    /// <summary>
    /// Replace the managed items for a category with a new set.
    /// </summary>
    void SetManagedItems(string category, IEnumerable<string> items);
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
        lock (_lock)
        {
            var entry = new AppliedEntry
            {
                Version = version,
                ContentHash = contentHash,
                AppliedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Status = status,
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
                return items;
            return new HashSet<string>();
        }
    }

    public void SetManagedItems(string category, IEnumerable<string> items)
    {
        lock (_lock)
        {
            _state.ManagedItems[category] = new HashSet<string>(items);
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
