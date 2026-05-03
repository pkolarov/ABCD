// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using System.Text.Json.Serialization;

namespace DDS.PolicyAgent.Linux.State;

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

public sealed class AppliedState
{
    [JsonPropertyName("policies")]
    public Dictionary<string, AppliedEntry> Policies { get; set; } = new();

    /// Usernames that were created by the DDS agent. Delete is only allowed for these.
    [JsonPropertyName("managed_usernames")]
    public HashSet<string> ManagedUsernames { get; set; } = new(StringComparer.Ordinal);

    /// Absolute file paths that were written by the DDS agent.
    [JsonPropertyName("managed_paths")]
    public HashSet<string> ManagedPaths { get; set; } = new(StringComparer.Ordinal);

    /// Package names that were installed by the DDS agent.
    [JsonPropertyName("managed_packages")]
    public HashSet<string> ManagedPackages { get; set; } = new(StringComparer.Ordinal);
}

public interface IAppliedStateStore
{
    AppliedState Load();
    bool HasChanged(string targetId, string contentHash);
    void RecordApplied(string targetId, string version, string contentHash, string status);
    void RecordManagedUsername(string username);
    void RecordManagedPath(string path);
    void RecordManagedPackage(string packageName);
    void RemoveManagedUsername(string username);
    void RemoveManagedPath(string path);
    void RemoveManagedPackage(string packageName);
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

    public bool HasChanged(string targetId, string contentHash)
    {
        lock (_lock)
        {
            return !_state.Policies.TryGetValue(targetId, out var p)
                || p.ContentHash != contentHash
                || !IsTerminalStatus(p.Status);
        }
    }

    public void RecordApplied(string targetId, string version, string contentHash, string status)
    {
        lock (_lock)
        {
            _state.Policies[targetId] = new AppliedEntry
            {
                Version     = version,
                ContentHash = contentHash,
                AppliedAt   = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Status      = status,
            };
            WriteToDisk(_state);
        }
    }

    public void RecordManagedUsername(string username)
    {
        lock (_lock)
        {
            if (_state.ManagedUsernames.Add(username))
                WriteToDisk(_state);
        }
    }

    public void RecordManagedPath(string path)
    {
        lock (_lock)
        {
            if (_state.ManagedPaths.Add(path))
                WriteToDisk(_state);
        }
    }

    public void RecordManagedPackage(string packageName)
    {
        lock (_lock)
        {
            if (_state.ManagedPackages.Add(packageName))
                WriteToDisk(_state);
        }
    }

    public void RemoveManagedUsername(string username)
    {
        lock (_lock)
        {
            if (_state.ManagedUsernames.Remove(username))
                WriteToDisk(_state);
        }
    }

    public void RemoveManagedPath(string path)
    {
        lock (_lock)
        {
            if (_state.ManagedPaths.Remove(path))
                WriteToDisk(_state);
        }
    }

    public void RemoveManagedPackage(string packageName)
    {
        lock (_lock)
        {
            if (_state.ManagedPackages.Remove(packageName))
                WriteToDisk(_state);
        }
    }

    private static bool IsTerminalStatus(string status)
        => status == "ok" || status == "skipped";

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
            return new AppliedState();
        }
    }

    private void WriteToDisk(AppliedState state)
    {
        var json = JsonSerializer.Serialize(state, JsonOpts);
        var tmp  = _path + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, _path, overwrite: true);
    }
}
