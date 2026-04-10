// SPDX-License-Identifier: MIT OR Apache-2.0

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
    /// (either never seen or content hash changed).
    /// </summary>
    public bool HasChanged(string targetId, string contentHash)
    {
        lock (_lock)
        {
            if (_state.Policies.TryGetValue(targetId, out var p) && p.ContentHash == contentHash)
                return false;
            if (_state.Software.TryGetValue(targetId, out var s) && s.ContentHash == contentHash)
                return false;
            return true;
        }
    }

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
        File.Move(tmp, _path, overwrite: true);
    }
}
