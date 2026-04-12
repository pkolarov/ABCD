// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using System.Text.Json.Serialization;

namespace DDS.PolicyAgent.MacOS.State;

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

    [JsonPropertyName("software")]
    public Dictionary<string, AppliedEntry> Software { get; set; } = new();
}

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
            return new AppliedState();
        }
    }

    private void WriteToDisk(AppliedState state)
    {
        var json = JsonSerializer.Serialize(state, JsonOpts);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, json);
        File.Move(tmp, _path, overwrite: true);
    }
}
