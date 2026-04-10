// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// In-memory implementation of <see cref="IRegistryOperations"/>
/// for testing and non-Windows dev hosts. Stores values in a
/// dictionary keyed by <c>"hive\subkey\valueName"</c>.
///
/// Thread-safe: all mutations go through a lock. Not persistent
/// across process restarts (by design — it's a test double).
/// </summary>
public sealed class InMemoryRegistryOperations : IRegistryOperations
{
    private readonly Dictionary<string, object> _store = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _keys = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public object? GetValue(string hive, string subKey, string? valueName)
    {
        lock (_lock)
        {
            var path = MakePath(hive, subKey, valueName);
            return _store.TryGetValue(path, out var v) ? v : null;
        }
    }

    public void SetValue(string hive, string subKey, string? valueName, object value, RegValueKind kind)
    {
        lock (_lock)
        {
            _keys.Add(MakeKeyPath(hive, subKey));
            _store[MakePath(hive, subKey, valueName)] = value;
        }
    }

    public void DeleteValue(string hive, string subKey, string valueName)
    {
        lock (_lock)
        {
            _store.Remove(MakePath(hive, subKey, valueName));
        }
    }

    public void DeleteKey(string hive, string subKey)
    {
        lock (_lock)
        {
            var keyPath = MakeKeyPath(hive, subKey);
            _keys.Remove(keyPath);
            // Remove all values under this key
            var prefix = keyPath + @"\";
            var toRemove = _store.Keys.Where(k =>
                k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                || k.Equals(keyPath, StringComparison.OrdinalIgnoreCase)).ToList();
            foreach (var k in toRemove)
                _store.Remove(k);
        }
    }

    public bool KeyExists(string hive, string subKey)
    {
        lock (_lock)
        {
            return _keys.Contains(MakeKeyPath(hive, subKey));
        }
    }

    // --- test helpers ---

    /// <summary>Read back a value for test assertions.</summary>
    public object? Peek(string hive, string subKey, string? valueName)
        => GetValue(hive, subKey, valueName);

    /// <summary>How many values are stored.</summary>
    public int Count { get { lock (_lock) { return _store.Count; } } }

    private static string MakeKeyPath(string hive, string subKey)
        => $@"{hive}\{subKey}";

    private static string MakePath(string hive, string subKey, string? valueName)
        => $@"{hive}\{subKey}\{valueName ?? "(Default)"}";
}
