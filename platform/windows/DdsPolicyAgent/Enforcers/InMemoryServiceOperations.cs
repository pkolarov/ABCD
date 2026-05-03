// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// In-memory test double for <see cref="IServiceOperations"/>.
/// Simulates Windows SCM service management in a dictionary.
/// </summary>
public sealed class InMemoryServiceOperations : IServiceOperations
{
    public sealed class ServiceState
    {
        public string Name { get; set; } = string.Empty;
        public string StartType { get; set; } = "Automatic";
        public string RunState { get; set; } = "Stopped";
    }

    private readonly Dictionary<string, ServiceState> _services =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    /// <summary>Pre-seed a service for test setup.</summary>
    public void Seed(string name, string startType = "Automatic", string runState = "Stopped")
    {
        lock (_lock)
        {
            _services[name] = new ServiceState
            {
                Name = name,
                StartType = startType,
                RunState = runState,
            };
        }
    }

    public bool ServiceExists(string name)
    {
        lock (_lock) { return _services.ContainsKey(name); }
    }

    public string? GetStartType(string name)
    {
        lock (_lock)
        {
            return _services.TryGetValue(name, out var s) ? s.StartType : null;
        }
    }

    public void SetStartType(string name, string startType)
    {
        lock (_lock)
        {
            if (!_services.TryGetValue(name, out var s))
                throw new InvalidOperationException($"Service '{name}' does not exist");
            s.StartType = startType;
        }
    }

    public string? GetRunState(string name)
    {
        lock (_lock)
        {
            return _services.TryGetValue(name, out var s) ? s.RunState : null;
        }
    }

    public void StartService(string name)
    {
        lock (_lock)
        {
            if (!_services.TryGetValue(name, out var s))
                throw new InvalidOperationException($"Service '{name}' does not exist");
            s.RunState = "Running";
        }
    }

    public void StopService(string name)
    {
        lock (_lock)
        {
            if (!_services.TryGetValue(name, out var s))
                throw new InvalidOperationException($"Service '{name}' does not exist");
            s.RunState = "Stopped";
        }
    }

    // --- test helpers ---

    public ServiceState? Peek(string name)
    {
        lock (_lock)
        {
            return _services.TryGetValue(name, out var s) ? s : null;
        }
    }

    public int Count { get { lock (_lock) { return _services.Count; } } }
}
