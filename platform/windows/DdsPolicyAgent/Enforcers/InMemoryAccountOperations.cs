// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// In-memory test double for <see cref="IAccountOperations"/>.
/// Simulates local Windows account management in a dictionary.
/// </summary>
public sealed class InMemoryAccountOperations : IAccountOperations
{
    public sealed class AccountState
    {
        public string Username { get; set; } = string.Empty;
        public string? FullName { get; set; }
        public string? Description { get; set; }
        public bool Enabled { get; set; } = true;
        public HashSet<string> Groups { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public bool PasswordNeverExpires { get; set; }
    }

    private readonly Dictionary<string, AccountState> _accounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    /// <summary>
    /// Simulate domain-joined state. Default: false (workgroup).
    /// Tests can set this to true to exercise the domain-join guard.
    /// </summary>
    public bool SimulateDomainJoined { get; set; }

    public bool UserExists(string username)
    {
        lock (_lock) { return _accounts.ContainsKey(username); }
    }

    public void CreateUser(string username, string? fullName, string? description)
    {
        lock (_lock)
        {
            if (_accounts.ContainsKey(username))
                throw new InvalidOperationException($"User '{username}' already exists");
            _accounts[username] = new AccountState
            {
                Username = username,
                FullName = fullName,
                Description = description,
            };
        }
    }

    public void DeleteUser(string username)
    {
        lock (_lock) { _accounts.Remove(username); }
    }

    public void DisableUser(string username)
    {
        lock (_lock)
        {
            if (_accounts.TryGetValue(username, out var a))
                a.Enabled = false;
        }
    }

    public void EnableUser(string username)
    {
        lock (_lock)
        {
            if (_accounts.TryGetValue(username, out var a))
                a.Enabled = true;
        }
    }

    public bool IsEnabled(string username)
    {
        lock (_lock)
        {
            return _accounts.TryGetValue(username, out var a) && a.Enabled;
        }
    }

    public IReadOnlyList<string> GetGroups(string username)
    {
        lock (_lock)
        {
            return _accounts.TryGetValue(username, out var a)
                ? a.Groups.ToList()
                : [];
        }
    }

    public void AddToGroup(string username, string group)
    {
        lock (_lock)
        {
            if (_accounts.TryGetValue(username, out var a))
                a.Groups.Add(group);
        }
    }

    public void SetPasswordNeverExpires(string username, bool neverExpires)
    {
        lock (_lock)
        {
            if (_accounts.TryGetValue(username, out var a))
                a.PasswordNeverExpires = neverExpires;
        }
    }

    public bool IsDomainJoined() => SimulateDomainJoined;

    // --- test helpers ---

    public AccountState? Peek(string username)
    {
        lock (_lock)
        {
            return _accounts.TryGetValue(username, out var a) ? a : null;
        }
    }

    public int Count { get { lock (_lock) { return _accounts.Count; } } }
}
