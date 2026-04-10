// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Thin abstraction over Win32 local account management so the
/// enforcer can be unit-tested on any platform. The production
/// implementation calls netapi32 / DirectoryServices.AccountManagement;
/// tests inject <see cref="InMemoryAccountOperations"/>.
/// </summary>
public interface IAccountOperations
{
    /// <summary>Does the local user account exist?</summary>
    bool UserExists(string username);

    /// <summary>Create a local user account with a random password.</summary>
    void CreateUser(string username, string? fullName, string? description);

    /// <summary>Delete a local user account.</summary>
    void DeleteUser(string username);

    /// <summary>Disable a local user account (keep profile).</summary>
    void DisableUser(string username);

    /// <summary>Re-enable a previously disabled account.</summary>
    void EnableUser(string username);

    /// <summary>Is the account currently enabled?</summary>
    bool IsEnabled(string username);

    /// <summary>Get the groups the user is a member of.</summary>
    IReadOnlyList<string> GetGroups(string username);

    /// <summary>
    /// Ensure the user is a member of <paramref name="group"/>.
    /// No-op if already a member.
    /// </summary>
    void AddToGroup(string username, string group);

    /// <summary>Set the PASSWORD_NEVER_EXPIRES flag.</summary>
    void SetPasswordNeverExpires(string username, bool neverExpires);

    /// <summary>
    /// Returns true if the machine is joined to an AD domain.
    /// The enforcer refuses account operations on domain-joined
    /// machines (v1 scope decision).
    /// </summary>
    bool IsDomainJoined();
}
