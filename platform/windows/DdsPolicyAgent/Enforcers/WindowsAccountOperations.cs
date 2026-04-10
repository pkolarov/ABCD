// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Production implementation of <see cref="IAccountOperations"/>
/// using Win32 APIs. Phase E stub — method bodies throw
/// <see cref="PlatformNotSupportedException"/> until the real
/// netapi32 P/Invoke or DirectoryServices.AccountManagement calls
/// are wired in the Windows VM.
///
/// The full implementation requires testing on a real Windows box
/// because the P/Invoke signatures and error handling depend on
/// the runtime environment (LocalSystem, account policies, etc.).
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsAccountOperations : IAccountOperations
{
    public bool UserExists(string username)
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");

    public void CreateUser(string username, string? fullName, string? description)
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");

    public void DeleteUser(string username)
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");

    public void DisableUser(string username)
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");

    public void EnableUser(string username)
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");

    public bool IsEnabled(string username)
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");

    public IReadOnlyList<string> GetGroups(string username)
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");

    public void AddToGroup(string username, string group)
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");

    public void SetPasswordNeverExpires(string username, bool neverExpires)
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");

    public bool IsDomainJoined()
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");
}
