// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Production implementation of <see cref="IPasswordPolicyOperations"/>
/// using secedit or NetUserModalsSet. Stub — real Win32 calls will
/// be wired during VM testing.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsPasswordPolicyOperations : IPasswordPolicyOperations
{
    public PasswordPolicyState GetCurrent()
        => throw new NotImplementedException("Requires Windows — will be implemented in VM testing phase");

    public void SetMinLength(uint value)
        => throw new NotImplementedException("Requires Windows");

    public void SetMaxAgeDays(uint value)
        => throw new NotImplementedException("Requires Windows");

    public void SetMinAgeDays(uint value)
        => throw new NotImplementedException("Requires Windows");

    public void SetHistorySize(uint value)
        => throw new NotImplementedException("Requires Windows");

    public void SetComplexityRequired(bool value)
        => throw new NotImplementedException("Requires Windows");

    public void SetLockoutThreshold(uint value)
        => throw new NotImplementedException("Requires Windows");

    public void SetLockoutDurationMinutes(uint value)
        => throw new NotImplementedException("Requires Windows");
}
