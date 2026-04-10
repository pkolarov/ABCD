// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Represents the current local password policy state. All fields
/// nullable — null means "couldn't read" (not "unconfigured").
/// </summary>
public sealed record PasswordPolicyState(
    uint? MinLength,
    uint? MaxAgeDays,
    uint? MinAgeDays,
    uint? HistorySize,
    bool? ComplexityRequired,
    uint? LockoutThreshold,
    uint? LockoutDurationMinutes);

/// <summary>
/// Thin abstraction over local password policy manipulation so the
/// enforcer can be unit-tested on any platform. The production
/// implementation uses <c>secedit</c> or <c>NetUserModalsSet</c>;
/// tests inject <see cref="InMemoryPasswordPolicyOperations"/>.
/// </summary>
public interface IPasswordPolicyOperations
{
    /// <summary>Read the current local password policy.</summary>
    PasswordPolicyState GetCurrent();

    /// <summary>Set minimum password length.</summary>
    void SetMinLength(uint value);

    /// <summary>Set maximum password age in days. 0 = never expires.</summary>
    void SetMaxAgeDays(uint value);

    /// <summary>Set minimum password age in days.</summary>
    void SetMinAgeDays(uint value);

    /// <summary>Set password history count.</summary>
    void SetHistorySize(uint value);

    /// <summary>Enable or disable Windows complexity requirements.</summary>
    void SetComplexityRequired(bool value);

    /// <summary>Set account lockout threshold. 0 = disabled.</summary>
    void SetLockoutThreshold(uint value);

    /// <summary>Set lockout duration in minutes.</summary>
    void SetLockoutDurationMinutes(uint value);
}
