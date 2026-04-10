// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// In-memory test double for <see cref="IPasswordPolicyOperations"/>.
/// </summary>
public sealed class InMemoryPasswordPolicyOperations : IPasswordPolicyOperations
{
    private uint _minLength;
    private uint _maxAgeDays = 42;  // Windows default
    private uint _minAgeDays;
    private uint _historySize;
    private bool _complexityRequired;
    private uint _lockoutThreshold;
    private uint _lockoutDurationMinutes;
    private readonly object _lock = new();

    public PasswordPolicyState GetCurrent()
    {
        lock (_lock)
        {
            return new PasswordPolicyState(
                _minLength, _maxAgeDays, _minAgeDays, _historySize,
                _complexityRequired, _lockoutThreshold, _lockoutDurationMinutes);
        }
    }

    public void SetMinLength(uint value) { lock (_lock) _minLength = value; }
    public void SetMaxAgeDays(uint value) { lock (_lock) _maxAgeDays = value; }
    public void SetMinAgeDays(uint value) { lock (_lock) _minAgeDays = value; }
    public void SetHistorySize(uint value) { lock (_lock) _historySize = value; }
    public void SetComplexityRequired(bool value) { lock (_lock) _complexityRequired = value; }
    public void SetLockoutThreshold(uint value) { lock (_lock) _lockoutThreshold = value; }
    public void SetLockoutDurationMinutes(uint value) { lock (_lock) _lockoutDurationMinutes = value; }
}
