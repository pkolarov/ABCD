// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.HostState;

/// <summary>
/// Seam over the Windows directory-join probe so consumers
/// (<see cref="Enforcers.AccountEnforcer"/>, <see cref="Worker"/>)
/// can be unit-tested without a real host. The production
/// implementation is <see cref="WindowsJoinStateProbe"/>; tests
/// use a fake or <see cref="InMemoryJoinStateProbe"/>.
/// </summary>
public interface IJoinStateProbe
{
    /// <summary>
    /// Return the cached <see cref="JoinState"/>. Probing happens
    /// at most once per <see cref="Refresh"/> call (or first call
    /// if not yet primed). Implementations must be thread-safe.
    /// </summary>
    JoinState Detect();

    /// <summary>
    /// Force a fresh probe. The next <see cref="Detect"/> call
    /// returns the new value. Re-probing is otherwise driven by
    /// the production probe's optional periodic refresh.
    /// </summary>
    void Refresh();
}
