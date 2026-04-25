// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.HostState;

/// <summary>
/// In-memory test double for <see cref="IJoinStateProbe"/>. Also
/// used as the non-Windows fallback in <c>Program.cs</c> so the
/// agent's host build works on macOS/Linux dev machines.
/// </summary>
public sealed class InMemoryJoinStateProbe : IJoinStateProbe
{
    private JoinState _current;

    public InMemoryJoinStateProbe(JoinState initial = JoinState.Workgroup)
    {
        _current = initial;
    }

    /// <summary>
    /// Set the value returned by the next <see cref="Detect"/>
    /// call. Tests use this to simulate host-state transitions.
    /// </summary>
    public JoinState Current
    {
        get { lock (this) return _current; }
        set { lock (this) _current = value; }
    }

    public JoinState Detect()
    {
        lock (this) return _current;
    }

    public void Refresh() { /* no-op — value is set explicitly */ }
}
