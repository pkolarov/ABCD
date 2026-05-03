// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Thin abstraction over Windows SCM so the service enforcer can be
/// unit-tested on any platform. The production implementation
/// (<see cref="WindowsServiceOperations"/>) calls
/// <c>System.ServiceProcess.ServiceController</c>; tests inject
/// <see cref="InMemoryServiceOperations"/>.
/// </summary>
public interface IServiceOperations
{
    /// <summary>Does a service with <paramref name="name"/> exist in the SCM?</summary>
    bool ServiceExists(string name);

    /// <summary>
    /// Returns the current start-type string for the service, e.g.
    /// "Automatic", "Manual", "Disabled". Returns <c>null</c> if the
    /// service does not exist.
    /// </summary>
    string? GetStartType(string name);

    /// <summary>
    /// Change the service's start type. <paramref name="startType"/>
    /// must be one of: "Boot", "System", "Automatic", "Manual",
    /// "Disabled". Throws if the service does not exist.
    /// </summary>
    void SetStartType(string name, string startType);

    /// <summary>
    /// Returns the current run-state string, e.g. "Running",
    /// "Stopped", "Paused". Returns <c>null</c> if the service does
    /// not exist.
    /// </summary>
    string? GetRunState(string name);

    /// <summary>
    /// Start the service. No-op if already running. Throws if the
    /// service does not exist or cannot be started.
    /// </summary>
    void StartService(string name);

    /// <summary>
    /// Stop the service. No-op if already stopped. Throws if the
    /// service does not exist or cannot be stopped.
    /// </summary>
    void StopService(string name);
}
