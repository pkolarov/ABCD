// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using System.ServiceProcess;
using Microsoft.Win32;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Production implementation of <see cref="IServiceOperations"/> that
/// calls <c>System.ServiceProcess.ServiceController</c> and the
/// Windows registry for start-type writes. Only instantiated on
/// Windows — the DI container guards this with a platform check.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsServiceOperations : IServiceOperations
{
    private static readonly TimeSpan WaitTimeout = TimeSpan.FromSeconds(30);

    public bool ServiceExists(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            _ = sc.Status; // triggers the SCM query; throws if not found
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    public string? GetStartType(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            return sc.StartType switch
            {
                ServiceStartMode.Boot => "Boot",
                ServiceStartMode.System => "System",
                ServiceStartMode.Automatic => "Automatic",
                ServiceStartMode.Manual => "Manual",
                ServiceStartMode.Disabled => "Disabled",
                _ => sc.StartType.ToString(),
            };
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    public void SetStartType(string name, string startType)
    {
        // ServiceController.StartType is read-only; change it via the
        // registry key HKLM\SYSTEM\CurrentControlSet\Services\<name>\Start.
        var regValue = startType switch
        {
            "Boot" => 0,
            "System" => 1,
            "Automatic" => 2,
            "Manual" => 3,
            "Disabled" => 4,
            _ => throw new ArgumentException($"Unknown start type: {startType}", nameof(startType)),
        };

        using var key = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\{name}", writable: true)
            ?? throw new InvalidOperationException($"Service '{name}' not found in registry");

        key.SetValue("Start", regValue, RegistryValueKind.DWord);
    }

    public string? GetRunState(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            return sc.Status switch
            {
                ServiceControllerStatus.Running => "Running",
                ServiceControllerStatus.Stopped => "Stopped",
                ServiceControllerStatus.Paused => "Paused",
                ServiceControllerStatus.StartPending => "StartPending",
                ServiceControllerStatus.StopPending => "StopPending",
                ServiceControllerStatus.PausePending => "PausePending",
                ServiceControllerStatus.ContinuePending => "ContinuePending",
                _ => sc.Status.ToString(),
            };
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    public void StartService(string name)
    {
        using var sc = new ServiceController(name);
        sc.Refresh();
        if (sc.Status == ServiceControllerStatus.Running)
            return;
        sc.Start();
        sc.WaitForStatus(ServiceControllerStatus.Running, WaitTimeout);
    }

    public void StopService(string name)
    {
        using var sc = new ServiceController(name);
        sc.Refresh();
        if (sc.Status == ServiceControllerStatus.Stopped)
            return;
        if (sc.CanStop)
        {
            sc.Stop();
            sc.WaitForStatus(ServiceControllerStatus.Stopped, WaitTimeout);
        }
    }

    public string? GetDisplayName(string name)
    {
        try
        {
            using var sc = new ServiceController(name);
            return sc.DisplayName;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    public void SetDisplayName(string name, string displayName)
    {
        // ServiceController.DisplayName is read-only; write via the
        // registry key HKLM\SYSTEM\CurrentControlSet\Services\<name>\DisplayName.
        using var key = Registry.LocalMachine.OpenSubKey(
            $@"SYSTEM\CurrentControlSet\Services\{name}", writable: true)
            ?? throw new InvalidOperationException($"Service '{name}' not found in registry");

        key.SetValue("DisplayName", displayName, RegistryValueKind.String);
    }
}
