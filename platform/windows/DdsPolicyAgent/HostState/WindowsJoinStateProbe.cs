// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.HostState;

/// <summary>
/// Production probe. Reads classic AD join via
/// <c>NetGetJoinInformation</c> and Entra/AAD device-join via
/// <c>NetGetAadJoinInformation</c>. Falls back to "no Entra signal"
/// when the latter is missing on older SKUs (the symbol is loaded
/// dynamically via <see cref="GetProcAddress"/>).
///
/// See <c>docs/windows-ad-coexistence-spec.md §2.2</c> for the
/// classification contract this implements.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsJoinStateProbe : IJoinStateProbe, IDisposable
{
    private readonly ILogger<WindowsJoinStateProbe>? _log;
    private readonly object _lock = new();
    private readonly Timer? _refreshTimer;
    private JoinState? _cached;

    /// <summary>
    /// Production constructor. Caller may pass an optional
    /// <paramref name="refreshInterval"/> to enable a background
    /// timer that calls <see cref="Refresh"/> on a schedule.
    /// Tests should pass <see cref="TimeSpan.Zero"/> (the default)
    /// to disable the timer.
    /// </summary>
    public WindowsJoinStateProbe(
        ILogger<WindowsJoinStateProbe>? log = null,
        TimeSpan refreshInterval = default)
    {
        _log = log;
        if (refreshInterval > TimeSpan.Zero)
        {
            _refreshTimer = new Timer(
                _ => Refresh(),
                state: null,
                dueTime: refreshInterval,
                period: refreshInterval);
        }
    }

    public JoinState Detect()
    {
        lock (_lock)
        {
            _cached ??= Probe();
            return _cached.Value;
        }
    }

    public void Refresh()
    {
        var fresh = Probe();
        JoinState? previous;
        lock (_lock)
        {
            previous = _cached;
            _cached = fresh;
        }
        if (previous is not null && previous.Value != fresh)
        {
            _log?.LogInformation(
                "JoinState transition: {Previous} -> {Fresh}", previous.Value, fresh);
        }
    }

    public void Dispose()
    {
        _refreshTimer?.Dispose();
    }

    // ----------------------------------------------------------------
    // Probe implementation
    // ----------------------------------------------------------------

    private JoinState Probe()
    {
        var adSignal = ProbeAdSignal();
        var entraSignal = ProbeEntraSignal();

        // Either probe failing in an unexpected way is fail-closed Unknown.
        if (adSignal == AdSignal.ProbeFailed || entraSignal == EntraSignal.ProbeFailed)
            return JoinState.Unknown;

        var hasAd = adSignal == AdSignal.Domain;
        var hasEntraDevice = entraSignal == EntraSignal.DeviceJoined;
        var hasWorkplaceOnly = entraSignal == EntraSignal.WorkplaceJoined;

        if (hasAd && (hasEntraDevice || hasWorkplaceOnly))
            return JoinState.HybridJoined;
        if (hasAd)
            return JoinState.AdJoined;
        if (hasEntraDevice)
            return JoinState.EntraOnlyJoined;

        if (hasWorkplaceOnly)
        {
            // Workplace registration alone does not disable workgroup behavior;
            // log informationally so operators can see why the host classified
            // as workgroup despite some Entra signal.
            _log?.LogInformation("JoinState: workplace_registered_only");
        }

        return JoinState.Workgroup;
    }

    private enum AdSignal { Workgroup, Domain, ProbeFailed }

    private AdSignal ProbeAdSignal()
    {
        IntPtr buffer = IntPtr.Zero;
        try
        {
            int rc = NetGetJoinInformation(null, out buffer, out var status);
            if (rc != 0)
            {
                _log?.LogWarning("NetGetJoinInformation failed: rc={Rc}", rc);
                return AdSignal.ProbeFailed;
            }

            return status switch
            {
                NetJoinStatus.NetSetupDomainName => AdSignal.Domain,
                NetJoinStatus.NetSetupWorkgroupName => AdSignal.Workgroup,
                NetJoinStatus.NetSetupUnjoined => AdSignal.Workgroup,
                NetJoinStatus.NetSetupUnknownStatus => AdSignal.ProbeFailed,
                _ => AdSignal.ProbeFailed,
            };
        }
        catch (Exception ex)
        {
            _log?.LogWarning(ex, "NetGetJoinInformation threw");
            return AdSignal.ProbeFailed;
        }
        finally
        {
            if (buffer != IntPtr.Zero) NetApiBufferFree(buffer);
        }
    }

    private enum EntraSignal { None, DeviceJoined, WorkplaceJoined, ProbeFailed }

    private EntraSignal ProbeEntraSignal()
    {
        IntPtr info = IntPtr.Zero;
        try
        {
            int hr = NetGetAadJoinInformation(null, out info);
            if (hr != 0 /* S_OK */)
            {
                _log?.LogDebug("NetGetAadJoinInformation hr=0x{Hr:X8}", hr);
                return EntraSignal.ProbeFailed;
            }
            if (info == IntPtr.Zero)
            {
                // S_OK with NULL info = no Entra signal, not failure.
                return EntraSignal.None;
            }

            var joinInfo = Marshal.PtrToStructure<DSREG_JOIN_INFO>(info);
            return joinInfo.joinType switch
            {
                DSREG_JOIN_TYPE.DSREG_DEVICE_JOIN => EntraSignal.DeviceJoined,
                DSREG_JOIN_TYPE.DSREG_WORKPLACE_JOIN => EntraSignal.WorkplaceJoined,
                DSREG_JOIN_TYPE.DSREG_UNKNOWN_JOIN => EntraSignal.ProbeFailed,
                _ => EntraSignal.None,
            };
        }
        catch (EntryPointNotFoundException)
        {
            // NetGetAadJoinInformation not present (very old SKU / Server Core
            // without the AAD module). Treat as no Entra signal, not Unknown.
            return EntraSignal.None;
        }
        catch (DllNotFoundException)
        {
            return EntraSignal.None;
        }
        catch (Exception ex)
        {
            _log?.LogWarning(ex, "NetGetAadJoinInformation threw");
            return EntraSignal.ProbeFailed;
        }
        finally
        {
            if (info != IntPtr.Zero) NetFreeAadJoinInformation(info);
        }
    }

    // ----------------------------------------------------------------
    // P/Invoke
    // ----------------------------------------------------------------

    private enum NetJoinStatus
    {
        NetSetupUnknownStatus = 0,
        NetSetupUnjoined,
        NetSetupWorkgroupName,
        NetSetupDomainName,
    }

    private enum DSREG_JOIN_TYPE
    {
        DSREG_UNKNOWN_JOIN = 0,
        DSREG_DEVICE_JOIN = 1,
        DSREG_WORKPLACE_JOIN = 2,
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct DSREG_JOIN_INFO
    {
        public DSREG_JOIN_TYPE joinType;
        public IntPtr pJoinCertificate;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pszDeviceId;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pszIdpDomain;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pszTenantId;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pszJoinUserEmail;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pszTenantDisplayName;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pszMdmEnrollmentUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pszMdmTermsOfUseUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pszMdmComplianceUrl;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pszUserSettingSyncUrl;
        public IntPtr pUserInfo;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetGetJoinInformation(
        string? server, out IntPtr nameBuffer, out NetJoinStatus status);

    [DllImport("netapi32.dll")]
    private static extern int NetApiBufferFree(IntPtr buffer);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetGetAadJoinInformation(
        string? pcszTenantId, out IntPtr ppJoinInfo);

    [DllImport("netapi32.dll")]
    private static extern void NetFreeAadJoinInformation(IntPtr pJoinInfo);
}
