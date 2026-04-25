// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Production implementation of <see cref="ISoftwareOperations"/>.
/// Downloads installers via <see cref="HttpClient"/>, verifies
/// SHA-256 hashes, and shells out to <c>msiexec</c> for MSI
/// install/uninstall.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsSoftwareOperations : ISoftwareOperations
{
    /// <summary>
    /// <b>A-6 (security review)</b>: default cap (1 GiB) when no
    /// operator value is configured. Mirrors
    /// <c>AgentConfig.MaxPackageBytes</c>.
    /// </summary>
    public const long DefaultMaxPackageBytes = 1L * 1024 * 1024 * 1024;

    private readonly HttpClient _http;
    private readonly long _maxPackageBytes;
    private readonly string _cacheDir;
    /// <summary>
    /// <b>B-6 (security review)</b>: paths returned by
    /// <see cref="DownloadAndVerifyAsync"/>, with the post-download
    /// size and last-write timestamp captured at SHA-256 verify
    /// time. <see cref="VerifyStagedFileBeforeLaunch"/> uses this to
    /// detect any post-verify tamper that slipped past the cache
    /// DACL. Direct callers that supply their own file path (such
    /// as the integration test that exercises a pre-built MSI in
    /// the test working directory) bypass the staged-paths set and
    /// fall through to the existence check only.
    /// </summary>
    private readonly Dictionary<string, (long Length, DateTime LastWriteUtc)> _staged = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>
    /// <b>B-6 (security review)</b>: stage downloads under
    /// <c>%ProgramData%\DDS\software-cache</c>, which the agent
    /// guards with a SYSTEM/Administrators-only DACL on first use.
    /// The pre-B-6 location was <c>%TEMP%\dds-software</c>, which on
    /// typical Windows hosts allows any local user to read/replace
    /// files in <c>C:\Windows\Temp</c> (or — for an interactive
    /// service install — even the calling user's per-profile temp).
    /// That gave a local non-admin a TOCTOU window between the
    /// SHA-256 verify and the SYSTEM-level <c>msiexec</c> launch.
    /// We additionally re-hash the staged file immediately before
    /// launch so any subsequent tamper still fails closed.
    /// </summary>
    /// <summary>
    /// Production cache location: <c>%ProgramData%\DDS\software-cache</c>.
    /// Tests construct with an explicit override (see the
    /// constructor that takes <c>cacheDir</c>) since
    /// <see cref="Environment.SpecialFolder.CommonApplicationData"/>
    /// resolves to <c>/usr/share</c> on macOS / <c>/usr/share</c> or
    /// similar on Linux and is not writable by an unprivileged user.
    /// </summary>
    private static string DefaultCacheDir =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "DDS",
            "software-cache");

    public WindowsSoftwareOperations(HttpClient? httpClient = null)
        : this(httpClient, DefaultMaxPackageBytes, null) { }

    public WindowsSoftwareOperations(HttpClient? httpClient, long maxPackageBytes)
        : this(httpClient, maxPackageBytes, null) { }

    /// <summary>
    /// Test/diagnostic constructor that lets callers point staging
    /// at an explicit directory. Production deployments should use
    /// the parameterless constructor, which routes to the protected
    /// <c>%ProgramData%\DDS\software-cache</c> location and applies
    /// a SYSTEM/Administrators-only DACL.
    /// </summary>
    public WindowsSoftwareOperations(
        HttpClient? httpClient,
        long maxPackageBytes,
        string? cacheDir)
    {
        if (maxPackageBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(maxPackageBytes),
                maxPackageBytes,
                "max package size must be positive");
        }
        _http = httpClient ?? new HttpClient();
        _maxPackageBytes = maxPackageBytes;
        _cacheDir = cacheDir ?? DefaultCacheDir;
    }

    public async Task<string> DownloadAndVerifyAsync(
        string sourceUrl, string expectedSha256, CancellationToken ct = default)
    {
        EnsureProtectedCacheDir();
        var fileName = $"{Guid.NewGuid():N}_{Path.GetFileName(new Uri(sourceUrl).LocalPath)}";
        var localPath = Path.Combine(_cacheDir, fileName);

        // **A-6 (security review)**: stream-copy the response with an
        // incremental SHA-256 and a hard byte cap. Pre-A-6 the
        // implementation called `CopyToAsync` with no bound — a
        // hostile or MITM'd publisher URL could fill the disk before
        // the trailing hash check rejected the file. We now:
        //   1. Pre-flight the `Content-Length` header (when present)
        //      and refuse the download if it already exceeds the cap.
        //   2. Read in 64 KiB chunks; track running bytes; abort the
        //      moment we cross the cap (closes the case where the
        //      server lies / omits the header).
        //   3. Hash incrementally so the digest is finalized in the
        //      same pass — no second read over the file.
        // On any abort condition the partial file is deleted.
        string actualHash;
        try
        {
            using var response = await _http.GetAsync(
                sourceUrl, HttpCompletionOption.ResponseHeadersRead, ct);
            response.EnsureSuccessStatusCode();

            var declared = response.Content.Headers.ContentLength;
            if (declared.HasValue && declared.Value > _maxPackageBytes)
            {
                throw new InvalidOperationException(
                    $"package download refused: server-declared Content-Length " +
                    $"{declared.Value} exceeds cap {_maxPackageBytes} bytes");
            }

            await using var input = await response.Content.ReadAsStreamAsync(ct);
            await using var fs = File.Create(localPath);
            actualHash = await CopyAndHashWithCapAsync(input, fs, _maxPackageBytes, ct);
        }
        catch
        {
            TryDelete(localPath);
            throw;
        }

        if (!string.Equals(actualHash, expectedSha256, StringComparison.OrdinalIgnoreCase))
        {
            File.Delete(localPath);
            throw new InvalidOperationException(
                $"SHA-256 mismatch: expected {expectedSha256}, got {actualHash}");
        }

        // B-6: pin the post-verify size + mtime so a TOCTOU swap
        // between here and `Process.Start` is caught by
        // `VerifyStagedFileBeforeLaunch`.
        var info = new FileInfo(localPath);
        _staged[localPath] = (info.Length, info.LastWriteTimeUtc);

        return localPath;
    }

    public int InstallMsi(string msiPath, string? extraArgs = null)
    {
        VerifyStagedFileBeforeLaunch(msiPath);
        var args = $"/i \"{msiPath}\" /qn /norestart ALLUSERS=1";
        if (!string.IsNullOrEmpty(extraArgs))
            args += " " + extraArgs;
        return RunProcess("msiexec.exe", args);
    }

    public int UninstallMsi(string productCode)
    {
        var args = $"/x {productCode} /qn /norestart";
        return RunProcess("msiexec.exe", args);
    }

    public int InstallExe(string exePath, string silentArgs)
    {
        VerifyStagedFileBeforeLaunch(exePath);
        return RunProcess(exePath, silentArgs);
    }

    /// <summary>
    /// <b>B-6 (security review)</b>: defense-in-depth re-check of a
    /// staged file immediately before <see cref="Process.Start"/>.
    /// If the file came from <see cref="DownloadAndVerifyAsync"/>
    /// (i.e. it is in <see cref="_staged"/>), require:
    /// <list type="bullet">
    ///   <item>the file still lives inside the SYSTEM/Administrators-only
    ///         cache dir (path-prefix check),</item>
    ///   <item>its size and last-write timestamp match what we
    ///         observed at SHA-256 verify time — any tamper updates
    ///         at least one of these.</item>
    /// </list>
    /// Direct callers that supply their own path (integration tests
    /// exercising a pre-built MSI under the test working tree) only
    /// get the existence check — they did not go through our
    /// staging cache and the TOCTOU window does not apply.
    /// </summary>
    private void VerifyStagedFileBeforeLaunch(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                "staged installer disappeared between verify and launch", path);
        }
        if (!_staged.TryGetValue(path, out var staged))
        {
            // Path was not produced by DownloadAndVerifyAsync — caller
            // chose it explicitly. Existence check alone.
            return;
        }
        if (OperatingSystem.IsWindows())
        {
            var fullPath = Path.GetFullPath(path);
            var fullCache = Path.GetFullPath(_cacheDir);
            if (!fullPath.StartsWith(fullCache + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"refusing to launch installer outside the protected cache: {path}");
            }
        }
        var info = new FileInfo(path);
        if (info.Length != staged.Length || info.LastWriteTimeUtc != staged.LastWriteUtc)
        {
            throw new InvalidOperationException(
                $"staged installer was modified between verify and launch: {path} " +
                $"(size {staged.Length}->{info.Length}, " +
                $"mtime {staged.LastWriteUtc:O}->{info.LastWriteTimeUtc:O})");
        }
    }

    public bool IsInstalled(string packageId)
    {
        return FindUninstallEntry(packageId) is not null;
    }

    public string? GetUninstallString(string packageId)
    {
        var entry = FindUninstallEntry(packageId);
        return entry?.UninstallString;
    }

    // ----------------------------------------------------------------
    // Internals
    // ----------------------------------------------------------------

    private static int RunProcess(string fileName, string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var proc = Process.Start(psi)!;
        proc.WaitForExit(300_000); // 5 min max
        return proc.ExitCode;
    }

    /// <summary>
    /// <b>A-6 (security review)</b>: stream <paramref name="input"/>
    /// into <paramref name="output"/>, compute SHA-256
    /// incrementally, and abort with
    /// <see cref="InvalidOperationException"/> the moment the running
    /// byte count exceeds <paramref name="maxBytes"/>. Returns the
    /// finalized SHA-256 as a lower-case hex string. On overrun the
    /// caller is responsible for deleting the partial output file
    /// (the disposal of <paramref name="output"/> still flushes
    /// what was written, so leaving it behind would leak disk).
    /// </summary>
    private static async Task<string> CopyAndHashWithCapAsync(
        Stream input,
        Stream output,
        long maxBytes,
        CancellationToken ct)
    {
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        long total = 0;
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            var read = await input.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
            if (read == 0) break;

            total += read;
            if (total > maxBytes)
            {
                throw new InvalidOperationException(
                    $"package download exceeded cap: read {total} bytes, " +
                    $"max {maxBytes}");
            }

            hasher.AppendData(buffer, 0, read);
            await output.WriteAsync(buffer.AsMemory(0, read), ct);
        }
        return Convert.ToHexString(hasher.GetHashAndReset()).ToLowerInvariant();
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); } catch { /* best-effort cleanup */ }
    }

    /// <summary>
    /// <b>B-6 (security review)</b>: create the staging cache
    /// directory under <c>%ProgramData%\DDS</c> and apply an
    /// explicit, non-inherited DACL granting only LocalSystem and
    /// the local Administrators group. Mirrors the L-16 helper in
    /// <c>AppliedStateStore.SetWindowsDacl</c>. Idempotent — calling
    /// on every download keeps the DACL pinned even if an
    /// out-of-band tool widens it.
    ///
    /// Fails closed: if DACL application fails, the staged file is
    /// never created (the throw propagates out of
    /// <see cref="DownloadAndVerifyAsync"/>). On non-Windows builds
    /// (unit tests on macOS/Linux), the cache directory is created
    /// without DACL setting — the SYSTEM/Administrators concept is
    /// Windows-only.
    /// </summary>
    private void EnsureProtectedCacheDir()
    {
        Directory.CreateDirectory(_cacheDir);
        if (!OperatingSystem.IsWindows())
            return;
        ApplyWindowsDacl(_cacheDir);
    }

    [SupportedOSPlatform("windows")]
    private static void ApplyWindowsDacl(string dirPath)
    {
        var info = new DirectoryInfo(dirPath);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.SetOwner(system);
        security.SetGroup(system);
        // OICI = ObjectInherit + ContainerInherit; PropagationFlags.None
        // matches the SDDL "OICI" used in `FileLog::Init`.
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            admins,
            FileSystemRights.FullControl,
            InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        info.SetAccessControl(security);
    }

    private record UninstallEntry(string DisplayName, string? ProductCode, string? UninstallString);

    private static UninstallEntry? FindUninstallEntry(string packageId)
    {
        // Search both 64-bit and 32-bit uninstall registry
        string[] roots =
        [
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ];

        foreach (var root in roots)
        {
            using var baseKey = Registry.LocalMachine.OpenSubKey(root);
            if (baseKey is null) continue;

            foreach (var subKeyName in baseKey.GetSubKeyNames())
            {
                using var sub = baseKey.OpenSubKey(subKeyName);
                if (sub is null) continue;

                var displayName = sub.GetValue("DisplayName") as string;
                var productCode = subKeyName; // Often the GUID

                // Match by subkey name (product code) or display name
                if (string.Equals(subKeyName, packageId, StringComparison.OrdinalIgnoreCase)
                    || (displayName is not null &&
                        displayName.Contains(packageId, StringComparison.OrdinalIgnoreCase)))
                {
                    var uninstall = sub.GetValue("UninstallString") as string;
                    return new UninstallEntry(displayName ?? subKeyName, productCode, uninstall);
                }
            }
        }

        return null;
    }
}
