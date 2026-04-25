// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Diagnostics;
using System.Runtime.Versioning;
using System.Security.Cryptography;
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
    private static readonly string TempDir = Path.Combine(Path.GetTempPath(), "dds-software");

    public WindowsSoftwareOperations(HttpClient? httpClient = null)
        : this(httpClient, DefaultMaxPackageBytes) { }

    public WindowsSoftwareOperations(HttpClient? httpClient, long maxPackageBytes)
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
    }

    public async Task<string> DownloadAndVerifyAsync(
        string sourceUrl, string expectedSha256, CancellationToken ct = default)
    {
        Directory.CreateDirectory(TempDir);
        var fileName = $"{Guid.NewGuid():N}_{Path.GetFileName(new Uri(sourceUrl).LocalPath)}";
        var localPath = Path.Combine(TempDir, fileName);

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

        return localPath;
    }

    public int InstallMsi(string msiPath, string? extraArgs = null)
    {
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
        return RunProcess(exePath, silentArgs);
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
