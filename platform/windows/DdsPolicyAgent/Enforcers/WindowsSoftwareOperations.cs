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
    private readonly HttpClient _http;
    private static readonly string TempDir = Path.Combine(Path.GetTempPath(), "dds-software");

    public WindowsSoftwareOperations(HttpClient? httpClient = null)
    {
        _http = httpClient ?? new HttpClient();
    }

    public async Task<string> DownloadAndVerifyAsync(
        string sourceUrl, string expectedSha256, CancellationToken ct = default)
    {
        Directory.CreateDirectory(TempDir);
        var fileName = $"{Guid.NewGuid():N}_{Path.GetFileName(new Uri(sourceUrl).LocalPath)}";
        var localPath = Path.Combine(TempDir, fileName);

        using (var response = await _http.GetAsync(sourceUrl, HttpCompletionOption.ResponseHeadersRead, ct))
        {
            response.EnsureSuccessStatusCode();
            await using var fs = File.Create(localPath);
            await response.Content.CopyToAsync(fs, ct);
        }

        // Verify SHA-256
        var actualHash = await ComputeSha256Async(localPath, ct);
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

    private static async Task<string> ComputeSha256Async(string path, CancellationToken ct)
    {
        await using var fs = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(fs, ct);
        return Convert.ToHexString(hash).ToLowerInvariant();
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
