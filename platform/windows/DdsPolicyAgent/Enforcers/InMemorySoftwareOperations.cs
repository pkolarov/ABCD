// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// In-memory test double for <see cref="ISoftwareOperations"/>.
/// Tracks installed packages for assertion in unit tests.
/// </summary>
public sealed class InMemorySoftwareOperations : ISoftwareOperations
{
    private readonly HashSet<string> _installed = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _downloadedFiles = new();

    /// <summary>Whether to simulate SHA-256 verification failure.</summary>
    public bool SimulateHashMismatch { get; set; }

    public Task<string> DownloadAndVerifyAsync(
        string sourceUrl, string expectedSha256, CancellationToken ct = default)
    {
        if (SimulateHashMismatch)
            throw new InvalidOperationException(
                $"SHA-256 mismatch: expected {expectedSha256}, got 0000000000000000");

        var fakePath = Path.Combine(Path.GetTempPath(), $"dds-fake-{Guid.NewGuid():N}.msi");
        _downloadedFiles[sourceUrl] = fakePath;
        return Task.FromResult(fakePath);
    }

    public int InstallMsi(string msiPath, string? extraArgs = null)
    {
        _installed.Add(msiPath);
        return 0;
    }

    public int UninstallMsi(string productCode)
    {
        _installed.Remove(productCode);
        return 0;
    }

    public int InstallExe(string exePath, string silentArgs)
    {
        _installed.Add(exePath);
        return 0;
    }

    public bool IsInstalled(string packageId)
        => _installed.Contains(packageId);

    public string? GetUninstallString(string packageId)
        => _installed.Contains(packageId) ? $"msiexec /x {packageId}" : null;

    /// <summary>Mark a package as installed (for test setup).</summary>
    public void SeedInstalled(string packageId) => _installed.Add(packageId);
}
