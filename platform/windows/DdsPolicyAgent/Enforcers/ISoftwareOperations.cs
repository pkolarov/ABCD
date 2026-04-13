// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Thin abstraction over MSI/EXE install/uninstall so the software
/// enforcer can be unit-tested. The production implementation shells
/// out to <c>msiexec</c>; tests inject
/// <see cref="InMemorySoftwareOperations"/>.
/// </summary>
public interface ISoftwareOperations
{
    /// <summary>
    /// Download a file from <paramref name="sourceUrl"/> to a temp
    /// path, verify its SHA-256 hash matches <paramref name="expectedSha256"/>,
    /// and return the local path. Throws on hash mismatch.
    /// </summary>
    Task<string> DownloadAndVerifyAsync(string sourceUrl, string expectedSha256, CancellationToken ct = default);

    /// <summary>
    /// Install an MSI package silently. Returns the msiexec exit code.
    /// </summary>
    int InstallMsi(string msiPath, string? extraArgs = null);

    /// <summary>
    /// Uninstall an MSI package by product code. Returns the msiexec exit code.
    /// </summary>
    int UninstallMsi(string productCode);

    /// <summary>
    /// Install an EXE package silently with the given arguments.
    /// Returns the process exit code.
    /// </summary>
    int InstallExe(string exePath, string silentArgs);

    /// <summary>
    /// Check whether a package is installed by looking up its product
    /// code or package ID in the Windows uninstall registry.
    /// </summary>
    bool IsInstalled(string packageId);

    /// <summary>
    /// Look up the uninstall string for a package. Returns null if
    /// the package is not found.
    /// </summary>
    string? GetUninstallString(string packageId);
}
