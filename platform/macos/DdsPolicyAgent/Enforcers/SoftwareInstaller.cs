// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Security.Cryptography;
using System.Text.Json;
using DDS.PolicyAgent.MacOS.Config;
using DDS.PolicyAgent.MacOS.Runtime;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.MacOS.Enforcers;

/// <summary>
/// macOS software installer backed by `/usr/sbin/installer` and
/// `/usr/sbin/pkgutil`. This first host-backed slice supports local or
/// HTTPS `.pkg` install/update flows with SHA-256 verification and
/// optional signature checks. Generic uninstall is still intentionally
/// refused because macOS packages do not have a universal safe remove
/// primitive.
/// </summary>
public sealed class SoftwareInstaller : IEnforcer
{
    private readonly ILogger<SoftwareInstaller> _log;
    private readonly ICommandRunner _runner;
    private readonly AgentConfig _config;
    private readonly IHttpClientFactory _httpClientFactory;

    public string Name => "Software";

    public SoftwareInstaller(
        ILogger<SoftwareInstaller> log,
        ICommandRunner runner,
        IOptions<AgentConfig> config,
        IHttpClientFactory httpClientFactory)
    {
        _log = log;
        _runner = runner;
        _config = config.Value;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive,
        EnforcementMode mode,
        CancellationToken ct = default)
    {
        var pkgId = directive.TryGetProperty("package_id", out var id)
            ? id.GetString()
            : "unknown";
        var version = directive.TryGetProperty("version", out var v)
            ? v.GetString()
            : "?";
        var action = directive.TryGetProperty("action", out var a)
            ? a.GetString()
            : "Install";

        var desc = $"{action} {pkgId} v{version}";
        if (mode == EnforcementMode.Audit)
        {
            _log.LogInformation("[AUDIT] Software: would {Action}", desc);
            return new EnforcementOutcome(
                EnforcementStatus.Ok,
                null,
                [$"[AUDIT] {desc}"]);
        }

        try
        {
            var change = await ApplyOneAsync(directive, pkgId ?? "unknown", version ?? "?", action ?? "Install", ct)
                .ConfigureAwait(false);
            return new EnforcementOutcome(EnforcementStatus.Ok, null, [change]);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Software install failed for {PackageId}", pkgId);
            return new EnforcementOutcome(
                EnforcementStatus.Failed,
                ex.Message,
                [$"FAILED: {desc} — {ex.Message}"]);
        }
    }

    private async Task<string> ApplyOneAsync(
        JsonElement directive,
        string packageId,
        string version,
        string action,
        CancellationToken ct)
    {
        if (!directive.TryGetProperty("source", out var sourceValue) ||
            string.IsNullOrWhiteSpace(sourceValue.GetString()))
        {
            throw new InvalidOperationException("software assignment is missing source");
        }

        if (!directive.TryGetProperty("sha256", out var shaValue) ||
            string.IsNullOrWhiteSpace(shaValue.GetString()))
        {
            throw new InvalidOperationException("software assignment is missing sha256");
        }

        if (HasInlineScript(directive, "pre_install_script") || HasInlineScript(directive, "post_install_script"))
        {
            if (!_config.AllowInlinePackageScripts)
            {
                throw new InvalidOperationException(
                    "inline pre/post install scripts are disabled for macOS package assignments");
            }
        }

        if (string.Equals(action, "Uninstall", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "generic macOS pkg uninstall is not supported yet; package-native removal recipes are still TODO");
        }

        var currentVersion = TryGetInstalledVersion(packageId);
        if (string.Equals(currentVersion, version, StringComparison.Ordinal))
        {
            return $"[NO-OP] {action} {packageId} v{version} (already installed)";
        }

        PrivilegeGuard.DemandRoot("macOS package installation");

        var source = sourceValue.GetString()!;
        var expectedSha = NormalizeSha(shaValue.GetString()!);
        var packagePath = await ResolvePackagePathAsync(source, packageId, version, ct).ConfigureAwait(false);
        var actualSha = await ComputeSha256Async(packagePath, ct).ConfigureAwait(false);
        if (!string.Equals(expectedSha, actualSha, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"package hash mismatch for '{packageId}': expected {expectedSha}, got {actualSha}");
        }

        if (_config.RequirePackageSignature)
        {
            _runner.RunChecked("/usr/sbin/pkgutil", ["--check-signature", packagePath]);
        }

        if (_config.AllowInlinePackageScripts)
        {
            RunInlineScriptIfPresent(directive, "pre_install_script", $"pre-install:{packageId}");
        }

        _runner.RunChecked(
            "/usr/sbin/installer",
            ["-pkg", packagePath, "-target", _config.PackageInstallTarget]);

        if (_config.AllowInlinePackageScripts)
        {
            RunInlineScriptIfPresent(directive, "post_install_script", $"post-install:{packageId}");
        }

        var installedVersion = TryGetInstalledVersion(packageId);
        if (installedVersion is null)
            throw new InvalidOperationException($"package '{packageId}' installed without a readable receipt");

        return $"{action} {packageId} v{version}";
    }

    private async Task<string> ResolvePackagePathAsync(
        string source,
        string packageId,
        string version,
        CancellationToken ct)
    {
        if (Uri.TryCreate(source, UriKind.Absolute, out var uri))
        {
            if (uri.IsFile)
                return uri.LocalPath;

            if (uri.Scheme is "https")
                return await DownloadPackageAsync(uri, packageId, version, ct).ConfigureAwait(false);

            throw new InvalidOperationException($"unsupported package source URI scheme '{uri.Scheme}'");
        }

        return Path.GetFullPath(source);
    }

    private async Task<string> DownloadPackageAsync(
        Uri uri,
        string packageId,
        string version,
        CancellationToken ct)
    {
        Directory.CreateDirectory(_config.ResolvePackageCacheDir());
        var extension = Path.GetExtension(uri.AbsolutePath);
        if (string.IsNullOrWhiteSpace(extension))
            extension = ".pkg";

        var targetPath = Path.Combine(
            _config.ResolvePackageCacheDir(),
            $"{SanitizeFileName(packageId)}-{SanitizeFileName(version)}{extension}");

        using var client = _httpClientFactory.CreateClient(nameof(SoftwareInstaller));
        using var response = await client.GetAsync(uri, ct).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        await using var input = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        await using var output = File.Create(targetPath);
        await input.CopyToAsync(output, ct).ConfigureAwait(false);

        return targetPath;
    }

    private string? TryGetInstalledVersion(string packageId)
    {
        var result = _runner.Run("/usr/sbin/pkgutil", ["--pkg-info", packageId]);
        if (!result.Succeeded)
            return null;

        foreach (var rawLine in result.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("version:", StringComparison.OrdinalIgnoreCase))
                return line["version:".Length..].Trim();
        }

        return null;
    }

    private static bool HasInlineScript(JsonElement directive, string propertyName)
        => directive.TryGetProperty(propertyName, out var script)
            && script.ValueKind != JsonValueKind.Null
            && !string.IsNullOrWhiteSpace(script.GetString());

    private void RunInlineScriptIfPresent(JsonElement directive, string propertyName, string label)
    {
        if (!HasInlineScript(directive, propertyName))
            return;

        var script = directive.GetProperty(propertyName).GetString()
            ?? throw new InvalidOperationException($"missing {propertyName}");

        _log.LogWarning("Executing inline package script {Label}", label);
        _runner.RunChecked("/bin/zsh", ["-lc", script]);
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken ct)
    {
        await using var stream = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string NormalizeSha(string sha)
        => sha.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? sha["sha256:".Length..].ToLowerInvariant()
            : sha.ToLowerInvariant();

    /// <summary>
    /// Extract the managed-item key (package_id) for an Install directive.
    /// Returns null for non-Install actions.
    /// </summary>
    public static string? ExtractManagedKey(JsonElement directive)
    {
        var action = directive.TryGetProperty("action", out var a) ? a.GetString() : "Install";
        if (!string.Equals(action, "Install", StringComparison.OrdinalIgnoreCase)) return null;
        return directive.TryGetProperty("package_id", out var id) ? id.GetString() : null;
    }

    /// <summary>
    /// Log stale software packages that are no longer in the policy.
    /// Generic macOS pkg uninstall is intentionally not supported, so
    /// this is audit-log only regardless of mode.
    /// </summary>
    public List<string> ReconcileStalePackages(IReadOnlySet<string> staleKeys, EnforcementMode mode)
    {
        var changes = new List<string>();
        foreach (var packageId in staleKeys)
        {
            _log.LogWarning(
                "Software reconcile: package '{PackageId}' is no longer in policy but cannot be auto-uninstalled on macOS",
                packageId);
            changes.Add($"[MANUAL] Reconcile-Uninstall {packageId} (macOS pkg uninstall not supported — remove manually)");
        }
        return changes;
    }

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        return new string(value.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
    }
}
