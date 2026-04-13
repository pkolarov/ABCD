// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Enforces <c>SoftwareAssignment</c> directives by dispatching
/// through <see cref="ISoftwareOperations"/>. Supports MSI and EXE
/// installers with SHA-256 verification.
///
/// The directive JSON has the shape:
/// <code>
/// {
///   "package_id": "com.example.editor",
///   "version": "2.1",
///   "action": "Install" | "Uninstall",
///   "installer_type": "msi" | "exe",
///   "source_url": "https://...",
///   "sha256": "abcdef...",
///   "silent_args": "/S"
/// }
/// </code>
/// </summary>
public sealed class SoftwareInstaller : IEnforcer
{
    private readonly ISoftwareOperations _ops;
    private readonly ILogger<SoftwareInstaller> _log;
    public string Name => "Software";

    public SoftwareInstaller(ISoftwareOperations ops, ILogger<SoftwareInstaller> log)
    {
        _ops = ops;
        _log = log;
    }

    public async Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive, EnforcementMode mode, CancellationToken ct = default)
    {
        var pkgId = directive.TryGetProperty("package_id", out var id)
            ? id.GetString() ?? "unknown"
            : "unknown";
        var version = directive.TryGetProperty("version", out var v)
            ? v.GetString() ?? "?"
            : "?";
        var action = directive.TryGetProperty("action", out var a)
            ? a.GetString() ?? "Install"
            : "Install";
        var installerType = directive.TryGetProperty("installer_type", out var t)
            ? t.GetString()?.ToLowerInvariant() ?? "msi"
            : "msi";

        var desc = $"{action} {pkgId} v{version}";

        if (mode == EnforcementMode.Audit)
        {
            _log.LogInformation("[AUDIT] Software: would {Action}", desc);
            return new EnforcementOutcome(
                EnforcementStatus.Ok, null, [$"[AUDIT] {desc}"]);
        }

        try
        {
            switch (action)
            {
                case "Install":
                    return await ApplyInstallAsync(directive, pkgId, version, installerType, desc, ct);

                case "Uninstall":
                    return ApplyUninstall(pkgId, desc);

                default:
                    return new EnforcementOutcome(
                        EnforcementStatus.Failed,
                        $"Unknown software action: {action}",
                        [$"FAILED: {desc} — unknown action"]);
            }
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Software enforcer failed: {Desc}", desc);
            return new EnforcementOutcome(
                EnforcementStatus.Failed, ex.Message,
                [$"FAILED: {desc} — {ex.Message}"]);
        }
    }

    private async Task<EnforcementOutcome> ApplyInstallAsync(
        JsonElement directive, string pkgId, string version,
        string installerType, string desc, CancellationToken ct)
    {
        // Already installed?
        if (_ops.IsInstalled(pkgId))
        {
            _log.LogDebug("Software: {Pkg} already installed — skip", pkgId);
            return new EnforcementOutcome(
                EnforcementStatus.Ok, null,
                [$"[NO-OP] {desc} (already installed)"]);
        }

        var sourceUrl = directive.TryGetProperty("source_url", out var u)
            ? u.GetString() : null;
        var sha256 = directive.TryGetProperty("sha256", out var h)
            ? h.GetString() : null;

        if (string.IsNullOrEmpty(sourceUrl))
            return new EnforcementOutcome(
                EnforcementStatus.Failed,
                "source_url is required for Install",
                [$"FAILED: {desc} — no source_url"]);

        if (string.IsNullOrEmpty(sha256))
            return new EnforcementOutcome(
                EnforcementStatus.Failed,
                "sha256 is required for Install",
                [$"FAILED: {desc} — no sha256"]);

        // Download + verify
        _log.LogInformation("Software: downloading {Url}", sourceUrl);
        var localPath = await _ops.DownloadAndVerifyAsync(sourceUrl, sha256, ct);

        // Install
        int exitCode;
        switch (installerType)
        {
            case "msi":
                var extraArgs = directive.TryGetProperty("silent_args", out var sa)
                    ? sa.GetString() : null;
                exitCode = _ops.InstallMsi(localPath, extraArgs);
                break;
            case "exe":
                var silentArgs = directive.TryGetProperty("silent_args", out var ea)
                    ? ea.GetString() ?? "/S" : "/S";
                exitCode = _ops.InstallExe(localPath, silentArgs);
                break;
            default:
                return new EnforcementOutcome(
                    EnforcementStatus.Failed,
                    $"Unknown installer_type: {installerType}",
                    [$"FAILED: {desc} — unknown installer_type"]);
        }

        // Clean up temp file
        try { File.Delete(localPath); } catch { /* best-effort */ }

        if (exitCode != 0)
        {
            var msg = $"Installer exited with code {exitCode}";
            _log.LogError("Software: {Desc} — {Msg}", desc, msg);
            return new EnforcementOutcome(
                EnforcementStatus.Failed, msg,
                [$"FAILED: {desc} — {msg}"]);
        }

        _log.LogInformation("Software: {Desc} — success", desc);
        return new EnforcementOutcome(
            EnforcementStatus.Ok, null, [desc]);
    }

    /// <summary>
    /// Extract the managed-item key for a software directive.
    /// Returns the package_id for Install actions.
    /// </summary>
    public static string? ExtractManagedKey(JsonElement directive)
    {
        var action = directive.TryGetProperty("action", out var a) ? a.GetString() : "Install";
        if (action != "Install") return null;
        return directive.TryGetProperty("package_id", out var id) ? id.GetString() : null;
    }

    /// <summary>
    /// Reconcile stale software — uninstall packages that were
    /// previously managed by DDS but are no longer assigned.
    /// </summary>
    public List<string> ReconcileStalePackages(
        IReadOnlySet<string> stalePackageIds, EnforcementMode mode)
    {
        var changes = new List<string>();
        foreach (var pkgId in stalePackageIds)
        {
            try
            {
                if (!_ops.IsInstalled(pkgId))
                    continue;

                var desc = $"Reconcile-Uninstall {pkgId}";

                if (mode == EnforcementMode.Audit)
                {
                    _log.LogInformation("[AUDIT] Software reconcile: would uninstall stale '{Pkg}'", pkgId);
                    changes.Add($"[AUDIT] {desc}");
                    continue;
                }

                var exitCode = _ops.UninstallMsi(pkgId);
                if (exitCode != 0)
                {
                    _log.LogError("Software reconcile: uninstall of '{Pkg}' failed with exit code {Code}", pkgId, exitCode);
                    changes.Add($"FAILED: {desc} — exit code {exitCode}");
                }
                else
                {
                    _log.LogInformation("Software reconcile: uninstalled stale '{Pkg}'", pkgId);
                    changes.Add(desc);
                }
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Software reconcile failed for '{Pkg}'", pkgId);
                changes.Add($"FAILED: Reconcile-Uninstall {pkgId} — {ex.Message}");
            }
        }
        return changes;
    }

    private EnforcementOutcome ApplyUninstall(string pkgId, string desc)
    {
        if (!_ops.IsInstalled(pkgId))
        {
            _log.LogDebug("Software: {Pkg} not installed — skip uninstall", pkgId);
            return new EnforcementOutcome(
                EnforcementStatus.Ok, null,
                [$"[NO-OP] {desc} (not installed)"]);
        }

        var exitCode = _ops.UninstallMsi(pkgId);
        if (exitCode != 0)
        {
            var msg = $"Uninstall exited with code {exitCode}";
            _log.LogError("Software: {Desc} — {Msg}", desc, msg);
            return new EnforcementOutcome(
                EnforcementStatus.Failed, msg,
                [$"FAILED: {desc} — {msg}"]);
        }

        _log.LogInformation("Software: {Desc} — success", desc);
        return new EnforcementOutcome(
            EnforcementStatus.Ok, null, [desc]);
    }
}
