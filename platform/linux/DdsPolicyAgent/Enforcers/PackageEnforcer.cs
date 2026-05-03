// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Linux.Runtime;

namespace DDS.PolicyAgent.Linux.Enforcers;

/// Applies LinuxPackageDirective entries (install / remove) via the host package manager.
///
/// Package manager detection order: dpkg (apt-get) → dnf → rpm.
/// Remove is refused for packages not in the `managedPackages` set (caller-supplied).
public sealed class PackageEnforcer
{
    private readonly ICommandRunner _runner;
    private readonly bool _auditOnly;
    private readonly ILogger _log;

    public PackageEnforcer(ICommandRunner runner, bool auditOnly, ILogger log)
    {
        _runner = runner;
        _auditOnly = auditOnly;
        _log = log;
    }

    public async Task<List<string>> ApplyAsync(
        IReadOnlyList<JsonElement> directives,
        IReadOnlySet<string> managedPackages,
        CancellationToken ct)
    {
        var applied = new List<string>();

        foreach (var d in directives)
        {
            var name    = d.TryGetProperty("name",    out var n) ? n.GetString() : null;
            var action  = d.TryGetProperty("action",  out var a) ? a.GetString() : null;
            var version = d.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.String
                ? v.GetString()
                : null;

            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(action))
            {
                _log.LogWarning("PackageEnforcer: directive missing name or action; skipping");
                continue;
            }

            if (!IsValidPackageName(name))
            {
                _log.LogWarning("PackageEnforcer: unsafe package name {N}; skipping", name);
                continue;
            }

            var tag = $"pkg:{action.ToLowerInvariant()}:{name}";

            switch (action)
            {
                case "Install":
                    await InstallAsync(name, version, ct).ConfigureAwait(false);
                    break;

                case "Remove":
                    if (!managedPackages.Contains(name))
                    {
                        _log.LogWarning("PackageEnforcer: {N} not DDS-managed; refusing Remove", name);
                        continue;
                    }
                    await RemoveAsync(name, ct).ConfigureAwait(false);
                    break;

                default:
                    _log.LogWarning("PackageEnforcer: unknown action {A}; skipping", action);
                    continue;
            }

            applied.Add(tag);
        }

        return applied;
    }

    private async Task InstallAsync(string name, string? version, CancellationToken ct)
    {
        var spec = string.IsNullOrEmpty(version) ? name : $"{name}={version}";

        if (_auditOnly)
        {
            _log.LogInformation("[audit] would install package {Spec}", spec);
            return;
        }

        var pm = await DetectPackageManagerAsync(ct).ConfigureAwait(false);
        var (cmd, args) = pm switch
        {
            PackageManager.Apt => ("apt-get", $"install -y {spec}"),
            PackageManager.Dnf => ("dnf", $"install -y {spec}"),
            PackageManager.Rpm => ("rpm", $"-i {spec}"),
            _                  => throw new InvalidOperationException("no supported package manager found"),
        };

        var result = await _runner.RunAsync(cmd, args, ct).ConfigureAwait(false);
        if (!result.Success)
            _log.LogWarning("{Cmd} {Args} exited {Code}: {Err}", cmd, args, result.ExitCode, result.Stderr);
    }

    private async Task RemoveAsync(string name, CancellationToken ct)
    {
        if (_auditOnly)
        {
            _log.LogInformation("[audit] would remove package {Name}", name);
            return;
        }

        var pm = await DetectPackageManagerAsync(ct).ConfigureAwait(false);
        var (cmd, args) = pm switch
        {
            PackageManager.Apt => ("apt-get", $"remove -y {name}"),
            PackageManager.Dnf => ("dnf", $"remove -y {name}"),
            PackageManager.Rpm => ("rpm", $"-e {name}"),
            _                  => throw new InvalidOperationException("no supported package manager found"),
        };

        var result = await _runner.RunAsync(cmd, args, ct).ConfigureAwait(false);
        if (!result.Success)
            _log.LogWarning("{Cmd} {Args} exited {Code}: {Err}", cmd, args, result.ExitCode, result.Stderr);
    }

    private enum PackageManager { Apt, Dnf, Rpm, Unknown }

    private async Task<PackageManager> DetectPackageManagerAsync(CancellationToken ct)
    {
        if ((await _runner.RunAsync("which", "apt-get", ct).ConfigureAwait(false)).Success)
            return PackageManager.Apt;
        if ((await _runner.RunAsync("which", "dnf", ct).ConfigureAwait(false)).Success)
            return PackageManager.Dnf;
        if ((await _runner.RunAsync("which", "rpm", ct).ConfigureAwait(false)).Success)
            return PackageManager.Rpm;
        return PackageManager.Unknown;
    }

    internal static bool IsValidPackageName(string name)
    {
        if (name.Length == 0 || name.Length > 128) return false;
        foreach (var c in name)
            if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_' && c != '.' && c != '+')
                return false;
        return true;
    }
}
