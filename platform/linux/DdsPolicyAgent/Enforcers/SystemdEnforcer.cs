// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.Linux.Runtime;

namespace DDS.PolicyAgent.Linux.Enforcers;

/// Applies LinuxSystemdDirective entries (enable/disable/start/stop/restart, drop-ins).
///
/// Safety invariants:
///   - Unit name must be a safe single-component name with a recognised suffix.
///   - Drop-in filenames must pass the same single-component safety check as sudoers.
///   - After writing any drop-in the daemon is reloaded.
[SupportedOSPlatform("linux")]
public sealed class SystemdEnforcer
{
    private static readonly HashSet<string> AllowedSuffixes =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".service", ".socket", ".timer", ".target", ".mount",
            ".automount", ".swap", ".path", ".slice", ".scope"
        };

    private const string DropinBase = "/etc/systemd/system";

    private readonly ICommandRunner _runner;
    private readonly bool _auditOnly;
    private readonly ILogger _log;

    public SystemdEnforcer(ICommandRunner runner, bool auditOnly, ILogger log)
    {
        _runner = runner;
        _auditOnly = auditOnly;
        _log = log;
    }

    public async Task<List<string>> ApplyAsync(
        IReadOnlyList<JsonElement> directives, CancellationToken ct)
    {
        var applied = new List<string>();
        var needReload = false;

        foreach (var d in directives)
        {
            var unit   = d.TryGetProperty("unit",   out var u) ? u.GetString() : null;
            var action = d.TryGetProperty("action", out var a) ? a.GetString() : null;

            if (string.IsNullOrWhiteSpace(unit) || string.IsNullOrWhiteSpace(action))
            {
                _log.LogWarning("SystemdEnforcer: directive missing unit or action; skipping");
                continue;
            }

            if (!IsSafeUnitName(unit))
            {
                _log.LogWarning("SystemdEnforcer: unsafe unit name {U}; skipping", unit);
                continue;
            }

            switch (action)
            {
                case "Enable":
                    await RunCtlOrLogAsync("enable", unit, ct).ConfigureAwait(false);
                    applied.Add($"systemd:enable:{unit}");
                    break;

                case "Disable":
                    await RunCtlOrLogAsync("disable", unit, ct).ConfigureAwait(false);
                    applied.Add($"systemd:disable:{unit}");
                    break;

                case "Start":
                    await RunCtlOrLogAsync("start", unit, ct).ConfigureAwait(false);
                    applied.Add($"systemd:start:{unit}");
                    break;

                case "Stop":
                    await RunCtlOrLogAsync("stop", unit, ct).ConfigureAwait(false);
                    applied.Add($"systemd:stop:{unit}");
                    break;

                case "Restart":
                    await RunCtlOrLogAsync("restart", unit, ct).ConfigureAwait(false);
                    applied.Add($"systemd:restart:{unit}");
                    break;

                case "ConfigureDropin":
                {
                    var stem = await WriteDropinAsync(unit, d, ct).ConfigureAwait(false);
                    if (stem != null)
                    {
                        needReload = true;
                        applied.Add($"systemd:configuredropin:{unit}/{stem}");
                    }
                    break;
                }

                case "RemoveDropin":
                {
                    var stem = await RemoveDropinAsync(unit, d, ct).ConfigureAwait(false);
                    if (stem != null)
                    {
                        needReload = true;
                        applied.Add($"systemd:removedropin:{unit}/{stem}");
                    }
                    break;
                }

                default:
                    _log.LogWarning("SystemdEnforcer: unknown action {A} for {U}; skipping", action, unit);
                    break;
            }
        }

        if (needReload)
            await RunCtlOrLogAsync("daemon-reload", string.Empty, ct).ConfigureAwait(false);

        return applied;
    }

    /// Deletes drop-in files that were written by DDS but are no longer declared in any
    /// current policy. <paramref name="staleDropins"/> is a set of "unit/stem" keys
    /// (managed set ∖ desired set). Returns a directive tag per processed entry.
    public async Task<List<string>> ReconcileStaleDropinsAsync(
        IReadOnlySet<string> staleDropins, CancellationToken ct)
    {
        var results = new List<string>();

        foreach (var key in staleDropins)
        {
            var slash = key.IndexOf('/');
            if (slash <= 0 || slash == key.Length - 1)
            {
                _log.LogWarning("SystemdEnforcer: invalid dropin key {K}; skipping", key);
                continue;
            }
            var unit = key[..slash];
            var stem = key[(slash + 1)..];

            if (!IsSafeUnitName(unit) || !IsSafeDropinStem(stem))
            {
                _log.LogWarning("SystemdEnforcer: unsafe dropin key {K}; skipping", key);
                continue;
            }

            var dropinPath = Path.Combine(DropinBase, $"{unit}.d", $"{stem}.conf");

            if (_auditOnly)
            {
                _log.LogInformation("[audit] would remove stale dropin {P}", dropinPath);
                results.Add($"systemd:removedropin:{key}");
                continue;
            }

            if (File.Exists(dropinPath))
            {
                File.Delete(dropinPath);
                _log.LogInformation("SystemdEnforcer: removed stale dropin {P}", dropinPath);
                await RunCtlOrLogAsync("daemon-reload", string.Empty, ct).ConfigureAwait(false);
            }
            results.Add($"systemd:removedropin:{key}");
        }

        return results;
    }

    [SupportedOSPlatform("linux")]
    private async Task<string?> WriteDropinAsync(string unit, JsonElement d, CancellationToken ct)
    {
        var stem    = d.TryGetProperty("dropin_name",    out var sn) ? sn.GetString() : null;
        var content = d.TryGetProperty("dropin_content", out var dc) ? dc.GetString() : null;

        if (string.IsNullOrWhiteSpace(stem) || string.IsNullOrWhiteSpace(content))
        {
            _log.LogWarning("SystemdEnforcer: ConfigureDropin for {U} missing dropin_name or content", unit);
            return null;
        }

        if (!IsSafeDropinStem(stem))
        {
            _log.LogWarning("SystemdEnforcer: unsafe dropin_name {S}; skipping", stem);
            return null;
        }

        var dropinDir  = Path.Combine(DropinBase, $"{unit}.d");
        var dropinPath = Path.Combine(dropinDir, $"{stem}.conf");

        if (_auditOnly)
        {
            _log.LogInformation("[audit] would write dropin {P}", dropinPath);
            return stem;
        }

        Directory.CreateDirectory(dropinDir);
        var tmp = dropinPath + ".dds-tmp";
        await File.WriteAllTextAsync(tmp, content, Encoding.UTF8, ct).ConfigureAwait(false);
        File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite |
                                  UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        File.Move(tmp, dropinPath, overwrite: true);
        _log.LogInformation("SystemdEnforcer: wrote dropin {P}", dropinPath);
        return stem;
    }

    private Task<string?> RemoveDropinAsync(string unit, JsonElement d, CancellationToken ct)
    {
        var stem = d.TryGetProperty("dropin_name", out var sn) ? sn.GetString() : null;

        if (string.IsNullOrWhiteSpace(stem) || !IsSafeDropinStem(stem))
        {
            _log.LogWarning("SystemdEnforcer: RemoveDropin for {U} has missing/unsafe dropin_name", unit);
            return Task.FromResult<string?>(null);
        }

        var dropinPath = Path.Combine(DropinBase, $"{unit}.d", $"{stem}.conf");

        if (_auditOnly)
        {
            _log.LogInformation("[audit] would remove dropin {P}", dropinPath);
            return Task.FromResult<string?>(stem);
        }

        if (File.Exists(dropinPath))
        {
            File.Delete(dropinPath);
            _log.LogInformation("SystemdEnforcer: removed dropin {P}", dropinPath);
        }

        return Task.FromResult<string?>(stem);
    }

    private async Task RunCtlOrLogAsync(string subcommand, string args, CancellationToken ct)
    {
        var fullArgs = string.IsNullOrEmpty(args) ? subcommand : $"{subcommand} {args}";

        if (_auditOnly)
        {
            _log.LogInformation("[audit] would run: systemctl {Args}", fullArgs);
            return;
        }

        var result = await _runner.RunAsync("systemctl", fullArgs, ct).ConfigureAwait(false);
        if (!result.Success)
            _log.LogWarning("systemctl {Args} exited {Code}: {Err}",
                fullArgs, result.ExitCode, result.Stderr);
    }

    internal static bool IsSafeUnitName(string name)
    {
        if (name.Length == 0 || name.Length > 128) return false;
        if (name.Contains('/') || name.Contains('\\') || name.Contains("..")) return false;
        return AllowedSuffixes.Any(s => name.EndsWith(s, StringComparison.OrdinalIgnoreCase));
    }

    internal static bool IsSafeDropinStem(string stem)
    {
        if (stem.Length == 0 || stem.Length > 64) return false;
        if (stem.Contains('/') || stem.Contains('\\') || stem.Contains('.')) return false;
        foreach (var c in stem)
            if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_') return false;
        return true;
    }
}
