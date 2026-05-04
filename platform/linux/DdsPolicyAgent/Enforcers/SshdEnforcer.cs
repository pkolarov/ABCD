// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.Linux.Runtime;

namespace DDS.PolicyAgent.Linux.Enforcers;

/// Applies an SshdPolicy by writing a DDS-managed drop-in at
/// `/etc/ssh/sshd_config.d/60-dds.conf` and reloading sshd via
/// `systemctl reload sshd` (or `ssh` on distros that use that unit name).
///
/// Safety invariants:
///   - Only the fields present in the policy are written; absent fields are omitted.
///   - PermitRootLogin value is restricted to known safe enum strings.
///   - AllowUsers / AllowGroups entries must pass the same username-safety check
///     as UserEnforcer.
///   - The drop-in is written atomically (temp + rename); original sshd_config is
///     never touched.
///   - Passing `null` for the policy removes the drop-in entirely.
[SupportedOSPlatform("linux")]
public sealed class SshdEnforcer
{
    private const string DropinPath = "/etc/ssh/sshd_config.d/60-dds.conf";

    private static readonly HashSet<string> ValidPermitRootLogin =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "yes", "no", "prohibit-password", "forced-commands-only"
        };

    private readonly ICommandRunner _runner;
    private readonly bool _auditOnly;
    private readonly ILogger _log;

    public SshdEnforcer(ICommandRunner runner, bool auditOnly, ILogger log)
    {
        _runner = runner;
        _auditOnly = auditOnly;
        _log = log;
    }

    /// Apply the given policy object (deserialized from the `ssh` field of
    /// `LinuxSettings`).  Pass a `null`-valued JsonElement to remove the drop-in.
    public async Task<List<string>> ApplyAsync(JsonElement? policy, CancellationToken ct)
    {
        // Null / absent ssh field → remove our drop-in if present.
        if (policy is null || policy.Value.ValueKind != JsonValueKind.Object)
        {
            if (File.Exists(DropinPath))
            {
                await RemoveDropinAsync(ct).ConfigureAwait(false);
                return ["sshd:remove"];
            }
            return [];
        }

        var p = policy.Value;
        var lines  = new List<string>();
        var result = new List<string>();

        if (p.TryGetProperty("password_authentication", out var pa) &&
            pa.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            lines.Add($"PasswordAuthentication {(pa.GetBoolean() ? "yes" : "no")}");
            result.Add($"sshd:set:PasswordAuthentication={pa.GetBoolean()}");
        }

        if (p.TryGetProperty("pubkey_authentication", out var pka) &&
            pka.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            lines.Add($"PubkeyAuthentication {(pka.GetBoolean() ? "yes" : "no")}");
            result.Add($"sshd:set:PubkeyAuthentication={pka.GetBoolean()}");
        }

        if (p.TryGetProperty("permit_root_login", out var prl) &&
            prl.ValueKind == JsonValueKind.String)
        {
            var val = prl.GetString() ?? string.Empty;
            if (!ValidPermitRootLogin.Contains(val))
            {
                _log.LogWarning("SshdEnforcer: invalid permit_root_login value {V}; skipping field", val);
            }
            else
            {
                lines.Add($"PermitRootLogin {val}");
                result.Add($"sshd:set:PermitRootLogin={val}");
            }
        }

        if (p.TryGetProperty("allow_users", out var au) &&
            au.ValueKind == JsonValueKind.Array)
        {
            var names = ParseNameList(au, "allow_users");
            if (names.Count > 0)
            {
                lines.Add($"AllowUsers {string.Join(' ', names)}");
                result.Add($"sshd:set:AllowUsers={string.Join(',', names)}");
            }
        }

        if (p.TryGetProperty("allow_groups", out var ag) &&
            ag.ValueKind == JsonValueKind.Array)
        {
            var names = ParseNameList(ag, "allow_groups");
            if (names.Count > 0)
            {
                lines.Add($"AllowGroups {string.Join(' ', names)}");
                result.Add($"sshd:set:AllowGroups={string.Join(',', names)}");
            }
        }

        if (lines.Count == 0)
        {
            // Policy object exists but produced no valid directives (all fields absent or invalid).
            // Treat identically to null policy: remove any previously-written dropin so it
            // doesn't linger after the operator removes all recognized ssh fields from the policy.
            if (File.Exists(DropinPath))
            {
                await RemoveDropinAsync(ct).ConfigureAwait(false);
                return ["sshd:remove"];
            }
            return [];
        }

        await WriteDropinAsync(lines, ct).ConfigureAwait(false);
        await ReloadSshdAsync(ct).ConfigureAwait(false);
        return result;
    }

    private List<string> ParseNameList(JsonElement array, string fieldName)
    {
        var names = new List<string>();
        foreach (var el in array.EnumerateArray())
        {
            var name = el.ValueKind == JsonValueKind.String ? el.GetString() : null;
            if (string.IsNullOrWhiteSpace(name))
                continue;
            if (!IsValidName(name))
            {
                _log.LogWarning("SshdEnforcer: unsafe name in {Field}: {Name}; skipping", fieldName, name);
                continue;
            }
            names.Add(name);
        }
        return names;
    }

    [SupportedOSPlatform("linux")]
    private async Task WriteDropinAsync(List<string> lines, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Managed by DDS — do not edit manually.");
        foreach (var line in lines)
            sb.AppendLine(line);

        var content = sb.ToString();

        if (_auditOnly)
        {
            _log.LogInformation("[audit] would write {Path} ({N} directives)", DropinPath, lines.Count);
            return;
        }

        var dir = Path.GetDirectoryName(DropinPath)!;
        Directory.CreateDirectory(dir);

        var tmp = DropinPath + ".dds-tmp";
        await File.WriteAllTextAsync(tmp, content, Encoding.UTF8, ct).ConfigureAwait(false);
        File.SetUnixFileMode(tmp,
            UnixFileMode.UserRead | UnixFileMode.UserWrite |
            UnixFileMode.GroupRead);
        File.Move(tmp, DropinPath, overwrite: true);
        _log.LogInformation("SshdEnforcer: wrote {Path}", DropinPath);
    }

    private Task RemoveDropinAsync(CancellationToken ct)
    {
        if (_auditOnly)
        {
            _log.LogInformation("[audit] would remove {Path}", DropinPath);
            return Task.CompletedTask;
        }

        if (File.Exists(DropinPath))
        {
            File.Delete(DropinPath);
            _log.LogInformation("SshdEnforcer: removed {Path}", DropinPath);
        }
        return Task.CompletedTask;
    }

    private async Task ReloadSshdAsync(CancellationToken ct)
    {
        if (_auditOnly)
        {
            _log.LogInformation("[audit] would run: systemctl reload sshd");
            return;
        }

        // Try "sshd" first; fall back to "ssh" for distros that use that unit name.
        var result = await _runner.RunAsync("systemctl", "reload sshd", ct).ConfigureAwait(false);
        if (!result.Success)
        {
            _log.LogDebug("systemctl reload sshd failed ({Code}); trying ssh unit", result.ExitCode);
            result = await _runner.RunAsync("systemctl", "reload ssh", ct).ConfigureAwait(false);
            if (!result.Success)
                _log.LogWarning("systemctl reload ssh exited {Code}: {Err}",
                    result.ExitCode, result.Stderr);
        }
    }

    // Names (users/groups) must be safe POSIX identifiers.
    internal static bool IsValidName(string name)
    {
        if (name.Length == 0 || name.Length > 32) return false;
        if (char.IsDigit(name[0])) return false;
        foreach (var c in name)
            if (!char.IsAsciiLetterOrDigit(c) && c != '_' && c != '-' && c != '.') return false;
        return true;
    }
}
