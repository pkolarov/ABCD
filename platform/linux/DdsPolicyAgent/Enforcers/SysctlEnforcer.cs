// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.Linux.Runtime;

namespace DDS.PolicyAgent.Linux.Enforcers;

/// Applies SysctlDirective entries by maintaining a DDS-managed drop-in file at
/// `/etc/sysctl.d/60-dds-managed.conf` and reloading via `sysctl --system`.
///
/// Safety invariants:
///   - Key must match the allowlist pattern: dotted segments of alphanumeric + underscore chars.
///   - Values are validated to contain only printable ASCII with no shell metacharacters.
///   - The drop-in file is written atomically (temp + rename).
///   - `Delete` removes a key from the managed drop-in; it does not touch other drop-ins.
[SupportedOSPlatform("linux")]
public sealed class SysctlEnforcer
{
    private const string DropinPath = "/etc/sysctl.d/60-dds-managed.conf";

    private readonly ICommandRunner _runner;
    private readonly bool _auditOnly;
    private readonly ILogger _log;

    public SysctlEnforcer(ICommandRunner runner, bool auditOnly, ILogger log)
    {
        _runner = runner;
        _auditOnly = auditOnly;
        _log = log;
    }

    public async Task<List<string>> ApplyAsync(
        IReadOnlyList<JsonElement> directives, CancellationToken ct)
    {
        if (directives.Count == 0)
            return [];

        // Load the current managed drop-in (if any) into a mutable dictionary.
        var current = LoadDropin();
        var applied  = new List<string>();
        var changed  = false;

        foreach (var d in directives)
        {
            var key    = d.TryGetProperty("key",    out var k) ? k.GetString() : null;
            var value  = d.TryGetProperty("value",  out var v) ? v.GetString() : null;
            var action = d.TryGetProperty("action", out var a) ? a.GetString() : null;

            if (string.IsNullOrWhiteSpace(key))
            {
                _log.LogWarning("SysctlEnforcer: directive missing key; skipping");
                continue;
            }

            if (!IsValidKey(key))
            {
                _log.LogWarning("SysctlEnforcer: unsafe key {K}; skipping", key);
                continue;
            }

            switch (action)
            {
                case "Set":
                    if (string.IsNullOrEmpty(value))
                    {
                        _log.LogWarning("SysctlEnforcer: Set directive for {K} missing value; skipping", key);
                        continue;
                    }

                    if (!IsValidValue(value))
                    {
                        _log.LogWarning("SysctlEnforcer: unsafe value for {K}; skipping", key);
                        continue;
                    }

                    if (!current.TryGetValue(key, out var existing) || existing != value)
                    {
                        current[key] = value;
                        changed = true;
                    }

                    applied.Add($"sysctl:set:{key}");
                    break;

                case "Delete":
                    if (current.Remove(key))
                        changed = true;
                    applied.Add($"sysctl:delete:{key}");
                    break;

                default:
                    _log.LogWarning("SysctlEnforcer: unknown action {A} for {K}; skipping", action, key);
                    continue;
            }
        }

        if (!changed)
            return applied;

        await WriteDropinAsync(current, ct).ConfigureAwait(false);
        await ReloadAsync(ct).ConfigureAwait(false);
        return applied;
    }

    private static Dictionary<string, string> LoadDropin()
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);

        if (!File.Exists(DropinPath))
            return result;

        foreach (var raw in File.ReadAllLines(DropinPath))
        {
            var line = raw.Trim();
            if (line.StartsWith('#') || line.Length == 0)
                continue;

            var eq = line.IndexOf('=');
            if (eq < 1) continue;

            var k = line[..eq].Trim();
            var v = line[(eq + 1)..].Trim();

            if (IsValidKey(k))
                result[k] = v;
        }

        return result;
    }

    [SupportedOSPlatform("linux")]
    private async Task WriteDropinAsync(
        Dictionary<string, string> entries, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Managed by DDS — do not edit manually.");

        foreach (var (k, v) in entries.OrderBy(e => e.Key, StringComparer.Ordinal))
            sb.AppendLine($"{k} = {v}");

        var content = sb.ToString();

        if (_auditOnly)
        {
            _log.LogInformation(
                "[audit] would write {Path} ({N} entries)", DropinPath, entries.Count);
            return;
        }

        var dir = Path.GetDirectoryName(DropinPath)!;
        Directory.CreateDirectory(dir);

        var tmp = DropinPath + ".dds-tmp";
        await File.WriteAllTextAsync(tmp, content, Encoding.UTF8, ct).ConfigureAwait(false);
        File.SetUnixFileMode(tmp,
            UnixFileMode.UserRead | UnixFileMode.UserWrite |
            UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        File.Move(tmp, DropinPath, overwrite: true);
        _log.LogInformation("SysctlEnforcer: wrote {Path} ({N} entries)", DropinPath, entries.Count);
    }

    private async Task ReloadAsync(CancellationToken ct)
    {
        if (_auditOnly)
        {
            _log.LogInformation("[audit] would run: sysctl --system");
            return;
        }

        var result = await _runner.RunAsync("sysctl", "--system", ct).ConfigureAwait(false);
        if (!result.Success)
            _log.LogWarning("sysctl --system exited {Code}: {Err}",
                result.ExitCode, result.Stderr);
    }

    /// Remove sysctl keys that are no longer declared in any applicable policy.
    ///
    /// Loads the current drop-in, computes the stale set (current keys minus
    /// <paramref name="desiredKeys"/>), removes them, and rewrites the file.
    /// Returns the directive tags for each removed key (e.g. "sysctl:delete:...").
    /// Returns empty if the drop-in does not exist or no keys are stale.
    public async Task<List<string>> ReconcileStaleKeysAsync(
        IReadOnlySet<string> desiredKeys, CancellationToken ct)
    {
        var current = LoadDropin();
        if (current.Count == 0)
            return [];

        var stale = current.Keys.Where(k => !desiredKeys.Contains(k)).ToList();
        if (stale.Count == 0)
            return [];

        _log.LogInformation(
            "SysctlEnforcer reconciliation: {Count} stale key(s) to remove", stale.Count);

        var applied = new List<string>(stale.Count);
        foreach (var k in stale)
        {
            current.Remove(k);
            applied.Add($"sysctl:delete:{k}");
        }

        await WriteDropinAsync(current, ct).ConfigureAwait(false);
        await ReloadAsync(ct).ConfigureAwait(false);
        return applied;
    }

    // Valid sysctl key: one or more dotted segments of [a-zA-Z0-9_], e.g. "net.ipv4.ip_forward".
    internal static bool IsValidKey(string key)
    {
        if (string.IsNullOrEmpty(key) || key.Length > 128) return false;
        foreach (var segment in key.Split('.'))
        {
            if (segment.Length == 0) return false;
            foreach (var c in segment)
                if (!char.IsAsciiLetterOrDigit(c) && c != '_') return false;
        }
        return true;
    }

    // Valid sysctl value: printable ASCII, no shell metacharacters or newlines.
    internal static bool IsValidValue(string value)
    {
        if (value.Length > 256) return false;
        foreach (var c in value)
        {
            if (c < 0x20 || c > 0x7E) return false;      // non-printable / non-ASCII
            if (c is '`' or '$' or ';' or '|' or '&' or '>' or '<' or '\\' or '"' or '\'')
                return false;
        }
        return true;
    }
}
