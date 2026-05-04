// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Linux.Runtime;

namespace DDS.PolicyAgent.Linux.Enforcers;

/// Applies LinuxUserDirective entries (create / modify / delete / enable / disable).
///
/// Safety invariants:
///   - Will not modify UIDs below MinUid (default 1000) — prevents root/system account tampering.
///   - Delete is refused for accounts not listed in `managedUsernames` (caller-supplied from
///     applied state).  In audit mode, neither invariant is violated because no commands run.
public sealed class UserEnforcer
{
    private const int MinUid = 1000;

    private readonly ICommandRunner _runner;
    private readonly bool _auditOnly;
    private readonly ILogger _log;

    public UserEnforcer(ICommandRunner runner, bool auditOnly, ILogger log)
    {
        _runner = runner;
        _auditOnly = auditOnly;
        _log = log;
    }

    public async Task<List<string>> ApplyAsync(
        IReadOnlyList<JsonElement> directives,
        IReadOnlySet<string> managedUsernames,
        CancellationToken ct)
    {
        var applied = new List<string>();

        foreach (var d in directives)
        {
            var username = d.TryGetProperty("username", out var u) ? u.GetString() : null;
            var action   = d.TryGetProperty("action",   out var a) ? a.GetString() : null;

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(action))
            {
                _log.LogWarning("UserEnforcer: directive missing username or action; skipping");
                continue;
            }

            if (!IsValidUsername(username))
            {
                _log.LogWarning("UserEnforcer: unsafe username {U}; skipping", username);
                continue;
            }

            var uid = d.TryGetProperty("uid", out var uidEl) && uidEl.ValueKind == JsonValueKind.Number
                ? uidEl.GetUInt32()
                : (uint?)null;

            if (uid.HasValue && uid.Value < MinUid)
            {
                _log.LogWarning("UserEnforcer: UID {Uid} below minimum {Min}; skipping {U}",
                    uid.Value, MinUid, username);
                continue;
            }

            var tag = $"user:{action.ToLowerInvariant()}:{username}";

            switch (action)
            {
                case "Create":
                    await ApplyCreateAsync(username, d, uid, ct).ConfigureAwait(false);
                    break;

                case "Delete":
                    if (!managedUsernames.Contains(username))
                    {
                        _log.LogWarning("UserEnforcer: {U} not DDS-managed; refusing Delete", username);
                        continue;
                    }
                    await RunOrLogAsync("userdel", $"-r {username}", ct).ConfigureAwait(false);
                    break;

                case "Disable":
                    await RunOrLogAsync("passwd", $"-l {username}", ct).ConfigureAwait(false);
                    break;

                case "Enable":
                    await RunOrLogAsync("passwd", $"-u {username}", ct).ConfigureAwait(false);
                    break;

                case "Modify":
                    await ApplyModifyAsync(username, d, ct).ConfigureAwait(false);
                    break;

                default:
                    _log.LogWarning("UserEnforcer: unknown action {A} for {U}; skipping", action, username);
                    continue;
            }

            applied.Add(tag);
        }

        return applied;
    }

    private async Task ApplyCreateAsync(
        string username, JsonElement d, uint? uid, CancellationToken ct)
    {
        var args = BuildUseraddArgs(username, d, uid);
        if (!await UserExistsAsync(username, ct).ConfigureAwait(false))
        {
            await RunOrLogAsync("useradd", args, ct).ConfigureAwait(false);
        }
        else
        {
            _log.LogDebug("UserEnforcer: {U} already exists; skipping create", username);
        }

        await ApplyGroupsAsync(username, d, ct).ConfigureAwait(false);
    }

    private async Task ApplyModifyAsync(string username, JsonElement d, CancellationToken ct)
    {
        var parts = new List<string>();

        if (d.TryGetProperty("shell", out var shell) && shell.ValueKind == JsonValueKind.String)
            parts.Add($"-s {shell.GetString()}");

        if (d.TryGetProperty("full_name", out var fn) && fn.ValueKind == JsonValueKind.String)
            parts.Add($"-c {ShellEscape(fn.GetString()!)}");

        if (parts.Count > 0)
            await RunOrLogAsync("usermod", $"{string.Join(" ", parts)} {username}", ct).ConfigureAwait(false);

        await ApplyGroupsAsync(username, d, ct).ConfigureAwait(false);
    }

    private async Task ApplyGroupsAsync(string username, JsonElement d, CancellationToken ct)
    {
        if (!d.TryGetProperty("groups", out var groups) ||
            groups.ValueKind != JsonValueKind.Array)
            return;

        foreach (var g in groups.EnumerateArray())
        {
            var gname = g.GetString();
            if (string.IsNullOrWhiteSpace(gname)) continue;
            await RunOrLogAsync("usermod", $"-aG {gname} {username}", ct).ConfigureAwait(false);
        }
    }

    private static string BuildUseraddArgs(string username, JsonElement d, uint? uid)
    {
        var parts = new List<string> { "-m" };

        if (uid.HasValue)
            parts.Add($"-u {uid.Value}");

        if (d.TryGetProperty("shell", out var shell) && shell.ValueKind == JsonValueKind.String)
            parts.Add($"-s {shell.GetString()}");

        if (d.TryGetProperty("full_name", out var fn) && fn.ValueKind == JsonValueKind.String)
            parts.Add($"-c {ShellEscape(fn.GetString()!)}");

        parts.Add(username);
        return string.Join(" ", parts);
    }

    private async Task<bool> UserExistsAsync(string username, CancellationToken ct)
    {
        if (_auditOnly) return false;
        var result = await _runner.RunAsync("id", $"-u {username}", ct).ConfigureAwait(false);
        return result.Success;
    }

    private async Task RunOrLogAsync(string cmd, string args, CancellationToken ct)
    {
        if (_auditOnly)
        {
            _log.LogInformation("[audit] would run: {Cmd} {Args}", cmd, args);
            return;
        }

        var result = await _runner.RunAsync(cmd, args, ct).ConfigureAwait(false);
        if (!result.Success)
            _log.LogWarning("{Cmd} {Args} exited {Code}: {Err}", cmd, args, result.ExitCode, result.Stderr);
    }

    /// Locks each stale DDS-managed user account with `passwd -l` (disable, not delete,
    /// to preserve home directory and files). Items not passing validation are skipped.
    public async Task<List<string>> ReconcileStaleUsersAsync(
        IEnumerable<string> staleUsernames, CancellationToken ct)
    {
        var applied = new List<string>();
        foreach (var username in staleUsernames)
        {
            if (!IsValidUsername(username))
            {
                _log.LogWarning("UserEnforcer: reconcile skip unsafe username {U}", username);
                continue;
            }
            _log.LogInformation("Reconciliation: disabling stale DDS-managed user {U}", username);
            await RunOrLogAsync("passwd", $"-l {username}", ct).ConfigureAwait(false);
            applied.Add($"user:disable:{username}");
        }
        return applied;
    }

    internal static bool IsValidUsername(string name)
    {
        if (name.Length == 0 || name.Length > 32) return false;
        foreach (var c in name)
            if (!char.IsAsciiLetterOrDigit(c) && c != '_' && c != '-' && c != '.')
                return false;
        if (name[0] == '-') return false;
        return true;
    }

    private static string ShellEscape(string s)
        => $"'{s.Replace("'", "'\\''")}'";
}
