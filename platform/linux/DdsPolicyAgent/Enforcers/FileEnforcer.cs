// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Security.Cryptography;
using System.Text.Json;
using DDS.PolicyAgent.Linux.Runtime;

namespace DDS.PolicyAgent.Linux.Enforcers;

/// Applies LinuxFileDirective entries (set / delete / ensure-dir).
///
/// Safety invariants:
///   - Path must be absolute and must not contain `..` components.
///   - Delete is only applied to paths in the DDS-managed set.
///   - SHA-256 of decoded content is verified before writing.
///   - Files are written atomically via a temp file + rename in the same directory.
public sealed class FileEnforcer
{
    private readonly ICommandRunner _runner;
    private readonly bool _auditOnly;
    private readonly ILogger _log;

    public FileEnforcer(ICommandRunner runner, bool auditOnly, ILogger log)
    {
        _runner = runner;
        _auditOnly = auditOnly;
        _log = log;
    }

    public async Task<List<string>> ApplyAsync(
        IReadOnlyList<JsonElement> directives,
        IReadOnlySet<string> managedPaths,
        CancellationToken ct)
    {
        var applied = new List<string>();

        foreach (var d in directives)
        {
            var path   = d.TryGetProperty("path",   out var p) ? p.GetString() : null;
            var action = d.TryGetProperty("action", out var a) ? a.GetString() : null;

            if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(action))
            {
                _log.LogWarning("FileEnforcer: directive missing path or action; skipping");
                continue;
            }

            if (!IsSafePath(path))
            {
                _log.LogWarning("FileEnforcer: unsafe path {P}; skipping", path);
                continue;
            }

            var tag = $"file:{action.ToLowerInvariant()}:{path}";

            switch (action)
            {
                case "Set":
                    if (!await ApplySetAsync(path, d, ct).ConfigureAwait(false))
                        continue;
                    break;

                case "Delete":
                    if (!managedPaths.Contains(path))
                    {
                        _log.LogWarning("FileEnforcer: {P} not DDS-managed; refusing Delete", path);
                        continue;
                    }
                    ApplyDelete(path);
                    break;

                case "EnsureDir":
                    await ApplyEnsureDirAsync(path, d, ct).ConfigureAwait(false);
                    break;

                default:
                    _log.LogWarning("FileEnforcer: unknown action {A} for {P}; skipping", action, path);
                    continue;
            }

            applied.Add(tag);
        }

        return applied;
    }

    private async Task<bool> ApplySetAsync(string path, JsonElement d, CancellationToken ct)
    {
        var contentB64 = d.TryGetProperty("content_b64", out var cb) ? cb.GetString() : null;
        if (string.IsNullOrEmpty(contentB64))
        {
            _log.LogWarning("FileEnforcer: Set action for {P} missing content_b64; skipping", path);
            return false;
        }

        byte[] bytes;
        try { bytes = Convert.FromBase64String(contentB64); }
        catch (FormatException)
        {
            _log.LogWarning("FileEnforcer: content_b64 malformed for {P}; skipping", path);
            return false;
        }

        if (d.TryGetProperty("content_sha256", out var shaEl) &&
            shaEl.ValueKind == JsonValueKind.String)
        {
            var expectedSha = shaEl.GetString()!;
            var actualSha   = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
            if (!string.Equals(actualSha, expectedSha.ToLowerInvariant(), StringComparison.Ordinal))
            {
                _log.LogWarning("FileEnforcer: SHA-256 mismatch for {P}; skipping", path);
                return false;
            }
        }

        if (_auditOnly)
        {
            _log.LogInformation("[audit] would write {P} ({N} bytes)", path, bytes.Length);
            return true;
        }

        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);

        var tmp = path + ".dds-tmp";
        await File.WriteAllBytesAsync(tmp, bytes, ct).ConfigureAwait(false);
        await ApplyOwnerAndModeAsync(tmp, d, ct).ConfigureAwait(false);
        File.Move(tmp, path, overwrite: true);
        _log.LogInformation("FileEnforcer: wrote {P}", path);
        return true;
    }

    private void ApplyDelete(string path)
    {
        if (_auditOnly)
        {
            _log.LogInformation("[audit] would delete {P}", path);
            return;
        }

        if (File.Exists(path))
        {
            File.Delete(path);
            _log.LogInformation("FileEnforcer: deleted {P}", path);
        }
    }

    private async Task ApplyEnsureDirAsync(string path, JsonElement d, CancellationToken ct)
    {
        if (_auditOnly)
        {
            _log.LogInformation("[audit] would ensure dir {P}", path);
            return;
        }

        Directory.CreateDirectory(path);
        await ApplyOwnerAndModeAsync(path, d, ct).ConfigureAwait(false);
        _log.LogInformation("FileEnforcer: ensured dir {P}", path);
    }

    private async Task ApplyOwnerAndModeAsync(string path, JsonElement d, CancellationToken ct)
    {
        if (d.TryGetProperty("owner", out var owner) && owner.ValueKind == JsonValueKind.String)
        {
            var ownerVal = owner.GetString()!;
            if (!IsSafeOwner(ownerVal))
            {
                _log.LogWarning("FileEnforcer: unsafe owner value {O} for {P}; skipping chown", ownerVal, path);
            }
            else
            {
                var result = await _runner
                    .RunAsync("chown", $"{ownerVal} {path}", ct)
                    .ConfigureAwait(false);
                if (!result.Success)
                    _log.LogWarning("chown failed for {P}: {Err}", path, result.Stderr);
            }
        }

        if (d.TryGetProperty("mode", out var mode) && mode.ValueKind == JsonValueKind.String)
        {
            var modeVal = mode.GetString()!;
            if (!IsSafeMode(modeVal))
            {
                _log.LogWarning("FileEnforcer: unsafe mode value {M} for {P}; skipping chmod", modeVal, path);
            }
            else
            {
                var result = await _runner
                    .RunAsync("chmod", $"{modeVal} {path}", ct)
                    .ConfigureAwait(false);
                if (!result.Success)
                    _log.LogWarning("chmod failed for {P}: {Err}", path, result.Stderr);
            }
        }
    }

    /// Deletes each stale DDS-managed file. Only safe, allowlisted paths are processed.
    public List<string> ReconcileStaleFiles(IEnumerable<string> stalePaths)
    {
        var applied = new List<string>();
        foreach (var path in stalePaths)
        {
            if (!IsSafePath(path))
            {
                _log.LogWarning("FileEnforcer: reconcile skip unsafe path {P}", path);
                continue;
            }
            _log.LogInformation("Reconciliation: deleting stale DDS-managed file {P}", path);
            ApplyDelete(path);
            applied.Add($"file:delete:{path}");
        }
        return applied;
    }

    internal static bool IsSafePath(string path)
    {
        if (!Path.IsPathRooted(path)) return false;
        var normalized = Path.GetFullPath(path);
        return normalized == path.TrimEnd('/');
    }

    // Valid owner: "user" or "user:group" where each part is a POSIX name ([a-zA-Z0-9_.-]+, ≤32 chars).
    // No spaces — prevents injecting extra arguments to chown (e.g. "nobody /etc/shadow").
    internal static bool IsSafeOwner(string owner)
    {
        if (string.IsNullOrEmpty(owner) || owner.Length > 65) return false;
        var parts = owner.Split(':', 2);
        foreach (var part in parts)
        {
            if (part.Length == 0 || part.Length > 32) return false;
            foreach (var c in part)
                if (!char.IsAsciiLetterOrDigit(c) && c != '_' && c != '-' && c != '.')
                    return false;
        }
        return true;
    }

    // Valid mode: 3 or 4 octal digits only (e.g. "644", "0644", "1777").
    // Rejects symbolic notation to prevent spaces and argument injection.
    internal static bool IsSafeMode(string mode)
    {
        if (mode.Length is < 3 or > 4) return false;
        foreach (var c in mode)
            if (c < '0' || c > '7') return false;
        return true;
    }
}
