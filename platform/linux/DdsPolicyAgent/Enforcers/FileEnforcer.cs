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
            var result = await _runner
                .RunAsync("chown", $"{owner.GetString()} {path}", ct)
                .ConfigureAwait(false);
            if (!result.Success)
                _log.LogWarning("chown failed for {P}: {Err}", path, result.Stderr);
        }

        if (d.TryGetProperty("mode", out var mode) && mode.ValueKind == JsonValueKind.String)
        {
            var result = await _runner
                .RunAsync("chmod", $"{mode.GetString()} {path}", ct)
                .ConfigureAwait(false);
            if (!result.Success)
                _log.LogWarning("chmod failed for {P}: {Err}", path, result.Stderr);
        }
    }

    internal static bool IsSafePath(string path)
    {
        if (!Path.IsPathRooted(path)) return false;
        var normalized = Path.GetFullPath(path);
        return normalized == path.TrimEnd('/');
    }
}
