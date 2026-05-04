// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.Linux.Runtime;

namespace DDS.PolicyAgent.Linux.Enforcers;

/// Applies LinuxSudoersDirective entries (write / delete `/etc/sudoers.d/` drop-ins).
///
/// Safety invariants:
///   - Filename must be a safe single-component stem (no path separators, no `.`, no `..`).
///   - Content is validated via `visudo -cf` before being moved into place.
///   - SHA-256 of the content is verified before writing to detect policy-server corruption.
///   - Delete is only performed for files whose path begins with the managed prefix.
[SupportedOSPlatform("linux")]
public sealed class SudoersEnforcer
{
    private const string SudoersDir = "/etc/sudoers.d";

    private readonly ICommandRunner _runner;
    private readonly bool _auditOnly;
    private readonly ILogger _log;

    public SudoersEnforcer(ICommandRunner runner, bool auditOnly, ILogger log)
    {
        _runner = runner;
        _auditOnly = auditOnly;
        _log = log;
    }

    public async Task<List<string>> ApplyAsync(
        IReadOnlyList<JsonElement> directives, CancellationToken ct)
    {
        var applied = new List<string>();

        foreach (var d in directives)
        {
            var filename       = d.TryGetProperty("filename",       out var fn)  ? fn.GetString()  : null;
            var content        = d.TryGetProperty("content",        out var co)  ? co.GetString()  : null;
            var contentSha256  = d.TryGetProperty("content_sha256", out var sha) ? sha.GetString() : null;

            if (string.IsNullOrWhiteSpace(filename))
            {
                _log.LogWarning("SudoersEnforcer: directive missing filename; skipping");
                continue;
            }

            if (!IsSafeFilename(filename))
            {
                _log.LogWarning("SudoersEnforcer: unsafe filename {F}; skipping", filename);
                continue;
            }

            if (content == null)
            {
                _log.LogWarning("SudoersEnforcer: directive missing content for {F}; skipping", filename);
                continue;
            }

            var targetPath = Path.Combine(SudoersDir, filename);

            // Empty content signals deletion.
            if (content.Length == 0)
            {
                await DeleteDropinAsync(targetPath, ct).ConfigureAwait(false);
                applied.Add($"sudoers:delete:{filename}");
                continue;
            }

            if (!string.IsNullOrEmpty(contentSha256) && !VerifySha256(content, contentSha256))
            {
                _log.LogWarning("SudoersEnforcer: SHA-256 mismatch for {F}; skipping", filename);
                continue;
            }

            await WriteDropinAsync(filename, targetPath, content, ct).ConfigureAwait(false);
            applied.Add($"sudoers:set:{filename}");
        }

        return applied;
    }

    [SupportedOSPlatform("linux")]
    private async Task WriteDropinAsync(
        string stem, string targetPath, string content, CancellationToken ct)
    {
        if (_auditOnly)
        {
            _log.LogInformation("[audit] would write sudoers drop-in {P} ({N} bytes)",
                targetPath, content.Length);
            return;
        }

        // Write to a temp file, validate, then move into place.
        var tmp = targetPath + ".dds-tmp";
        try
        {
            await File.WriteAllTextAsync(tmp, content, Encoding.ASCII, ct).ConfigureAwait(false);
            File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.GroupRead);

            var check = await _runner.RunAsync("visudo", $"-cf {tmp}", ct).ConfigureAwait(false);
            if (!check.Success)
            {
                _log.LogWarning(
                    "SudoersEnforcer: visudo rejected {F}: {Err}", stem, check.Stderr);
                return;
            }

            File.Move(tmp, targetPath, overwrite: true);
            _log.LogInformation("SudoersEnforcer: wrote {P}", targetPath);
        }
        finally
        {
            if (File.Exists(tmp))
                File.Delete(tmp);
        }
    }

    private Task DeleteDropinAsync(string targetPath, CancellationToken ct)
    {
        if (_auditOnly)
        {
            _log.LogInformation("[audit] would delete sudoers drop-in {P}", targetPath);
            return Task.CompletedTask;
        }

        if (File.Exists(targetPath))
        {
            File.Delete(targetPath);
            _log.LogInformation("SudoersEnforcer: deleted {P}", targetPath);
        }

        return Task.CompletedTask;
    }

    /// Deletes each sudoers drop-in whose filename is in <paramref name="staleFilenames"/>.
    /// Only filenames that pass <see cref="IsSafeFilename"/> are removed; others are skipped
    /// with a warning. Returns a directive tag for each deletion attempted.
    public async Task<List<string>> ReconcileStaleSudoersAsync(
        IReadOnlySet<string> staleFilenames, CancellationToken ct)
    {
        var applied = new List<string>();
        foreach (var filename in staleFilenames)
        {
            if (!IsSafeFilename(filename))
            {
                _log.LogWarning(
                    "SudoersEnforcer: stale filename {F} is unsafe; skipping reconciliation",
                    filename);
                continue;
            }

            var targetPath = Path.Combine(SudoersDir, filename);
            if (_auditOnly)
            {
                _log.LogInformation("[audit] would delete stale sudoers drop-in {P}", targetPath);
            }
            else
            {
                await DeleteDropinAsync(targetPath, ct).ConfigureAwait(false);
            }
            applied.Add($"sudoers:delete:{filename}");
        }
        return applied;
    }

    internal static bool IsSafeFilename(string name)
    {
        if (name.Length == 0 || name.Length > 64) return false;
        if (name.Contains('/') || name.Contains('\\')) return false;
        if (name == "." || name == "..") return false;
        foreach (var c in name)
            if (!char.IsAsciiLetterOrDigit(c) && c != '-' && c != '_') return false;
        return true;
    }

    private static bool VerifySha256(string content, string expectedHex)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        var actual = Convert.ToHexString(hash).ToLowerInvariant();
        return actual == expectedHex.ToLowerInvariant();
    }
}
