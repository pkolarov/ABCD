// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using DDS.PolicyAgent.MacOS.Config;
using DDS.PolicyAgent.MacOS.Runtime;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.MacOS.Enforcers;

public interface IProfileOperations
{
    bool IsInstalled(string identifier, string payloadSha256);
    void Install(string identifier, string displayName, string payloadSha256, byte[] payloadBytes);
    void Remove(string identifier);
}

public sealed class InMemoryProfileOperations : IProfileOperations
{
    private readonly Dictionary<string, (string Name, string Sha, byte[] Payload)> _profiles = new();

    public bool IsInstalled(string identifier, string payloadSha256)
        => _profiles.TryGetValue(identifier, out var current) && current.Sha == payloadSha256;

    public void Install(string identifier, string displayName, string payloadSha256, byte[] payloadBytes)
        => _profiles[identifier] = (displayName, payloadSha256, payloadBytes);

    public void Remove(string identifier)
        => _profiles.Remove(identifier);
}

public sealed class HostProfileOperations : IProfileOperations
{
    private readonly ICommandRunner _runner;
    private readonly AgentConfig _config;

    public HostProfileOperations(
        ICommandRunner runner,
        IOptions<AgentConfig> config)
    {
        _runner = runner;
        _config = config.Value;
    }

    public bool IsInstalled(string identifier, string payloadSha256)
    {
        if (!ProfileExists(identifier))
            return false;

        var stamp = LoadStamp(identifier);
        return stamp is not null
            && string.Equals(
                NormalizeSha(stamp.PayloadSha256),
                NormalizeSha(payloadSha256),
                StringComparison.Ordinal);
    }

    public void Install(string identifier, string displayName, string payloadSha256, byte[] payloadBytes)
    {
        PrivilegeGuard.DemandRoot("configuration profile installation");
        Directory.CreateDirectory(_config.ResolveProfileStateDir());

        var payloadPath = Path.Combine(
            _config.ResolveProfileStateDir(),
            $"{SanitizeFileName(identifier)}.{Guid.NewGuid():N}.mobileconfig");

        File.WriteAllBytes(payloadPath, payloadBytes);
        try
        {
            _runner.RunChecked("/usr/bin/profiles", ["-I", "-F", payloadPath, "-f"]);
        }
        finally
        {
            try { File.Delete(payloadPath); }
            catch { }
        }

        SaveStamp(new InstalledProfileState
        {
            Identifier = identifier,
            DisplayName = displayName,
            PayloadSha256 = NormalizeSha(payloadSha256),
            UpdatedAtUtc = DateTimeOffset.UtcNow,
        });
    }

    public void Remove(string identifier)
    {
        PrivilegeGuard.DemandRoot("configuration profile removal");
        if (!ProfileExists(identifier))
        {
            DeleteStamp(identifier);
            return;
        }

        _runner.RunChecked("/usr/bin/profiles", ["-R", "-p", identifier, "-f"]);
        DeleteStamp(identifier);
    }

    private bool ProfileExists(string identifier)
    {
        var outputPath = Path.Combine(
            _config.ResolveProfileStateDir(),
            $"profiles-list.{Guid.NewGuid():N}.plist");
        Directory.CreateDirectory(_config.ResolveProfileStateDir());

        try
        {
            var result = _runner.Run("/usr/bin/profiles", ["-C", "-o", outputPath]);
            if (!result.Succeeded || !File.Exists(outputPath))
                return false;

            var json = _runner.RunChecked("/usr/bin/plutil", ["-convert", "json", "-o", "-", outputPath]);
            var root = JsonNode.Parse(json.StandardOutput);
            return ContainsIdentifier(root, identifier);
        }
        finally
        {
            try { File.Delete(outputPath); }
            catch { }
        }
    }

    private InstalledProfileState? LoadStamp(string identifier)
    {
        var path = StampPath(identifier);
        if (!File.Exists(path))
            return null;
        return JsonSerializer.Deserialize<InstalledProfileState>(File.ReadAllText(path));
    }

    private void SaveStamp(InstalledProfileState state)
    {
        Directory.CreateDirectory(_config.ResolveProfileStateDir());
        File.WriteAllText(StampPath(state.Identifier), JsonSerializer.Serialize(state));
    }

    private void DeleteStamp(string identifier)
    {
        try { File.Delete(StampPath(identifier)); }
        catch { }
    }

    private string StampPath(string identifier)
        => Path.Combine(_config.ResolveProfileStateDir(), $"{SanitizeFileName(identifier)}.json");

    private static bool ContainsIdentifier(JsonNode? node, string identifier)
    {
        if (node is null)
            return false;

        if (node is JsonObject obj)
        {
            foreach (var kvp in obj)
            {
                if (kvp.Value is JsonValue value &&
                    (kvp.Key.Equals("ProfileIdentifier", StringComparison.OrdinalIgnoreCase)
                    || kvp.Key.Equals("PayloadIdentifier", StringComparison.OrdinalIgnoreCase)
                    || kvp.Key.Equals("identifier", StringComparison.OrdinalIgnoreCase)) &&
                    string.Equals(value.GetValue<string>(), identifier, StringComparison.Ordinal))
                {
                    return true;
                }

                if (ContainsIdentifier(kvp.Value, identifier))
                    return true;
            }
        }
        else if (node is JsonArray array)
        {
            foreach (var child in array)
            {
                if (ContainsIdentifier(child, identifier))
                    return true;
            }
        }

        return false;
    }

    private static string NormalizeSha(string sha)
        => sha.StartsWith("sha256:", StringComparison.OrdinalIgnoreCase)
            ? sha["sha256:".Length..].ToLowerInvariant()
            : sha.ToLowerInvariant();

    private static string SanitizeFileName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        return new string(value.Select(c => invalid.Contains(c) ? '_' : c).ToArray());
    }

    private sealed class InstalledProfileState
    {
        public string Identifier { get; set; } = string.Empty;
        public string DisplayName { get; set; } = string.Empty;
        public string PayloadSha256 { get; set; } = string.Empty;
        public DateTimeOffset UpdatedAtUtc { get; set; }
    }
}

public sealed class ProfileEnforcer : IEnforcer
{
    private readonly IProfileOperations _ops;
    private readonly ILogger<ProfileEnforcer> _log;

    public string Name => "Profiles";

    public ProfileEnforcer(
        IProfileOperations ops,
        ILogger<ProfileEnforcer> log)
    {
        _ops = ops;
        _log = log;
    }

    public Task<EnforcementOutcome> ApplyAsync(
        JsonElement directive,
        EnforcementMode mode,
        CancellationToken ct = default)
    {
        if (directive.ValueKind != JsonValueKind.Array)
            return Task.FromResult(new EnforcementOutcome(EnforcementStatus.Skipped));

        var changes = new List<string>();
        string? firstError = null;
        var overallStatus = EnforcementStatus.Ok;

        foreach (var item in directive.EnumerateArray())
        {
            try
            {
                changes.Add(ApplyOne(item, mode));
            }
            catch (Exception ex)
            {
                var desc = DescribeDirective(item);
                _log.LogError(ex, "Profile enforcer failed on {Directive}", desc);
                changes.Add($"FAILED: {desc} — {ex.Message}");
                firstError ??= ex.Message;
                overallStatus = EnforcementStatus.Failed;
            }
        }

        return Task.FromResult(new EnforcementOutcome(overallStatus, firstError, changes));
    }

    private string ApplyOne(JsonElement item, EnforcementMode mode)
    {
        var identifier = item.GetProperty("identifier").GetString()
            ?? throw new InvalidOperationException("missing identifier");
        var action = item.GetProperty("action").GetString()
            ?? throw new InvalidOperationException("missing action");
        var desc = $"{action} profile {identifier}";

        if (mode == EnforcementMode.Audit)
        {
            _log.LogInformation("[AUDIT] Profiles: would {Action}", desc);
            return $"[AUDIT] {desc}";
        }

        switch (action)
        {
            case "Install":
            {
                var displayName = item.GetProperty("display_name").GetString()
                    ?? throw new InvalidOperationException("missing display_name");
                var sha = item.GetProperty("payload_sha256").GetString()
                    ?? throw new InvalidOperationException("missing payload_sha256");
                var b64 = item.GetProperty("mobileconfig_b64").GetString()
                    ?? throw new InvalidOperationException("missing mobileconfig_b64");

                if (_ops.IsInstalled(identifier, sha))
                    return $"[NO-OP] {desc} (already installed)";

                byte[] payload;
                try
                {
                    payload = Convert.FromBase64String(b64);
                }
                catch (FormatException ex)
                {
                    throw new InvalidOperationException("invalid mobileconfig base64", ex);
                }

                _ops.Install(identifier, displayName, sha, payload);
                _log.LogInformation("Profiles: installed {Identifier}", identifier);
                return desc;
            }

            case "Remove":
                _ops.Remove(identifier);
                _log.LogInformation("Profiles: removed {Identifier}", identifier);
                return desc;

            default:
                throw new InvalidOperationException($"unknown profile action: {action}");
        }
    }

    /// <summary>
    /// Extract the managed-item key (identifier) for an Install directive.
    /// Returns null for non-Install actions.
    /// </summary>
    public static string? ExtractManagedKey(JsonElement item)
    {
        var action = item.TryGetProperty("action", out var a) ? a.GetString() : null;
        if (action != "Install") return null;
        return item.TryGetProperty("identifier", out var i) ? i.GetString() : null;
    }

    /// <summary>
    /// Remove configuration profiles that were previously managed by DDS
    /// but are no longer present in the current policy.
    /// </summary>
    public List<string> ReconcileStaleProfiles(IReadOnlySet<string> staleKeys, EnforcementMode mode)
    {
        var changes = new List<string>();
        foreach (var identifier in staleKeys)
        {
            try
            {
                var desc = $"Reconcile-Remove profile {identifier}";

                if (mode == EnforcementMode.Audit)
                {
                    _log.LogInformation("[AUDIT] Profile reconcile: would remove {Identifier}", identifier);
                    changes.Add($"[AUDIT] {desc}");
                    continue;
                }

                _ops.Remove(identifier);
                _log.LogInformation("Profile reconcile: removed stale profile {Identifier}", identifier);
                changes.Add(desc);
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Profile reconcile failed for {Identifier}", identifier);
                changes.Add($"FAILED: Reconcile-Remove profile {identifier} — {ex.Message}");
            }
        }
        return changes;
    }

    private static string DescribeDirective(JsonElement item)
    {
        var identifier = item.TryGetProperty("identifier", out var i) ? i.GetString() : "?";
        var action = item.TryGetProperty("action", out var a) ? a.GetString() : "?";
        return $"{action} profile {identifier}";
    }
}
