// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using DDS.PolicyAgent.MacOS.Config;
using DDS.PolicyAgent.MacOS.Runtime;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.MacOS.Enforcers;

public enum PreferenceScope
{
    System,
    UserTemplate,
}

public interface IMacPreferenceOperations
{
    string? GetValueJson(string domain, string key, PreferenceScope scope);
    void SetValueJson(string domain, string key, PreferenceScope scope, string valueJson);
    void DeleteValue(string domain, string key, PreferenceScope scope);
}

public sealed class InMemoryMacPreferenceOperations : IMacPreferenceOperations
{
    private readonly Dictionary<(PreferenceScope Scope, string Domain, string Key), string> _values = new();

    public string? GetValueJson(string domain, string key, PreferenceScope scope)
        => _values.TryGetValue((scope, domain, key), out var value) ? value : null;

    public void SetValueJson(string domain, string key, PreferenceScope scope, string valueJson)
        => _values[(scope, domain, key)] = valueJson;

    public void DeleteValue(string domain, string key, PreferenceScope scope)
        => _values.Remove((scope, domain, key));
}

public sealed class HostMacPreferenceOperations : IMacPreferenceOperations
{
    private readonly ICommandRunner _runner;
    private readonly AgentConfig _config;

    public HostMacPreferenceOperations(
        ICommandRunner runner,
        IOptions<AgentConfig> config)
    {
        _runner = runner;
        _config = config.Value;
    }

    public string? GetValueJson(string domain, string key, PreferenceScope scope)
    {
        var path = ResolvePlistPath(domain, scope);
        if (!File.Exists(path))
            return null;

        var doc = ReadDocument(path);
        return doc.TryGetPropertyValue(key, out var value) && value is not null
            ? value.ToJsonString()
            : null;
    }

    public void SetValueJson(string domain, string key, PreferenceScope scope, string valueJson)
    {
        var path = ResolvePlistPath(domain, scope);
        var doc = ReadDocument(path);
        doc[key] = JsonNode.Parse(valueJson);
        WriteDocument(path, doc);
    }

    public void DeleteValue(string domain, string key, PreferenceScope scope)
    {
        var path = ResolvePlistPath(domain, scope);
        if (!File.Exists(path))
            return;

        var doc = ReadDocument(path);
        if (!doc.Remove(key))
            return;

        if (doc.Count == 0)
        {
            File.Delete(path);
            return;
        }

        WriteDocument(path, doc);
    }

    private JsonObject ReadDocument(string path)
    {
        if (!File.Exists(path))
            return [];

        var result = _runner.RunChecked(
            "/usr/bin/plutil",
            ["-convert", "json", "-o", "-", path]);
        var node = JsonNode.Parse(result.StandardOutput) as JsonObject;
        return node ?? [];
    }

    private void WriteDocument(string path, JsonObject doc)
    {
        var dir = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException($"invalid plist path '{path}'");
        Directory.CreateDirectory(dir);

        var tempJsonPath = Path.Combine(
            dir,
            $".{Path.GetFileNameWithoutExtension(path)}.{Guid.NewGuid():N}.json");

        File.WriteAllText(tempJsonPath, doc.ToJsonString());
        try
        {
            _runner.RunChecked(
                "/usr/bin/plutil",
                ["-convert", "binary1", tempJsonPath, "-o", path]);
        }
        finally
        {
            try { File.Delete(tempJsonPath); }
            catch { }
        }
    }

    private string ResolvePlistPath(string domain, PreferenceScope scope)
    {
        var root = scope switch
        {
            PreferenceScope.System => _config.ResolveManagedPreferencesDir(),
            PreferenceScope.UserTemplate => _config.ResolveUserTemplatePreferencesDir(),
            _ => throw new InvalidOperationException($"unsupported preference scope {scope}"),
        };

        return Path.Combine(root, $"{domain}.plist");
    }
}

/// <summary>
/// Applies <c>MacOsSettings.preferences</c> directives. The v1
/// implementation focuses on validation, idempotency, and audit
/// behavior while delegating storage to an operation interface. The
/// default host implementation writes managed plist files with
/// `plutil`; tests can still inject in-memory doubles.
/// </summary>
public sealed class PreferenceEnforcer : IEnforcer
{
    private readonly IMacPreferenceOperations _ops;
    private readonly ILogger<PreferenceEnforcer> _log;

    public string Name => "Preferences";

    public PreferenceEnforcer(
        IMacPreferenceOperations ops,
        ILogger<PreferenceEnforcer> log)
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
                _log.LogError(ex, "Preference enforcer failed on {Directive}", desc);
                changes.Add($"FAILED: {desc} — {ex.Message}");
                firstError ??= ex.Message;
                overallStatus = EnforcementStatus.Failed;
            }
        }

        return Task.FromResult(new EnforcementOutcome(overallStatus, firstError, changes));
    }

    private string ApplyOne(JsonElement item, EnforcementMode mode)
    {
        var domain = item.GetProperty("domain").GetString() ?? throw new InvalidOperationException("missing domain");
        var key = item.GetProperty("key").GetString() ?? throw new InvalidOperationException("missing key");
        var action = item.GetProperty("action").GetString() ?? throw new InvalidOperationException("missing action");
        var scope = ParseScope(item);

        if (!IsValidDomain(domain))
            throw new InvalidOperationException($"invalid preference domain '{domain}'");

        var desc = $"{action} {scope}:{domain}:{key}";
        if (mode == EnforcementMode.Audit)
        {
            _log.LogInformation("[AUDIT] Preferences: would {Action}", desc);
            return $"[AUDIT] {desc}";
        }

        switch (action)
        {
            case "Set":
                if (!item.TryGetProperty("value", out var value))
                    throw new InvalidOperationException("Set action requires value");
                var valueJson = NormalizeJson(value.GetRawText());
                var current = _ops.GetValueJson(domain, key, scope);
                if (current == valueJson)
                    return $"[NO-OP] {desc} (already set)";
                _ops.SetValueJson(domain, key, scope, valueJson);
                _log.LogInformation("Preferences: {Action}", desc);
                return desc;

            case "Delete":
                _ops.DeleteValue(domain, key, scope);
                _log.LogInformation("Preferences: {Action}", desc);
                return desc;

            default:
                throw new InvalidOperationException($"unknown preference action: {action}");
        }
    }

    private static PreferenceScope ParseScope(JsonElement item)
    {
        if (!item.TryGetProperty("scope", out var s) || s.ValueKind == JsonValueKind.Null)
            return PreferenceScope.System;

        return s.GetString() switch
        {
            "System" => PreferenceScope.System,
            "UserTemplate" => PreferenceScope.UserTemplate,
            _ => throw new InvalidOperationException($"unknown preference scope: {s.GetString()}"),
        };
    }

    internal static bool IsValidDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
            return false;
        foreach (var c in domain)
        {
            if (char.IsLetterOrDigit(c) || c == '.' || c == '-')
                continue;
            return false;
        }
        return true;
    }

    internal static string NormalizeJson(string valueJson)
    {
        var node = JsonNode.Parse(valueJson);
        return node?.ToJsonString() ?? "null";
    }

    private static string DescribeDirective(JsonElement item)
    {
        var domain = item.TryGetProperty("domain", out var d) ? d.GetString() : "?";
        var key = item.TryGetProperty("key", out var k) ? k.GetString() : "?";
        var action = item.TryGetProperty("action", out var a) ? a.GetString() : "?";
        return $"{action} {domain}:{key}";
    }
}
