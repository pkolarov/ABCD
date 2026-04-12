// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.MacOS.Config;
using DDS.PolicyAgent.MacOS.Runtime;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.MacOS.Enforcers;

public interface ILaunchdOperations
{
    bool HasJob(string label);
    void Configure(string label, string plistPath, bool? enabled);
    void Load(string label);
    void Unload(string label);
    void Kickstart(string label);
}

public sealed class InMemoryLaunchdOperations : ILaunchdOperations
{
    public sealed class JobState
    {
        public string Label { get; set; } = string.Empty;
        public string PlistPath { get; set; } = string.Empty;
        public bool? Enabled { get; set; }
        public bool Loaded { get; set; }
    }

    private readonly Dictionary<string, JobState> _jobs = new(StringComparer.OrdinalIgnoreCase);

    public bool HasJob(string label) => _jobs.ContainsKey(label);

    public void Configure(string label, string plistPath, bool? enabled)
    {
        _jobs[label] = new JobState
        {
            Label = label,
            PlistPath = plistPath,
            Enabled = enabled,
            Loaded = _jobs.TryGetValue(label, out var existing) && existing.Loaded,
        };
    }

    public void Load(string label)
    {
        if (_jobs.TryGetValue(label, out var job))
            job.Loaded = true;
        else
            _jobs[label] = new JobState { Label = label, Loaded = true };
    }

    public void Unload(string label)
    {
        if (_jobs.TryGetValue(label, out var job))
            job.Loaded = false;
    }

    public void Kickstart(string label)
    {
        if (_jobs.TryGetValue(label, out var job))
            job.Loaded = true;
        else
            _jobs[label] = new JobState { Label = label, Loaded = true };
    }

    public JobState? Peek(string label) => _jobs.TryGetValue(label, out var job) ? job : null;
}

public sealed class HostLaunchdOperations : ILaunchdOperations
{
    private readonly ICommandRunner _runner;
    private readonly AgentConfig _config;
    private readonly object _stateLock = new();

    public HostLaunchdOperations(
        ICommandRunner runner,
        IOptions<AgentConfig> config)
    {
        _runner = runner;
        _config = config.Value;
    }

    public bool HasJob(string label)
        => _runner.Run("/bin/launchctl", ["print", ServiceTarget(label)]).Succeeded;

    public void Configure(string label, string plistPath, bool? enabled)
    {
        if (string.IsNullOrWhiteSpace(plistPath))
            throw new InvalidOperationException("launchd Configure requires plist_path");

        var fullPath = Path.GetFullPath(plistPath);
        if (!File.Exists(fullPath))
            throw new InvalidOperationException($"launchd plist '{fullPath}' does not exist");
        if (!IsManagedPath(fullPath))
            throw new InvalidOperationException(
                $"launchd plist '{fullPath}' is outside managed roots");

        var actualLabel = _runner.RunChecked(
            "/usr/bin/plutil",
            ["-extract", "Label", "raw", "-o", "-", fullPath]).StandardOutput.Trim();
        if (!string.Equals(actualLabel, label, StringComparison.Ordinal))
            throw new InvalidOperationException(
                $"launchd plist label mismatch: expected '{label}', found '{actualLabel}'");

        UpdateBinding(label, fullPath);

        if (enabled.HasValue)
        {
            _runner.RunChecked(
                "/bin/launchctl",
                [enabled.Value ? "enable" : "disable", ServiceTarget(label)]);
        }
    }

    public void Load(string label)
    {
        PrivilegeGuard.DemandRoot("launchd bootstrap");
        var plistPath = ResolvePlistPath(label);
        _runner.RunChecked("/bin/launchctl", ["bootstrap", _config.LaunchdDomain, plistPath]);
    }

    public void Unload(string label)
    {
        PrivilegeGuard.DemandRoot("launchd bootout");
        var serviceTarget = ServiceTarget(label);
        var result = _runner.Run("/bin/launchctl", ["bootout", serviceTarget]);
        if (result.Succeeded)
            return;

        var plistPath = ResolvePlistPath(label, required: false);
        if (plistPath is not null)
        {
            result = _runner.Run("/bin/launchctl", ["bootout", _config.LaunchdDomain, plistPath]);
            if (result.Succeeded)
                return;
        }

        throw new CommandExecutionException(
            CommandRunnerExtensions.BuildFailureMessage(
                "/bin/launchctl",
                ["bootout", serviceTarget],
                result));
    }

    public void Kickstart(string label)
    {
        PrivilegeGuard.DemandRoot("launchd kickstart");
        _runner.RunChecked("/bin/launchctl", ["kickstart", "-k", ServiceTarget(label)]);
    }

    private string ResolvePlistPath(string label, bool required = true)
    {
        var bindings = LoadBindings();
        if (bindings.TryGetValue(label, out var bound) && File.Exists(bound))
            return bound;

        var candidates = new[]
        {
            Path.Combine(_config.ResolveLaunchDaemonPlistDir(), $"{label}.plist"),
            Path.Combine(_config.ResolveLaunchAgentPlistDir(), $"{label}.plist"),
        };

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
                return candidate;
        }

        if (required)
            throw new InvalidOperationException($"no managed launchd plist registered for '{label}'");
        return null!;
    }

    private bool IsManagedPath(string path)
    {
        var roots = new[]
        {
            _config.ResolveLaunchDaemonPlistDir(),
            _config.ResolveLaunchAgentPlistDir(),
            _config.ResolveStateDir(),
        };

        return roots.Any(root => IsUnderRoot(path, root));
    }

    private void UpdateBinding(string label, string plistPath)
    {
        lock (_stateLock)
        {
            var bindings = LoadBindings();
            bindings[label] = plistPath;
            SaveBindings(bindings);
        }
    }

    private Dictionary<string, string> LoadBindings()
    {
        var path = _config.ResolveLaunchdStateFile();
        if (!File.Exists(path))
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var text = File.ReadAllText(path);
        var raw = JsonSerializer.Deserialize<Dictionary<string, string>>(text)
            ?? new Dictionary<string, string>();
        return new Dictionary<string, string>(raw, StringComparer.OrdinalIgnoreCase);
    }

    private void SaveBindings(Dictionary<string, string> bindings)
    {
        var path = _config.ResolveLaunchdStateFile();
        var dir = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException($"invalid launchd state file path '{path}'");
        Directory.CreateDirectory(dir);
        File.WriteAllText(path, JsonSerializer.Serialize(bindings));
    }

    private string ServiceTarget(string label) => $"{_config.LaunchdDomain}/{label}";

    private static bool IsUnderRoot(string path, string root)
    {
        if (string.IsNullOrWhiteSpace(root))
            return false;

        var fullPath = Path.GetFullPath(path)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var fullRoot = Path.GetFullPath(root)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

        return fullPath.Equals(fullRoot, StringComparison.Ordinal)
            || fullPath.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    }
}

public sealed class LaunchdEnforcer : IEnforcer
{
    private readonly ILaunchdOperations _ops;
    private readonly ILogger<LaunchdEnforcer> _log;

    public string Name => "Launchd";

    public LaunchdEnforcer(
        ILaunchdOperations ops,
        ILogger<LaunchdEnforcer> log)
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
                _log.LogError(ex, "launchd enforcer failed on {Directive}", desc);
                changes.Add($"FAILED: {desc} — {ex.Message}");
                firstError ??= ex.Message;
                overallStatus = EnforcementStatus.Failed;
            }
        }

        return Task.FromResult(new EnforcementOutcome(overallStatus, firstError, changes));
    }

    private string ApplyOne(JsonElement item, EnforcementMode mode)
    {
        var label = item.GetProperty("label").GetString() ?? throw new InvalidOperationException("missing label");
        var action = item.GetProperty("action").GetString() ?? throw new InvalidOperationException("missing action");
        var plistPath = item.TryGetProperty("plist_path", out var path) && path.ValueKind != JsonValueKind.Null
            ? path.GetString() ?? string.Empty
            : string.Empty;
        var enabled = item.TryGetProperty("enabled", out var e) && e.ValueKind != JsonValueKind.Null
            ? e.GetBoolean()
            : (bool?)null;

        var desc = $"{action} {label}";
        if (mode == EnforcementMode.Audit)
        {
            _log.LogInformation("[AUDIT] launchd: would {Action}", desc);
            return $"[AUDIT] {desc}";
        }

        switch (action)
        {
            case "Configure":
                _ops.Configure(label, plistPath, enabled);
                _log.LogInformation("launchd: configured {Label}", label);
                return desc;
            case "Load":
                _ops.Load(label);
                _log.LogInformation("launchd: loaded {Label}", label);
                return desc;
            case "Unload":
                _ops.Unload(label);
                _log.LogInformation("launchd: unloaded {Label}", label);
                return desc;
            case "Kickstart":
                _ops.Kickstart(label);
                _log.LogInformation("launchd: kickstarted {Label}", label);
                return desc;
            default:
                throw new InvalidOperationException($"unknown launchd action: {action}");
        }
    }

    private static string DescribeDirective(JsonElement item)
    {
        var label = item.TryGetProperty("label", out var l) ? l.GetString() : "?";
        var action = item.TryGetProperty("action", out var a) ? a.GetString() : "?";
        return $"{action} {label}";
    }
}
