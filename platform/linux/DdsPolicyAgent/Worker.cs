// SPDX-License-Identifier: MIT OR Apache-2.0
// This worker runs only on Linux; suppress CA1416 for Linux-only enforcer calls.
#pragma warning disable CA1416

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.Linux.Client;
using DDS.PolicyAgent.Linux.Config;
using DDS.PolicyAgent.Linux.Enforcers;
using DDS.PolicyAgent.Linux.Runtime;
using DDS.PolicyAgent.Linux.State;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.Linux;

public sealed class Worker : BackgroundService
{
    private readonly IDdsNodeClient _client;
    private readonly IAppliedStateStore _stateStore;
    private readonly AgentConfig _config;
    private readonly ICommandRunner _runner;
    private readonly ILogger<Worker> _log;

    public Worker(
        IDdsNodeClient client,
        IAppliedStateStore stateStore,
        IOptions<AgentConfig> config,
        ICommandRunner runner,
        ILogger<Worker> log)
    {
        _client = client;
        _stateStore = stateStore;
        _config = config.Value;
        _runner = runner;
        _log = log;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrWhiteSpace(_config.DeviceUrn))
        {
            _log.LogError("DeviceUrn is not configured; cannot start Linux policy agent");
            return;
        }

        if (string.IsNullOrWhiteSpace(_config.PinnedNodePubkeyB64))
        {
            _log.LogError("PinnedNodePubkeyB64 is not configured; cannot start Linux policy agent");
            return;
        }

        _log.LogInformation(
            "DDS Linux Policy Agent started. device={DeviceUrn} poll={Interval}s node={NodeUrl} audit={Audit}",
            _config.DeviceUrn, _config.PollIntervalSeconds, _config.NodeBaseUrl, _config.AuditOnly);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PollOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Poll cycle failed; will retry next interval");
            }

            await Task.Delay(
                TimeSpan.FromSeconds(_config.PollIntervalSeconds),
                stoppingToken).ConfigureAwait(false);
        }
    }

    internal async Task PollOnceAsync(CancellationToken ct)
    {
        var policies = await _client
            .GetPoliciesAsync(_config.DeviceUrn, ct)
            .ConfigureAwait(false);
        _log.LogDebug("Received {Count} applicable Linux policies", policies.Count);

        // Build managed sets from current applied state for safe-delete guards.
        var state = _stateStore.Load();
        var managedUsernames = new HashSet<string>(
            state.ManagedUsernames, StringComparer.Ordinal);
        var managedPaths = new HashSet<string>(
            state.ManagedPaths, StringComparer.Ordinal);
        var managedPackages = new HashSet<string>(
            state.ManagedPackages, StringComparer.Ordinal);

        var userEnforcer    = new UserEnforcer   (_runner, _config.AuditOnly, _log);
        var sudoersEnforcer = new SudoersEnforcer(_runner, _config.AuditOnly, _log);
        var fileEnforcer    = new FileEnforcer   (_runner, _config.AuditOnly, _log);
        var systemdEnforcer = new SystemdEnforcer(_runner, _config.AuditOnly, _log);
        var pkgEnforcer     = new PackageEnforcer(_runner, _config.AuditOnly, _log);

        foreach (var p in policies)
        {
            var hash = ContentHash(p.Document);
            var policyId = p.Document.TryGetProperty("policy_id", out var id)
                ? id.GetString() ?? p.Jti
                : p.Jti;
            var version = p.Document.TryGetProperty("version", out var v)
                ? v.ToString()
                : "0";

            if (!_stateStore.HasChanged(policyId, hash))
            {
                _log.LogDebug("Policy {Id} v{Version} unchanged; skip", policyId, version);
                continue;
            }

            var hasLinuxObject = p.Document.TryGetProperty("linux", out var linux)
                && linux.ValueKind == JsonValueKind.Object;

            if (!hasLinuxObject)
            {
                var skipReport = new AppliedReport
                {
                    DeviceUrn  = _config.DeviceUrn,
                    TargetId   = policyId,
                    Version    = version,
                    Status     = "skipped",
                    Kind       = AppliedKind.Policy,
                    Directives = [],
                    AppliedAt  = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                };
                await _client.ReportAppliedAsync(skipReport, ct).ConfigureAwait(false);
                _stateStore.RecordApplied(policyId, version, hash, "skipped");
                continue;
            }

            var allDirectives = new List<string>();
            string? errorMsg  = null;

            try
            {
                allDirectives.AddRange(await ApplyLinuxSectionAsync(
                    linux, policyId, version,
                    userEnforcer, sudoersEnforcer, fileEnforcer, systemdEnforcer, pkgEnforcer,
                    managedUsernames, managedPaths, managedPackages,
                    ct).ConfigureAwait(false));
            }
            catch (Exception ex)
            {
                errorMsg = ex.Message;
                _log.LogError(ex, "Policy {Id} enforcer threw; recording error", policyId);
            }

            if (errorMsg is null)
                RecordManagedResources(allDirectives);

            var status = errorMsg is null ? "ok" : "error";
            var report = new AppliedReport
            {
                DeviceUrn  = _config.DeviceUrn,
                TargetId   = policyId,
                Version    = version,
                Status     = status,
                Kind       = AppliedKind.Policy,
                Directives = allDirectives,
                Error      = errorMsg,
                AppliedAt  = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            };
            await _client.ReportAppliedAsync(report, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(policyId, version, hash, status);
        }
    }

    private static async Task<List<string>> ApplyLinuxSectionAsync(
        JsonElement linux,
        string policyId,
        string version,
        UserEnforcer userEnforcer,
        SudoersEnforcer sudoersEnforcer,
        FileEnforcer fileEnforcer,
        SystemdEnforcer systemdEnforcer,
        PackageEnforcer pkgEnforcer,
        IReadOnlySet<string> managedUsernames,
        IReadOnlySet<string> managedPaths,
        IReadOnlySet<string> managedPackages,
        CancellationToken ct)
    {
        var all = new List<string>();

        all.AddRange(await userEnforcer.ApplyAsync(
            GetArray(linux, "local_users"), managedUsernames, ct).ConfigureAwait(false));

        all.AddRange(await sudoersEnforcer.ApplyAsync(
            GetArray(linux, "sudoers"), ct).ConfigureAwait(false));

        all.AddRange(await fileEnforcer.ApplyAsync(
            GetArray(linux, "files"), managedPaths, ct).ConfigureAwait(false));

        all.AddRange(await systemdEnforcer.ApplyAsync(
            GetArray(linux, "systemd"), ct).ConfigureAwait(false));

        all.AddRange(await pkgEnforcer.ApplyAsync(
            GetArray(linux, "packages"), managedPackages, ct).ConfigureAwait(false));

        return all;
    }

    private static IReadOnlyList<JsonElement> GetArray(JsonElement parent, string property)
    {
        if (parent.TryGetProperty(property, out var el) && el.ValueKind == JsonValueKind.Array)
            return el.EnumerateArray().ToList();
        return [];
    }

    // Parse directive tags emitted by enforcers (e.g. "user:create:alice") and
    // register the affected resource in the applied state store so that future
    // Delete / Remove operations pass the DDS-managed safety check.
    private void RecordManagedResources(IEnumerable<string> directives)
    {
        foreach (var tag in directives)
        {
            var parts = tag.Split(':', 3);
            if (parts.Length != 3) continue;
            var (category, action, id) = (parts[0], parts[1], parts[2]);

            switch (category)
            {
                case "user" when action == "create":
                    _stateStore.RecordManagedUsername(id);
                    break;
                case "user" when action == "delete":
                    _stateStore.RemoveManagedUsername(id);
                    break;
                case "file" when action == "set" || action == "ensuredir":
                    _stateStore.RecordManagedPath(id);
                    break;
                case "file" when action == "delete":
                    _stateStore.RemoveManagedPath(id);
                    break;
                case "pkg" when action == "install":
                    _stateStore.RecordManagedPackage(id);
                    break;
                case "pkg" when action == "remove":
                    _stateStore.RemoveManagedPackage(id);
                    break;
            }
        }
    }

    private static string ContentHash(JsonElement element)
    {
        var json = JsonSerializer.Serialize(element);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

}
