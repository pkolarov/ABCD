// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DDS.PolicyAgent.Linux.Client;
using DDS.PolicyAgent.Linux.Config;
using DDS.PolicyAgent.Linux.State;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.Linux;

public sealed class Worker : BackgroundService
{
    private readonly IDdsNodeClient _client;
    private readonly IAppliedStateStore _stateStore;
    private readonly AgentConfig _config;
    private readonly ILogger<Worker> _log;

    public Worker(
        IDdsNodeClient client,
        IAppliedStateStore stateStore,
        IOptions<AgentConfig> config,
        ILogger<Worker> log)
    {
        _client = client;
        _stateStore = stateStore;
        _config = config.Value;
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
            "DDS Linux Policy Agent started. device={DeviceUrn} poll={Interval}s node={NodeUrl}",
            _config.DeviceUrn, _config.PollIntervalSeconds, _config.NodeBaseUrl);

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
            var status = hasLinuxObject ? "ok" : "skipped";
            var report = new AppliedReport
            {
                DeviceUrn = _config.DeviceUrn,
                TargetId = policyId,
                Version = version,
                Status = status,
                Kind = AppliedKind.Policy,
                Directives = [],
                AppliedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            };
            await _client.ReportAppliedAsync(report, ct).ConfigureAwait(false);
            _stateStore.RecordApplied(policyId, version, hash, status);
        }
    }

    private static string ContentHash(JsonElement element)
    {
        var json = JsonSerializer.Serialize(element);
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(json));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
