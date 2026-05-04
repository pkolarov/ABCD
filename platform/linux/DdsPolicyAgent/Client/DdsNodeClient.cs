// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DDS.PolicyAgent.Linux.Client;

public sealed class ApplicableLinuxPolicy
{
    [JsonPropertyName("jti")]
    public string Jti { get; set; } = string.Empty;

    [JsonPropertyName("issuer")]
    public string Issuer { get; set; } = string.Empty;

    [JsonPropertyName("iat")]
    public ulong Iat { get; set; }

    [JsonPropertyName("document")]
    public JsonElement Document { get; set; }
}

public sealed class LinuxPoliciesResponse
{
    [JsonPropertyName("policies")]
    public List<ApplicableLinuxPolicy> Policies { get; set; } = [];
}

public sealed class AppliedReport
{
    [JsonPropertyName("device_urn")]
    public string DeviceUrn { get; set; } = string.Empty;

    [JsonPropertyName("target_id")]
    public string TargetId { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    [JsonPropertyName("status")]
    public string Status { get; set; } = "ok";

    [JsonPropertyName("kind")]
    public string? Kind { get; set; }

    [JsonPropertyName("directives")]
    public List<string> Directives { get; set; } = [];

    [JsonPropertyName("error")]
    public string? Error { get; set; }

    [JsonPropertyName("applied_at")]
    public ulong AppliedAt { get; set; }
}

public static class AppliedKind
{
    public const string Policy = "policy";
    public const string Reconciliation = "reconciliation";
}

public interface IDdsNodeClient
{
    Task<List<ApplicableLinuxPolicy>> GetPoliciesAsync(
        string deviceUrn, CancellationToken ct = default);

    Task ReportAppliedAsync(
        AppliedReport report, CancellationToken ct = default);
}

public sealed class DdsNodeClient : IDdsNodeClient
{
    private readonly HttpClient _http;
    private readonly EnvelopeVerifier _verifier;

    private static readonly JsonSerializerOptions PayloadJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public DdsNodeClient(HttpClient http, EnvelopeVerifier verifier)
    {
        _http = http;
        _verifier = verifier;
    }

    public async Task<List<ApplicableLinuxPolicy>> GetPoliciesAsync(
        string deviceUrn, CancellationToken ct = default)
    {
        var url = $"v1/linux/policies?device_urn={Uri.EscapeDataString(deviceUrn)}";
        var env = await _http.GetFromJsonAsync<SignedPolicyEnvelope>(url, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("dds-node returned empty envelope");
        var payload = _verifier.VerifyAndUnwrap(env, EnvelopeKind.LinuxPolicies);
        var resp = JsonSerializer.Deserialize<LinuxPoliciesResponse>(payload, PayloadJsonOptions);
        return resp?.Policies ?? [];
    }

    public async Task ReportAppliedAsync(
        AppliedReport report, CancellationToken ct = default)
    {
        using var resp = await _http
            .PostAsJsonAsync("v1/linux/applied", report, ct)
            .ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
    }
}
