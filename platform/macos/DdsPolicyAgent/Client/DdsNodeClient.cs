// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DDS.PolicyAgent.MacOS.Client;

public sealed class ApplicableMacOsPolicy
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

public sealed class ApplicableSoftware
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

public sealed class MacOsPoliciesResponse
{
    [JsonPropertyName("policies")]
    public List<ApplicableMacOsPolicy> Policies { get; set; } = [];
}

public sealed class MacOsSoftwareResponse
{
    [JsonPropertyName("software")]
    public List<ApplicableSoftware> Software { get; set; } = [];
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

    [JsonPropertyName("directives")]
    public List<string> Directives { get; set; } = [];

    [JsonPropertyName("error")]
    public string? Error { get; set; }

    [JsonPropertyName("applied_at")]
    public ulong AppliedAt { get; set; }
}

public interface IDdsNodeClient
{
    Task<List<ApplicableMacOsPolicy>> GetPoliciesAsync(
        string deviceUrn, CancellationToken ct = default);

    Task<List<ApplicableSoftware>> GetSoftwareAsync(
        string deviceUrn, CancellationToken ct = default);

    Task ReportAppliedAsync(
        AppliedReport report, CancellationToken ct = default);
}

public sealed class DdsNodeClient : IDdsNodeClient
{
    private readonly HttpClient _http;

    public DdsNodeClient(HttpClient http) => _http = http;

    public async Task<List<ApplicableMacOsPolicy>> GetPoliciesAsync(
        string deviceUrn, CancellationToken ct = default)
    {
        var url = $"v1/macos/policies?device_urn={Uri.EscapeDataString(deviceUrn)}";
        var resp = await _http.GetFromJsonAsync<MacOsPoliciesResponse>(url, ct)
            .ConfigureAwait(false);
        return resp?.Policies ?? [];
    }

    public async Task<List<ApplicableSoftware>> GetSoftwareAsync(
        string deviceUrn, CancellationToken ct = default)
    {
        var url = $"v1/macos/software?device_urn={Uri.EscapeDataString(deviceUrn)}";
        var resp = await _http.GetFromJsonAsync<MacOsSoftwareResponse>(url, ct)
            .ConfigureAwait(false);
        return resp?.Software ?? [];
    }

    public async Task ReportAppliedAsync(
        AppliedReport report, CancellationToken ct = default)
    {
        using var resp = await _http
            .PostAsJsonAsync("v1/macos/applied", report, ct)
            .ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
    }
}
