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

    /// <summary>
    /// Splits the audit-event vocabulary on the node side into
    /// <c>policy.applied</c> / <c>policy.failed</c> /
    /// <c>software.applied</c> / <c>software.failed</c>. Null falls
    /// back to the generic <c>apply.*</c> family — used by the
    /// reconciliation pass and the host-state heartbeat where there
    /// is no single document to attribute to. Lower-case wire form
    /// matches the Rust enum's <c>#[serde(rename_all = "lowercase")]</c>.
    /// </summary>
    [JsonPropertyName("kind")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Kind { get; set; }

    [JsonPropertyName("directives")]
    public List<string> Directives { get; set; } = [];

    [JsonPropertyName("error")]
    public string? Error { get; set; }

    [JsonPropertyName("applied_at")]
    public ulong AppliedAt { get; set; }
}

/// <summary>
/// Canonical lower-case wire values for <see cref="AppliedReport.Kind"/>.
/// Centralised here so every <c>ReportAsync</c> call site uses the
/// same string and a typo cannot silently disable the audit-action
/// split on the node.
/// </summary>
public static class AppliedKind
{
    public const string Policy = "policy";
    public const string Software = "software";
    public const string Reconciliation = "reconciliation";
    public const string HostState = "hoststate";
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

    public async Task<List<ApplicableMacOsPolicy>> GetPoliciesAsync(
        string deviceUrn, CancellationToken ct = default)
    {
        var url = $"v1/macos/policies?device_urn={Uri.EscapeDataString(deviceUrn)}";
        var env = await _http.GetFromJsonAsync<SignedPolicyEnvelope>(url, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("dds-node returned empty envelope");
        var payload = _verifier.VerifyAndUnwrap(env, EnvelopeKind.MacOsPolicies);
        var resp = JsonSerializer.Deserialize<MacOsPoliciesResponse>(payload, PayloadJsonOptions);
        return resp?.Policies ?? [];
    }

    public async Task<List<ApplicableSoftware>> GetSoftwareAsync(
        string deviceUrn, CancellationToken ct = default)
    {
        var url = $"v1/macos/software?device_urn={Uri.EscapeDataString(deviceUrn)}";
        var env = await _http.GetFromJsonAsync<SignedPolicyEnvelope>(url, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("dds-node returned empty envelope");
        var payload = _verifier.VerifyAndUnwrap(env, EnvelopeKind.MacOsSoftware);
        var resp = JsonSerializer.Deserialize<MacOsSoftwareResponse>(payload, PayloadJsonOptions);
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
