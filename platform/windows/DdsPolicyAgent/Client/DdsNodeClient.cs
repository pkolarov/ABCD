// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DDS.PolicyAgent.Client;

// ---------- Wire types matching dds-node /v1/windows/* ----------

public sealed class ApplicableWindowsPolicy
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

public sealed class WindowsPoliciesResponse
{
    [JsonPropertyName("policies")]
    public List<ApplicableWindowsPolicy> Policies { get; set; } = [];
}

public sealed class WindowsSoftwareResponse
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

    /// <summary>
    /// AD-07: structured reason code explaining why the report has the
    /// status it does. See <see cref="State.AppliedReason"/> for the
    /// canonical taxonomy. Null when the legacy unconditional-enforce
    /// path runs on a workgroup host with no transition to report.
    /// </summary>
    [JsonPropertyName("reason")]
    public string? Reason { get; set; }
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

// ---------- Client ----------

/// <summary>
/// HTTP client for the dds-node Windows applier endpoints.
/// Uses <see cref="IHttpClientFactory"/> for testability and
/// connection pooling.
///
/// <para>
/// <b>H-2 (security review)</b>: the policy/software endpoints now
/// return a <see cref="SignedPolicyEnvelope"/>. The client unwraps
/// and verifies the envelope against a pinned node pubkey before
/// handing the payload back. If no pubkey is pinned
/// (<c>pinnedNodePubkey == null</c>) the client refuses to fetch
/// — failing closed is the correct default for a SYSTEM agent.
/// </para>
/// </summary>
public interface IDdsNodeClient
{
    Task<List<ApplicableWindowsPolicy>> GetPoliciesAsync(
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

    private static readonly System.Text.Json.JsonSerializerOptions PayloadJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    public DdsNodeClient(HttpClient http, EnvelopeVerifier verifier)
    {
        _http = http;
        _verifier = verifier;
    }

    public async Task<List<ApplicableWindowsPolicy>> GetPoliciesAsync(
        string deviceUrn, CancellationToken ct = default)
    {
        var url = $"v1/windows/policies?device_urn={Uri.EscapeDataString(deviceUrn)}";
        var env = await _http.GetFromJsonAsync<SignedPolicyEnvelope>(url, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("dds-node returned empty envelope");
        var payload = _verifier.VerifyAndUnwrap(env, EnvelopeKind.WindowsPolicies);
        var resp = System.Text.Json.JsonSerializer
            .Deserialize<WindowsPoliciesResponse>(payload, PayloadJsonOptions);
        return resp?.Policies ?? [];
    }

    public async Task<List<ApplicableSoftware>> GetSoftwareAsync(
        string deviceUrn, CancellationToken ct = default)
    {
        var url = $"v1/windows/software?device_urn={Uri.EscapeDataString(deviceUrn)}";
        var env = await _http.GetFromJsonAsync<SignedPolicyEnvelope>(url, ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("dds-node returned empty envelope");
        var payload = _verifier.VerifyAndUnwrap(env, EnvelopeKind.WindowsSoftware);
        var resp = System.Text.Json.JsonSerializer
            .Deserialize<WindowsSoftwareResponse>(payload, PayloadJsonOptions);
        return resp?.Software ?? [];
    }

    public async Task ReportAppliedAsync(
        AppliedReport report, CancellationToken ct = default)
    {
        using var resp = await _http
            .PostAsJsonAsync("v1/windows/applied", report, ct)
            .ConfigureAwait(false);
        resp.EnsureSuccessStatusCode();
    }
}
