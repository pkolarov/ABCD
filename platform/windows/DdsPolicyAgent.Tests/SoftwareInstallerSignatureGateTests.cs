// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;
using DDS.PolicyAgent.Config;
using DDS.PolicyAgent.Enforcers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace DDS.PolicyAgent.Tests;

/// <summary>
/// SC-5 Phase B.2 — Windows Authenticode signature gate. Mirrors the
/// macOS Phase B.3 test surface in
/// <c>platform/macos/DdsPolicyAgent.Tests/EnforcerTests.cs</c>:
/// <list type="number">
///   <item>parser: directive → spec (PublisherIdentitySpec.TryParse)</item>
///   <item>parser: SHA-1 thumbprint shape</item>
///   <item>integration: matching subject proceeds past the signature gate</item>
///   <item>integration: missing / mismatched / wrong-platform pin fails closed</item>
///   <item>integration: RequirePackageSignature=false but publisher_identity set still gates</item>
/// </list>
/// </summary>
public sealed class SoftwareInstallerSignatureGateTests
{
    // -- PublisherIdentitySpec parser ---------------------------------

    [Fact]
    public void PublisherIdentitySpec_TryParse_returns_null_when_field_absent()
    {
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.app","action":"Install"}
        """).RootElement;
        Assert.Null(PublisherIdentitySpec.TryParse(directive));
    }

    [Fact]
    public void PublisherIdentitySpec_TryParse_returns_null_when_field_explicit_null()
    {
        var directive = JsonDocument.Parse("""
        {"package_id":"com.example.app","action":"Install","publisher_identity":null}
        """).RootElement;
        Assert.Null(PublisherIdentitySpec.TryParse(directive));
    }

    [Fact]
    public void PublisherIdentitySpec_TryParse_extracts_Authenticode_subject_only()
    {
        var directive = JsonDocument.Parse("""
        {"publisher_identity":{"Authenticode":{"subject":"Acme Corp"}}}
        """).RootElement;
        var parsed = PublisherIdentitySpec.TryParse(directive);
        var auth = Assert.IsType<PublisherIdentitySpec.Authenticode>(parsed);
        Assert.Equal("Acme Corp", auth.Subject);
        Assert.Null(auth.RootThumbprintSha1Hex);
    }

    [Fact]
    public void PublisherIdentitySpec_TryParse_extracts_Authenticode_with_thumbprint()
    {
        const string thumb = "0123456789abcdef0123456789abcdef01234567";
        var directive = JsonDocument.Parse(
            "{\"publisher_identity\":{\"Authenticode\":{\"subject\":\"Acme Corp\",\"root_thumbprint\":\"" + thumb + "\"}}}")
            .RootElement;
        var parsed = PublisherIdentitySpec.TryParse(directive);
        var auth = Assert.IsType<PublisherIdentitySpec.Authenticode>(parsed);
        Assert.Equal("Acme Corp", auth.Subject);
        Assert.Equal(thumb, auth.RootThumbprintSha1Hex);
    }

    [Fact]
    public void PublisherIdentitySpec_TryParse_treats_explicit_null_thumbprint_as_absent()
    {
        var directive = JsonDocument.Parse("""
        {"publisher_identity":{"Authenticode":{"subject":"Acme Corp","root_thumbprint":null}}}
        """).RootElement;
        var parsed = PublisherIdentitySpec.TryParse(directive);
        var auth = Assert.IsType<PublisherIdentitySpec.Authenticode>(parsed);
        Assert.Null(auth.RootThumbprintSha1Hex);
    }

    [Fact]
    public void PublisherIdentitySpec_TryParse_rejects_empty_authenticode_subject()
    {
        var directive = JsonDocument.Parse("""
        {"publisher_identity":{"Authenticode":{"subject":""}}}
        """).RootElement;
        Assert.Throws<InvalidOperationException>(() => PublisherIdentitySpec.TryParse(directive));
    }

    [Theory]
    [InlineData("0123456789abcdef0123456789abcdef0123456")]   // 39 chars
    [InlineData("0123456789abcdef0123456789abcdef012345678")] // 41 chars
    [InlineData("0123456789ABCDEF0123456789abcdef01234567")]  // mixed case (upper)
    [InlineData("0123456789abcdef0123456789abcdef0123456g")]  // out-of-range char
    public void PublisherIdentitySpec_TryParse_rejects_malformed_thumbprint(string thumb)
    {
        var json = "{\"publisher_identity\":{\"Authenticode\":{\"subject\":\"Acme\",\"root_thumbprint\":\"" + thumb + "\"}}}";
        var directive = JsonDocument.Parse(json).RootElement;
        Assert.Throws<InvalidOperationException>(() => PublisherIdentitySpec.TryParse(directive));
    }

    [Fact]
    public void PublisherIdentitySpec_TryParse_extracts_AppleDeveloperId_team_id()
    {
        // Cross-platform variant should round-trip through the parser
        // (so the Windows agent can recognise + reject it as a wrong-
        // platform pin), even though it has no enforcement path on
        // Windows.
        var directive = JsonDocument.Parse("""
        {"publisher_identity":{"AppleDeveloperId":{"team_id":"ABCDE12345"}}}
        """).RootElement;
        var parsed = PublisherIdentitySpec.TryParse(directive);
        var apple = Assert.IsType<PublisherIdentitySpec.AppleDeveloperId>(parsed);
        Assert.Equal("ABCDE12345", apple.TeamId);
    }

    [Theory]
    [InlineData("ABCDE1234")]   // 9 chars
    [InlineData("ABCDE123456")] // 11 chars
    [InlineData("abcde12345")]  // lowercase
    [InlineData("ABCDE-1234")]  // non-alphanumeric
    public void PublisherIdentitySpec_TryParse_rejects_malformed_team_id(string teamId)
    {
        var json = "{\"publisher_identity\":{\"AppleDeveloperId\":{\"team_id\":\"" + teamId + "\"}}}";
        var directive = JsonDocument.Parse(json).RootElement;
        Assert.Throws<InvalidOperationException>(() => PublisherIdentitySpec.TryParse(directive));
    }

    [Fact]
    public void PublisherIdentitySpec_TryParse_rejects_unknown_variant()
    {
        var directive = JsonDocument.Parse("""
        {"publisher_identity":{"Bogus":{"subject":"Acme"}}}
        """).RootElement;
        Assert.Throws<InvalidOperationException>(() => PublisherIdentitySpec.TryParse(directive));
    }

    [Fact]
    public void PublisherIdentitySpec_TryParse_rejects_empty_object()
    {
        var directive = JsonDocument.Parse("""
        {"publisher_identity":{}}
        """).RootElement;
        Assert.Throws<InvalidOperationException>(() => PublisherIdentitySpec.TryParse(directive));
    }

    [Fact]
    public void PublisherIdentitySpec_TryParse_rejects_two_variants()
    {
        var directive = JsonDocument.Parse("""
        {"publisher_identity":{"Authenticode":{"subject":"X"},"AppleDeveloperId":{"team_id":"ABCDE12345"}}}
        """).RootElement;
        Assert.Throws<InvalidOperationException>(() => PublisherIdentitySpec.TryParse(directive));
    }

    // -- Stub authenticode verifier behaviour -------------------------

    [Fact]
    public void StubAuthenticodeVerifier_always_fails_with_clear_reason()
    {
        var verifier = new StubAuthenticodeVerifier();
        var result = verifier.Verify("/any/path");
        Assert.False(result.IsValid);
        Assert.Null(result.SignerSubject);
        Assert.Null(result.RootThumbprintSha1Hex);
        Assert.NotNull(result.Reason);
        Assert.Contains("Windows", result.Reason);
    }

    // -- SoftwareInstaller signature gate integration -----------------

    private static SoftwareInstaller MakeInstaller(
        IAuthenticodeVerifier verifier,
        bool requirePackageSignature,
        ISoftwareOperations? ops = null)
    {
        return new SoftwareInstaller(
            ops ?? new InMemorySoftwareOperations(),
            verifier,
            Options.Create(new AgentConfig { RequirePackageSignature = requirePackageSignature }),
            NullLogger<SoftwareInstaller>.Instance);
    }

    private static JsonElement Directive(string? publisherIdentityJson)
    {
        var pi = publisherIdentityJson is null
            ? string.Empty
            : ",\"publisher_identity\":" + publisherIdentityJson;
        var json = "{"
            + "\"package_id\":\"com.example.app\","
            + "\"version\":\"1.0\","
            + "\"action\":\"Install\","
            + "\"installer_type\":\"msi\","
            + "\"source_url\":\"https://example.com/app.msi\","
            + "\"sha256\":\"abc123\""
            + pi
            + "}";
        return JsonDocument.Parse(json).RootElement;
    }

    [Fact]
    public async Task SoftwareInstaller_phase_b2_accepts_matching_subject()
    {
        var verifier = new ScriptedAuthenticodeVerifier(
            new AuthenticodeVerifyResult(
                IsValid: true,
                SignerSubject: "Acme Corp",
                RootThumbprintSha1Hex: null,
                Reason: null));
        var installer = MakeInstaller(verifier, requirePackageSignature: true);
        var directive = Directive("""{"Authenticode":{"subject":"Acme Corp"}}""");

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
        Assert.NotNull(outcome.Changes);
        Assert.Single(outcome.Changes);
    }

    [Fact]
    public async Task SoftwareInstaller_phase_b2_rejects_mismatched_subject()
    {
        var verifier = new ScriptedAuthenticodeVerifier(
            new AuthenticodeVerifyResult(
                IsValid: true,
                SignerSubject: "Other Corp",
                RootThumbprintSha1Hex: null,
                Reason: null));
        var installer = MakeInstaller(verifier, requirePackageSignature: true);
        var directive = Directive("""{"Authenticode":{"subject":"Acme Corp"}}""");

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);
        Assert.Contains("subject mismatch", outcome.Error);
        Assert.Contains("Acme Corp", outcome.Error);
        Assert.Contains("Other Corp", outcome.Error);
    }

    [Fact]
    public async Task SoftwareInstaller_phase_b2_rejects_unsigned_when_required()
    {
        var verifier = new ScriptedAuthenticodeVerifier(
            new AuthenticodeVerifyResult(
                IsValid: false,
                SignerSubject: null,
                RootThumbprintSha1Hex: null,
                Reason: "WinVerifyTrust returned 0x800B0100"));
        var installer = MakeInstaller(verifier, requirePackageSignature: true);
        var directive = Directive(publisherIdentityJson: null);

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);
        Assert.Contains("Authenticode verify failed", outcome.Error);
        Assert.Contains("0x800B0100", outcome.Error);
    }

    [Fact]
    public async Task SoftwareInstaller_phase_b2_rejects_unsigned_when_publisher_identity_set_even_if_require_off()
    {
        // Backward-compat angle: an operator who explicitly turned
        // RequirePackageSignature off must still get the signature gate
        // when a directive carries publisher_identity. Otherwise a
        // legacy "I trust hash only" config silently downgrades the
        // two-signature gate to one signature.
        var verifier = new ScriptedAuthenticodeVerifier(
            new AuthenticodeVerifyResult(
                IsValid: false,
                SignerSubject: null,
                RootThumbprintSha1Hex: null,
                Reason: "WinVerifyTrust returned 0x800B0100"));
        var installer = MakeInstaller(verifier, requirePackageSignature: false);
        var directive = Directive("""{"Authenticode":{"subject":"Acme Corp"}}""");

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);
        Assert.Contains("Authenticode verify failed", outcome.Error);
    }

    [Fact]
    public async Task SoftwareInstaller_phase_b2_accepts_unsigned_when_neither_require_nor_pin()
    {
        // Legacy hash-only path stays intact when both signals are off.
        // The verifier MUST NOT be called.
        var verifier = new ThrowingAuthenticodeVerifier();
        var installer = MakeInstaller(verifier, requirePackageSignature: false);
        var directive = Directive(publisherIdentityJson: null);

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
    }

    /// <summary>
    /// SC-5 Phase B.4 cross-platform test
    /// <c>software_install_accepts_signed_blob_with_no_publisher_identity_directive</c>:
    /// when <c>RequirePackageSignature</c> is on but the directive does
    /// not pin a <c>publisher_identity</c>, a validly-signed blob must
    /// proceed past the signature gate. This is the legacy hash + sig
    /// path that pre-Phase-B publishers will live on during the migration
    /// window; without this test a future regression that always
    /// requires <c>publisher_identity</c> alongside
    /// <c>RequirePackageSignature</c> would silently break legacy publishers.
    /// </summary>
    [Fact]
    public async Task SoftwareInstaller_phase_b2_accepts_signed_blob_with_no_publisher_identity_directive()
    {
        var verifier = new ScriptedAuthenticodeVerifier(
            new AuthenticodeVerifyResult(
                IsValid: true,
                SignerSubject: "Acme Corp",
                RootThumbprintSha1Hex: null,
                Reason: null));
        var installer = MakeInstaller(verifier, requirePackageSignature: true);
        var directive = Directive(publisherIdentityJson: null);

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
    }

    [Fact]
    public async Task SoftwareInstaller_phase_b2_rejects_apple_developer_id_on_windows()
    {
        // Wrong-platform pin: AppleDeveloperId on a Windows agent must
        // fail closed even when RequirePackageSignature is on. The
        // verifier MUST NOT be called — the wrong-platform check fires
        // first.
        var verifier = new ThrowingAuthenticodeVerifier();
        var installer = MakeInstaller(verifier, requirePackageSignature: true);
        var directive = Directive("""{"AppleDeveloperId":{"team_id":"ABCDE12345"}}""");

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);
        Assert.Contains("AppleDeveloperId publisher_identity", outcome.Error);
    }

    [Fact]
    public async Task SoftwareInstaller_phase_b2_rejects_missing_root_thumbprint_when_pinned()
    {
        var verifier = new ScriptedAuthenticodeVerifier(
            new AuthenticodeVerifyResult(
                IsValid: true,
                SignerSubject: "Acme Corp",
                RootThumbprintSha1Hex: null, // chain has no root recoverable
                Reason: null));
        var installer = MakeInstaller(verifier, requirePackageSignature: true);
        const string thumb = "0123456789abcdef0123456789abcdef01234567";
        var directive = Directive(
            "{\"Authenticode\":{\"subject\":\"Acme Corp\",\"root_thumbprint\":\"" + thumb + "\"}}");

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);
        Assert.Contains("root thumbprint", outcome.Error);
    }

    [Fact]
    public async Task SoftwareInstaller_phase_b2_rejects_mismatched_root_thumbprint()
    {
        var verifier = new ScriptedAuthenticodeVerifier(
            new AuthenticodeVerifyResult(
                IsValid: true,
                SignerSubject: "Acme Corp",
                RootThumbprintSha1Hex: "ffffffffffffffffffffffffffffffffffffffff",
                Reason: null));
        var installer = MakeInstaller(verifier, requirePackageSignature: true);
        const string expected = "0123456789abcdef0123456789abcdef01234567";
        var directive = Directive(
            "{\"Authenticode\":{\"subject\":\"Acme Corp\",\"root_thumbprint\":\"" + expected + "\"}}");

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);
        Assert.Contains("thumbprint mismatch", outcome.Error);
        Assert.Contains(expected, outcome.Error);
    }

    [Fact]
    public async Task SoftwareInstaller_phase_b2_accepts_matching_root_thumbprint()
    {
        const string thumb = "0123456789abcdef0123456789abcdef01234567";
        var verifier = new ScriptedAuthenticodeVerifier(
            new AuthenticodeVerifyResult(
                IsValid: true,
                SignerSubject: "Acme Corp",
                RootThumbprintSha1Hex: thumb,
                Reason: null));
        var installer = MakeInstaller(verifier, requirePackageSignature: true);
        var directive = Directive(
            "{\"Authenticode\":{\"subject\":\"Acme Corp\",\"root_thumbprint\":\"" + thumb + "\"}}");

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Ok, outcome.Status);
    }

    [Fact]
    public async Task SoftwareInstaller_phase_b2_rejects_malformed_publisher_identity()
    {
        var verifier = new ThrowingAuthenticodeVerifier();
        var installer = MakeInstaller(verifier, requirePackageSignature: true);
        // Subject is empty — must fail at parse, before the download.
        var directive = Directive("""{"Authenticode":{"subject":""}}""");

        var outcome = await installer.ApplyAsync(directive, EnforcementMode.Enforce);

        Assert.Equal(EnforcementStatus.Failed, outcome.Status);
        Assert.NotNull(outcome.Error);
        Assert.Contains("publisher_identity", outcome.Error);
    }

    /// <summary>
    /// Test double — returns a preset <see cref="AuthenticodeVerifyResult"/>.
    /// </summary>
    private sealed class ScriptedAuthenticodeVerifier : IAuthenticodeVerifier
    {
        private readonly AuthenticodeVerifyResult _result;
        public ScriptedAuthenticodeVerifier(AuthenticodeVerifyResult result) => _result = result;
        public AuthenticodeVerifyResult Verify(string filePath) => _result;
    }

    /// <summary>
    /// Test double — fails the test if Verify is called. Used to assert
    /// the gate path is *not* taken (e.g. legacy hash-only flow, or the
    /// wrong-platform pin which must short-circuit before the call).
    /// </summary>
    private sealed class ThrowingAuthenticodeVerifier : IAuthenticodeVerifier
    {
        public AuthenticodeVerifyResult Verify(string filePath)
        {
            throw new Xunit.Sdk.XunitException(
                "Authenticode verifier was called when it should have been short-circuited");
        }
    }
}
