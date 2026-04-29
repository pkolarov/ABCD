// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Parsed view of the optional <c>publisher_identity</c> field on a
/// <c>SoftwareAssignment</c> directive. Mirrors the externally-tagged
/// Rust enum at <c>dds-domain/src/types.rs::PublisherIdentity</c>:
/// <code>
/// "publisher_identity": {"Authenticode": {"subject": "Acme Corp",
///                                          "root_thumbprint": "..."}}
/// "publisher_identity": {"AppleDeveloperId": {"team_id": "ABCDE12345"}}
/// </code>
/// SC-5 Phase B.2 only consumes the <c>Authenticode</c> variant; an
/// <c>AppleDeveloperId</c> variant on a Windows scope is treated as a
/// configuration error and rejected by the agent (the policy author
/// scoped a macOS-only signer expectation onto a Windows device).
/// Mirrors <c>DDS.PolicyAgent.MacOS.Enforcers.PublisherIdentitySpec</c>.
/// </summary>
internal abstract record PublisherIdentitySpec
{
    /// <summary>
    /// Windows Authenticode pinning. The agent must call
    /// <c>WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)</c> on the
    /// staged installer and compare
    /// <c>CertGetNameString(CERT_NAME_SIMPLE_DISPLAY_TYPE)</c> against
    /// <see cref="Subject"/>. The optional
    /// <see cref="RootThumbprintSha1Hex"/> further pins the chain root
    /// (40 lowercase hex chars, SHA-1 fingerprint).
    /// </summary>
    public sealed record Authenticode(string Subject, string? RootThumbprintSha1Hex)
        : PublisherIdentitySpec;

    /// <summary>
    /// macOS Developer ID pinning. Not enforceable on Windows — if the
    /// directive has this variant, the agent fails the install closed
    /// (the policy author scoped a macOS-only signer expectation onto
    /// a Windows device).
    /// </summary>
    public sealed record AppleDeveloperId(string TeamId) : PublisherIdentitySpec;

    /// <summary>
    /// Parse the optional <c>publisher_identity</c> field from a
    /// <c>SoftwareAssignment</c> directive. Returns <c>null</c> when
    /// the field is absent (legacy hash-only behaviour); throws when
    /// the field is present but malformed (an unknown variant tag,
    /// missing inner fields, an empty subject, a wrong-shape Apple
    /// Team ID, or a wrong-shape root thumbprint — anything the agent
    /// cannot enforce should fail closed at parse time).
    /// </summary>
    public static PublisherIdentitySpec? TryParse(JsonElement directive)
    {
        if (!directive.TryGetProperty("publisher_identity", out var pi)
            || pi.ValueKind == JsonValueKind.Null)
        {
            return null;
        }

        if (pi.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(
                "publisher_identity must be a JSON object with a single variant tag");
        }

        // Externally-tagged enum: exactly one property, the variant tag.
        JsonProperty tag = default;
        var seen = 0;
        foreach (var prop in pi.EnumerateObject())
        {
            if (seen++ > 0)
                throw new InvalidOperationException(
                    "publisher_identity must have exactly one variant tag");
            tag = prop;
        }
        if (seen == 0)
        {
            throw new InvalidOperationException(
                "publisher_identity is empty — expected a variant tag");
        }

        return tag.Name switch
        {
            "Authenticode" => ParseAuthenticode(tag.Value),
            "AppleDeveloperId" => ParseAppleDeveloperId(tag.Value),
            _ => throw new InvalidOperationException(
                $"unknown publisher_identity variant '{tag.Name}'"),
        };
    }

    private static Authenticode ParseAuthenticode(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object
            || !value.TryGetProperty("subject", out var subjectNode)
            || subjectNode.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(
                "Authenticode.subject must be a string");
        }
        var subject = subjectNode.GetString()!;
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new InvalidOperationException(
                "Authenticode.subject must not be empty");
        }

        string? rootThumbprint = null;
        if (value.TryGetProperty("root_thumbprint", out var thumbNode)
            && thumbNode.ValueKind != JsonValueKind.Null)
        {
            if (thumbNode.ValueKind != JsonValueKind.String)
            {
                throw new InvalidOperationException(
                    "Authenticode.root_thumbprint must be a string");
            }
            rootThumbprint = thumbNode.GetString();
            if (!IsValidSha1Thumbprint(rootThumbprint))
            {
                throw new InvalidOperationException(
                    $"Authenticode.root_thumbprint '{rootThumbprint}' must be exactly " +
                    "40 lowercase hex characters (SHA-1)");
            }
        }

        return new Authenticode(subject, rootThumbprint);
    }

    private static AppleDeveloperId ParseAppleDeveloperId(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object
            || !value.TryGetProperty("team_id", out var teamIdNode)
            || teamIdNode.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(
                "AppleDeveloperId.team_id must be a string");
        }
        var teamId = teamIdNode.GetString()!;
        if (!IsValidAppleTeamId(teamId))
        {
            throw new InvalidOperationException(
                $"AppleDeveloperId.team_id '{teamId}' must be exactly 10 uppercase alphanumerics");
        }
        return new AppleDeveloperId(teamId);
    }

    /// <summary>
    /// Apple Team IDs are exactly 10 uppercase ASCII alphanumerics.
    /// Mirrors <c>PublisherIdentity::validate</c> on the Rust side.
    /// </summary>
    public static bool IsValidAppleTeamId(string value)
    {
        if (value.Length != 10) return false;
        foreach (var c in value)
        {
            if (!(c is >= '0' and <= '9' or >= 'A' and <= 'Z')) return false;
        }
        return true;
    }

    /// <summary>
    /// SHA-1 thumbprints are 40 lowercase hex characters. Mirrors the
    /// invariant on <c>PublisherIdentity::Authenticode.root_thumbprint</c>
    /// on the Rust side.
    /// </summary>
    public static bool IsValidSha1Thumbprint(string? value)
    {
        if (value is null || value.Length != 40) return false;
        foreach (var c in value)
        {
            if (!(c is >= '0' and <= '9' or >= 'a' and <= 'f')) return false;
        }
        return true;
    }
}
