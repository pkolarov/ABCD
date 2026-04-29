// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json;

namespace DDS.PolicyAgent.MacOS.Enforcers;

/// <summary>
/// Parsed view of the optional <c>publisher_identity</c> field on a
/// <c>SoftwareAssignment</c> directive. Mirrors the
/// externally-tagged Rust enum at
/// <c>dds-domain/src/types.rs::PublisherIdentity</c>:
/// <code>
/// "publisher_identity": {"AppleDeveloperId": {"team_id": "ABCDE12345"}}
/// "publisher_identity": {"Authenticode": {"subject": "Acme", "root_thumbprint": "..."}}
/// </code>
/// SC-5 Phase B.3 only consumes the <c>AppleDeveloperId</c> variant; an
/// <c>Authenticode</c> variant on a macOS scope is treated as a
/// configuration error and rejected by the agent (the policy author
/// scoped a Windows-only signer expectation onto a macOS device).
/// </summary>
internal abstract record PublisherIdentitySpec
{
    /// <summary>
    /// macOS Developer ID. The agent must call
    /// <c>pkgutil --check-signature</c> on the staged package and
    /// compare the parsed Team ID against <see cref="TeamId"/>
    /// (case-sensitive — Apple Team IDs are 10 uppercase
    /// alphanumerics).
    /// </summary>
    public sealed record AppleDeveloperId(string TeamId) : PublisherIdentitySpec;

    /// <summary>
    /// Windows Authenticode pinning. Not enforceable on macOS — if the
    /// directive has this variant, the agent fails the install closed.
    /// </summary>
    public sealed record Authenticode(string Subject) : PublisherIdentitySpec;

    /// <summary>
    /// Parse the optional <c>publisher_identity</c> field from a
    /// <c>SoftwareAssignment</c> directive. Returns <c>null</c> when
    /// the field is absent (legacy hash-only behaviour); throws when
    /// the field is present but malformed (an unknown variant tag,
    /// missing inner fields, or a wrong-shape Apple Team ID — anything
    /// the agent cannot enforce should fail closed at parse time).
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
            "AppleDeveloperId" => ParseAppleDeveloperId(tag.Value),
            "Authenticode" => ParseAuthenticode(tag.Value),
            _ => throw new InvalidOperationException(
                $"unknown publisher_identity variant '{tag.Name}'"),
        };
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
        return new Authenticode(subject);
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
}
