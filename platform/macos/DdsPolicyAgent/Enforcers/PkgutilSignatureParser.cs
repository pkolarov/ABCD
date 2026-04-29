// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.RegularExpressions;

namespace DDS.PolicyAgent.MacOS.Enforcers;

/// <summary>
/// Pulls the Apple Developer Team ID out of <c>pkgutil --check-signature</c>
/// output. The leaf certificate row in pkgutil's "Certificate Chain"
/// section ends with a parenthesised 10-char Team ID:
/// <code>
///    1. Developer ID Installer: Acme Corp (ABCDE12345)
/// </code>
/// We pin the parser to that exact shape so a stray match elsewhere
/// in the output (e.g. a status line or comment) cannot satisfy the
/// gate. This is the *parser*; the policy decision (compare against
/// the expected publisher identity) lives in <see cref="SoftwareInstaller"/>.
/// </summary>
internal static partial class PkgutilSignatureParser
{
    // Match the leaf-cert line. Constraints:
    //   * Indented ("   1. ..." or any whitespace + digit + '.')
    //   * Subject text contains a colon (e.g. "Developer ID Installer:")
    //   * Trailing parenthesised 10-char Team ID at end of line
    [GeneratedRegex(
        @"^\s*\d+\.\s+.*:.*\(([0-9A-Z]{10})\)\s*$",
        RegexOptions.Multiline)]
    private static partial Regex LeafCertLineRegex();

    /// <summary>
    /// Return the first Team ID found in a "Developer ID …: …
    /// (XXXXXXXXXX)" leaf-certificate line. Returns <c>null</c> when
    /// the output does not contain such a line — that includes
    /// unsigned packages and signed-but-not-Developer-ID packages
    /// (e.g. an Apple-system component) which the policy agent must
    /// refuse when a publisher identity is pinned.
    /// </summary>
    public static string? ExtractTeamId(string pkgutilStdout)
    {
        if (string.IsNullOrEmpty(pkgutilStdout)) return null;
        var match = LeafCertLineRegex().Match(pkgutilStdout);
        return match.Success ? match.Groups[1].Value : null;
    }
}
