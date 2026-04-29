// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Cross-platform fallback used when the agent is built against
/// <c>net*.0</c> on a non-Windows host (e.g. unit-test runs on macOS
/// CI). The signature gate refuses to apply any directive that
/// requires Authenticode — <c>RequirePackageSignature = true</c> or a
/// non-null <c>publisher_identity</c> fail closed with a clear reason.
/// Production Windows builds register
/// <see cref="WinTrustAuthenticodeVerifier"/> instead in
/// <c>Program.cs</c>.
/// </summary>
public sealed class StubAuthenticodeVerifier : IAuthenticodeVerifier
{
    public AuthenticodeVerifyResult Verify(string filePath)
    {
        return new AuthenticodeVerifyResult(
            IsValid: false,
            SignerSubject: null,
            RootThumbprintSha1Hex: null,
            Reason: "Authenticode verification is only available on Windows hosts");
    }
}
