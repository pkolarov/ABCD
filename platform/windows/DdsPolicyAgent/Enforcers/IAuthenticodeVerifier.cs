// SPDX-License-Identifier: MIT OR Apache-2.0

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// Result of an Authenticode verification on a staged installer.
/// Mirrors the macOS <c>pkgutil --check-signature</c> outcome but
/// surfaces both the signer subject and the chain-root thumbprint so a
/// publisher_identity directive can pin either or both.
/// </summary>
/// <param name="IsValid">
/// <c>true</c> iff <c>WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)</c>
/// returns <c>0</c> (the signature embeds and chains to a system-trusted
/// root). A revoked, expired (without a trusted timestamp), or
/// untrusted-chain certificate produces <c>false</c>.
/// </param>
/// <param name="SignerSubject">
/// The signer's <c>CertGetNameString(CERT_NAME_SIMPLE_DISPLAY_TYPE)</c>
/// — typically the Common Name from the Subject distinguished name
/// (e.g. "Acme Corporation"). <c>null</c> on a verification failure
/// where no signer chain could be parsed.
/// </param>
/// <param name="RootThumbprintSha1Hex">
/// SHA-1 thumbprint of the chain root certificate, as 40 lowercase hex
/// chars. <c>null</c> when the chain has fewer than two elements (a
/// self-signed leaf) or when the file is unsigned. The publisher_identity
/// directive's optional thumbprint compares against this value.
/// </param>
/// <param name="Reason">
/// Human-readable failure reason when <see cref="IsValid"/> is
/// <c>false</c>. The agent surfaces this in the enforcement outcome's
/// error message so an operator can disambiguate "unsigned" from
/// "revoked" without inspecting the host.
/// </param>
public sealed record AuthenticodeVerifyResult(
    bool IsValid,
    string? SignerSubject,
    string? RootThumbprintSha1Hex,
    string? Reason);

/// <summary>
/// Thin abstraction over <c>WinVerifyTrust</c> + <c>CertGetNameString</c>
/// so the SC-5 Phase B.2 signature gate can be unit-tested on
/// non-Windows hosts. The production implementation
/// (<see cref="WinTrustAuthenticodeVerifier"/>) shells into the Win32
/// crypto APIs; tests inject a stub.
/// </summary>
public interface IAuthenticodeVerifier
{
    /// <summary>
    /// Verify the Authenticode signature of the file at
    /// <paramref name="filePath"/>. Returns a populated
    /// <see cref="AuthenticodeVerifyResult"/>; never throws on a
    /// verification failure (callers must read
    /// <see cref="AuthenticodeVerifyResult.IsValid"/>). Throws only on
    /// I/O errors that indicate the file is gone — those are
    /// propagated to surface a TOCTOU/staging bug.
    /// </summary>
    AuthenticodeVerifyResult Verify(string filePath);
}
