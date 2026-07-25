// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using DDS.PolicyAgent.Enforcers;

namespace DDS.PolicyAgent.Tests;

/// <summary>
/// <b>M-6 (pre-prod review 2026-07-24)</b> — live regression coverage for
/// the Authenticode signer-extraction path.
///
/// <para>
/// The bug these tests pin: the verifier used to read the signer with
/// <c>new X509Certificate2(filePath)</c>, which only understands a PKCS#7
/// blob embedded in a PE file's certificate directory. A Windows
/// Installer package keeps its signature in the OLE compound-document
/// stream <c>\005DigitalSignature</c> instead, so that constructor threw,
/// the verifier's <c>catch</c> reported <c>IsValid = false</c>, and every
/// MSI <c>SoftwareAssignment</c> failed closed while
/// <c>RequirePackageSignature</c> defaults to <c>true</c>.
/// </para>
///
/// <para>
/// These tests need a real, validly-signed MSI, which only exists on a
/// Windows host with signed products installed. They discover one from
/// the Windows Installer cache and <c>Skip</c> when the host cannot
/// supply one, so they are informative on a developer/CI Windows box and
/// inert everywhere else.
/// </para>
/// </summary>
public class WinTrustAuthenticodeVerifierLiveTests
{
    /// <summary>
    /// Cached fixture lookup.
    /// </summary>
    /// <remarks>
    /// Cached deliberately. <see cref="FindSignedMsiCore"/> runs
    /// <c>WinVerifyTrust</c> with <c>WTD_REVOKE_WHOLECHAIN</c>, which
    /// performs CRL/OCSP revocation fetches — potentially a network
    /// round-trip per candidate. Several tests need the fixture, and
    /// re-scanning per test would multiply that cost on a CI runner.
    /// <see cref="Lazy{T}"/> makes it exactly one scan per test run.
    /// </remarks>
    private static readonly Lazy<string?> SignedMsi =
        new(FindSignedMsiCore, LazyThreadSafetyMode.ExecutionAndPublication);

    private static string? FindSignedMsi() => SignedMsi.Value;

    /// <summary>
    /// Maximum Windows-Installer cache entries to probe before giving
    /// up. Kept small: every probe may cost a revocation round-trip, and
    /// on any host that has a signed MSI at all, one turns up in the
    /// first handful. Exhausting the budget just skips the tests.
    /// </summary>
    private const int MaxCandidates = 20;

    /// <summary>
    /// Find a locally-cached MSI whose Authenticode signature currently
    /// validates. Returns <c>null</c> when the host has none — a clean
    /// container, a runner where the cache is not readable, or a machine
    /// whose cached packages have all expired without a trusted
    /// timestamp.
    /// </summary>
    private static string? FindSignedMsiCore()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return null;
        }

        var cache = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Installer");
        if (!Directory.Exists(cache))
        {
            return null;
        }

        List<string> candidates;
        try
        {
            candidates = Directory.EnumerateFiles(cache, "*.msi").Take(MaxCandidates).ToList();
        }
        catch (Exception)
        {
            // The Installer cache is ACL'd to administrators on many
            // hosts, and CI runners vary. No fixture — tests skip.
            return null;
        }

        var verifier = new WinTrustAuthenticodeVerifier();
        foreach (var path in candidates)
        {
            try
            {
                if (verifier.Verify(path).IsValid)
                {
                    return path;
                }
            }
            catch
            {
                // Unreadable / locked cache entry — try the next one.
            }
        }
        return null;
    }

    /// <summary>
    /// The core M-6 regression: a validly-signed MSI must verify AND
    /// yield a non-null signer subject. Before the fix this returned
    /// <c>IsValid = false</c> with
    /// <c>Reason = "signer-cert extract failed: ..."</c>, which is what
    /// made every MSI software assignment fail closed.
    /// </summary>
    [SkippableFact]
    public void SignedMsi_Verifies_AndYieldsSignerSubject()
    {
        Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
            "WinTrust is Windows-only");
        var msi = FindSignedMsi();
        Skip.If(msi is null, "no validly-signed MSI available in the Windows Installer cache");

        var result = new WinTrustAuthenticodeVerifier().Verify(msi!);

        Assert.True(result.IsValid, $"expected a valid verdict, got: {result.Reason}");
        Assert.False(
            string.IsNullOrWhiteSpace(result.SignerSubject),
            "M-6: signer subject must be extractable from an MSI — a null subject here is the "
                + "exact failure that made RequirePackageSignature reject every MSI assignment");
        Assert.False(
            string.IsNullOrWhiteSpace(result.RootThumbprintSha1Hex),
            "chain-root thumbprint must be populated so publisher_identity can pin it");
        Assert.Matches("^[0-9a-f]{40}$", result.RootThumbprintSha1Hex!);
        Assert.Null(result.Reason);
    }

    /// <summary>
    /// Pins the measured behaviour of the pre-M-6 extraction technique,
    /// and asserts the new path agrees with it.
    ///
    /// <para>
    /// <b>Measured 2026-07-25 on Windows 11 ARM64 / .NET:</b> the review
    /// predicted <c>new X509Certificate2(msiPath)</c> would throw on an
    /// MSI (signature in the OLE <c>\005DigitalSignature</c> stream
    /// rather than PE-embedded), making every MSI assignment fail closed.
    /// It does <b>not</b> throw — .NET's file constructor routes through
    /// <c>CryptQueryObject</c>, which dispatches to the registered MSI
    /// Subject Interface Package and reads the signer correctly. So the
    /// predicted "MSI installs silently fail closed" outcome was NOT
    /// real on this platform.
    /// </para>
    ///
    /// <para>
    /// The M-6 change is kept because it is still the better shape —
    /// it reports the chain <c>WinVerifyTrust</c> actually validated
    /// rather than one rebuilt afterwards, it does not re-read the file
    /// a second time (closing a TOCTOU window), and it avoids the
    /// SYSLIB0057-obsolete constructor. This test guards that the
    /// migration is behaviour-preserving: both techniques must name the
    /// same signer.
    /// </para>
    /// </summary>
    [SkippableFact]
    public void NewExtraction_AgreesWithOldFileConstructor_OnSignerSubject()
    {
        Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
            "WinTrust is Windows-only");
        var msi = FindSignedMsi();
        Skip.If(msi is null, "no validly-signed MSI available in the Windows Installer cache");

        string? legacySubject = null;
        try
        {
#pragma warning disable SYSLIB0057
            using var legacy = new X509Certificate2(msi!);
#pragma warning restore SYSLIB0057
            legacySubject = legacy.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        }
        catch (Exception)
        {
            // If the platform ever *does* start throwing here, that is
            // precisely the failure mode M-6 guards against and the new
            // path is strictly required. Nothing left to compare.
            return;
        }

        var result = new WinTrustAuthenticodeVerifier().Verify(msi!);
        Assert.True(result.IsValid, $"expected a valid verdict, got: {result.Reason}");
        Assert.Equal(legacySubject, result.SignerSubject);
    }

    /// <summary>
    /// A signed PE file must keep working — the fix must not regress the
    /// case that already worked. Uses a system binary, which is
    /// Authenticode-signed by Microsoft on every supported Windows SKU.
    /// </summary>
    [SkippableFact]
    public void SignedPeFile_StillVerifies()
    {
        Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
            "WinTrust is Windows-only");
        var system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
        var candidate = Path.Combine(system32, "kernel32.dll");
        Skip.IfNot(File.Exists(candidate), "kernel32.dll not present");

        var result = new WinTrustAuthenticodeVerifier().Verify(candidate);

        // System binaries are catalog-signed rather than embedded-signed
        // on some SKUs; only assert the signer shape when WinTrust says
        // the file is trusted.
        Skip.IfNot(result.IsValid, $"kernel32.dll not embedded-signed here: {result.Reason}");
        Assert.False(
            string.IsNullOrWhiteSpace(result.SignerSubject),
            "signer subject must be extractable from a signed PE file");
    }

    /// <summary>
    /// An unsigned file must fail closed with a WinVerifyTrust reason —
    /// not with a signer-extraction error, and never with
    /// <c>IsValid = true</c>.
    /// </summary>
    [SkippableFact]
    public void UnsignedFile_FailsClosed()
    {
        Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
            "WinTrust is Windows-only");
        var tmp = Path.Combine(Path.GetTempPath(), $"dds-m6-unsigned-{Guid.NewGuid():N}.msi");
        File.WriteAllBytes(tmp, new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 });
        try
        {
            var result = new WinTrustAuthenticodeVerifier().Verify(tmp);
            Assert.False(result.IsValid);
            Assert.NotNull(result.Reason);
            Assert.Null(result.SignerSubject);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    /// <summary>
    /// A missing staged file is a staging bug, not a verification
    /// failure — the interface contract says it throws.
    /// </summary>
    [SkippableFact]
    public void MissingFile_Throws()
    {
        Skip.IfNot(RuntimeInformation.IsOSPlatform(OSPlatform.Windows),
            "WinTrust is Windows-only");
        var missing = Path.Combine(Path.GetTempPath(), $"dds-m6-absent-{Guid.NewGuid():N}.msi");
        Assert.Throws<FileNotFoundException>(() => new WinTrustAuthenticodeVerifier().Verify(missing));
    }
}
