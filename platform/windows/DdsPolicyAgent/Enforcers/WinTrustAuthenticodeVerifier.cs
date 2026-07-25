// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// <b>SC-5 Phase B.2 (security review)</b>: production Authenticode
/// verifier for Windows. Routes through
/// <c>WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)</c> for chain
/// trust (revocation + system root), then pulls the signer subject and
/// chain-root thumbprint out of the <i>same</i> WinTrust provider state
/// that produced the verdict.
///
/// <para>
/// <b>M-6 (pre-prod review 2026-07-24)</b>: the signer used to be read
/// with <c>new X509Certificate2(filePath)</c>. That constructor only
/// understands a PKCS#7 blob embedded in a PE file's certificate
/// directory — for a Windows Installer package the signature lives in
/// the OLE compound-document stream <c>\005DigitalSignature</c>, so the
/// constructor throws, the <c>catch</c> below turned that into
/// <c>IsValid = false</c>, and <i>every</i> MSI
/// <c>SoftwareAssignment</c> failed closed while
/// <c>RequirePackageSignature</c> defaults to <c>true</c>. The practical
/// consequence was worse than a broken install: the documented way out
/// is to turn signature enforcement off fleet-wide.
/// </para>
///
/// <para>
/// Reading the certificate back out of the WinTrust provider state
/// instead is both format-agnostic (WinTrust dispatches to the right
/// Subject Interface Package — PE, MSI, CAB, catalog) and strictly more
/// accurate: it reports the chain WinTrust actually validated rather
/// than one we rebuild afterwards from the file. The two calls no longer
/// race each other over the on-disk file at all, which also closes the
/// TOCTOU window the old two-pass approach carried.
/// </para>
///
/// Mirrors the macOS <c>pkgutil --check-signature</c> + Team-ID parse
/// approach (see <c>platform/macos/DdsPolicyAgent/Enforcers/SoftwareInstaller.cs</c>),
/// but using the Windows-native API surface. The class is
/// <c>SupportedOSPlatform("windows")</c> because all entry points
/// require Win32. Non-Windows builds get a stub at construction; the
/// agent's host wiring only registers this on Windows hosts.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WinTrustAuthenticodeVerifier : IAuthenticodeVerifier
{
    public AuthenticodeVerifyResult Verify(string filePath)
    {
        if (!File.Exists(filePath))
        {
            // Surface the staging bug directly — the caller already
            // re-checked existence in VerifyStagedFileBeforeLaunch, so
            // a missing file here is a hard error.
            throw new FileNotFoundException(
                "staged installer disappeared before Authenticode verify", filePath);
        }

        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        var actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        var data = new WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
            dwUIChoice = WTD_UI_NONE,
            fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice = WTD_CHOICE_FILE,
            pFile = fileInfoPtr,
            dwStateAction = WTD_STATEACTION_VERIFY,
            hWVTStateData = IntPtr.Zero,
            pwszURLReference = null,
            dwProvFlags = 0,
            dwUIContext = 0,
            pSignatureSettings = IntPtr.Zero,
        };

        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            var trustResult = WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);
            if (trustResult != 0)
            {
                return new AuthenticodeVerifyResult(
                    IsValid: false,
                    SignerSubject: null,
                    RootThumbprintSha1Hex: null,
                    Reason: $"WinVerifyTrust returned 0x{trustResult:X8}");
            }

            // M-6: extract from the live provider state, *before* the
            // CLOSE below frees it. This is the whole point of the fix —
            // the state handle already holds the parsed signer chain for
            // whatever subject type the file is (PE, MSI, CAB, catalog).
            return ExtractSignerFromState(data.hWVTStateData);
        }
        catch (Exception ex)
        {
            // Fail closed on anything unexpected, but say what happened —
            // an operator must be able to tell "unsigned" from "the agent
            // could not read the signer".
            return new AuthenticodeVerifyResult(
                IsValid: false,
                SignerSubject: null,
                RootThumbprintSha1Hex: null,
                Reason: $"signer-cert extract failed: {ex.Message}");
        }
        finally
        {
            // Always close to release the WinTrust state regardless of
            // result, then free the marshalled file-info block.
            if (data.hWVTStateData != IntPtr.Zero || data.dwStateAction == WTD_STATEACTION_VERIFY)
            {
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                _ = WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);
            }
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    /// <summary>
    /// Pull the signer subject and chain-root thumbprint out of a
    /// verified WinTrust state handle.
    ///
    /// <para>
    /// <c>WTHelperProvDataFromStateData</c> → <c>CRYPT_PROVIDER_DATA</c>,
    /// <c>WTHelperGetProvSignerFromChain</c> → the primary signer, then
    /// <c>WTHelperGetProvCertFromChain</c> indexes that signer's already-built
    /// certificate chain: element 0 is the leaf, element
    /// <c>csCertChain - 1</c> is the root. Using WinTrust's chain rather
    /// than rebuilding one with <see cref="X509Chain"/> means the
    /// thumbprint we report is the root that actually anchored the
    /// verdict.
    /// </para>
    /// </summary>
    private static AuthenticodeVerifyResult ExtractSignerFromState(IntPtr stateData)
    {
        if (stateData == IntPtr.Zero)
        {
            return new AuthenticodeVerifyResult(
                false, null, null, "WinTrust returned no provider state");
        }

        var provData = WTHelperProvDataFromStateData(stateData);
        if (provData == IntPtr.Zero)
        {
            return new AuthenticodeVerifyResult(
                false, null, null, "WTHelperProvDataFromStateData returned NULL");
        }

        var signer = WTHelperGetProvSignerFromChain(
            provData, dwSignerIdx: 0, fCounterSigner: false, dwCounterSignerIdx: 0);
        if (signer == IntPtr.Zero)
        {
            return new AuthenticodeVerifyResult(
                false, null, null, "WTHelperGetProvSignerFromChain returned NULL");
        }

        // `csCertChain` sits at a fixed 4-byte-aligned offset in
        // CRYPT_PROVIDER_SGNR (cbStruct:4 + FILETIME:8), identical on
        // x86 / x64 / ARM64, so reading it directly avoids marshalling
        // the whole (large, version-dependent) struct.
        var certCount = (uint)Marshal.ReadInt32(signer, CRYPT_PROVIDER_SGNR_CS_CERT_CHAIN_OFFSET);
        if (certCount == 0)
        {
            return new AuthenticodeVerifyResult(
                false, null, null, "signer chain is empty");
        }

        var leafCtx = ProvCertContext(signer, 0);
        if (leafCtx == IntPtr.Zero)
        {
            return new AuthenticodeVerifyResult(
                false, null, null, "could not read leaf certificate from signer chain");
        }

        // X509Certificate2(IntPtr) duplicates the underlying
        // CERT_CONTEXT, so the managed object stays valid after the
        // WinTrust state is closed. It is also not covered by SYSLIB0057
        // (which targets the file / byte-array constructors), so no
        // pragma suppression is needed here any more.
        using var leaf = new X509Certificate2(leafCtx);
        var subject = leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

        string? rootThumbprint = null;
        var rootCtx = ProvCertContext(signer, certCount - 1);
        if (rootCtx != IntPtr.Zero)
        {
            using var root = new X509Certificate2(rootCtx);
            rootThumbprint = root.Thumbprint?.ToLowerInvariant();
        }

        return new AuthenticodeVerifyResult(
            IsValid: true,
            SignerSubject: string.IsNullOrEmpty(subject) ? null : subject,
            RootThumbprintSha1Hex: string.IsNullOrEmpty(rootThumbprint) ? null : rootThumbprint,
            Reason: null);
    }

    /// <summary>
    /// <c>WTHelperGetProvCertFromChain(pSgnr, idx)-&gt;pCert</c>. Only the
    /// first two fields of <c>CRYPT_PROVIDER_CERT</c> are read
    /// (<c>cbStruct</c>, then the <c>PCCERT_CONTEXT</c>), which sit at a
    /// stable offset under sequential layout on every supported
    /// architecture.
    /// </summary>
    private static IntPtr ProvCertContext(IntPtr signer, uint index)
    {
        var provCert = WTHelperGetProvCertFromChain(signer, index);
        if (provCert == IntPtr.Zero)
        {
            return IntPtr.Zero;
        }
        var head = Marshal.PtrToStructure<CRYPT_PROVIDER_CERT_HEAD>(provCert);
        return head.pCert;
    }

    // ---- Win32 P/Invoke surface for WinVerifyTrust -------------------

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;

    /// <summary>
    /// Byte offset of <c>csCertChain</c> within <c>CRYPT_PROVIDER_SGNR</c>:
    /// <c>DWORD cbStruct</c> (4) + <c>FILETIME sftVerifyAsOf</c> (8).
    /// Both members are 4-byte aligned, so the offset is the same on
    /// x86, x64 and ARM64.
    /// </summary>
    private const int CRYPT_PROVIDER_SGNR_CS_CERT_CHAIN_OFFSET = 12;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    /// <summary>
    /// Leading members of <c>CRYPT_PROVIDER_CERT</c>. Deliberately
    /// partial: we never write it back and never rely on its total size,
    /// only on <c>pCert</c> following <c>cbStruct</c> under the platform's
    /// natural alignment — which is what the C header specifies.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct CRYPT_PROVIDER_CERT_HEAD
    {
        public uint cbStruct;
        public IntPtr pCert;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", SetLastError = false)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    [DllImport("wintrust.dll", SetLastError = false)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr pProvData,
        uint dwSignerIdx,
        [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner,
        uint dwCounterSignerIdx);

    [DllImport("wintrust.dll", SetLastError = false)]
    private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, uint idxCert);
}
