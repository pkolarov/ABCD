// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace DDS.PolicyAgent.Enforcers;

/// <summary>
/// <b>SC-5 Phase B.2 (security review)</b>: production Authenticode
/// verifier for Windows. Routes through
/// <c>WinVerifyTrust(WINTRUST_ACTION_GENERIC_VERIFY_V2)</c> for chain
/// trust (revocation + system root) and
/// <see cref="X509Certificate2"/> for signer-subject and chain-root
/// thumbprint extraction. The two calls share the same on-disk file —
/// the staged installer inside the SYSTEM-only DACL (B-6) — so a
/// TOCTOU swap between them is bounded by the same window already
/// covered by <c>VerifyStagedFileBeforeLaunch</c>.
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

        var trustResult = InvokeWinVerifyTrust(filePath);
        if (trustResult != 0)
        {
            return new AuthenticodeVerifyResult(
                IsValid: false,
                SignerSubject: null,
                RootThumbprintSha1Hex: null,
                Reason: $"WinVerifyTrust returned 0x{trustResult:X8}");
        }

        // Chain pull: load the embedded signer cert + walk the chain to
        // extract the root thumbprint. WinVerifyTrust already validated
        // the chain — this call is for *labelling* (signer subject + root
        // thumbprint), not for trust.
        try
        {
            using var leaf = X509CertificateLoader.LoadCertificateFromFile(filePath);
            var subject = leaf.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            string? rootThumbprint = null;
            using (var chain = new X509Chain())
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // already done by WinVerifyTrust
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
                chain.Build(leaf);
                if (chain.ChainElements.Count > 0)
                {
                    var root = chain.ChainElements[^1].Certificate;
                    rootThumbprint = root.Thumbprint?.ToLowerInvariant();
                }
            }

            return new AuthenticodeVerifyResult(
                IsValid: true,
                SignerSubject: string.IsNullOrEmpty(subject) ? null : subject,
                RootThumbprintSha1Hex: rootThumbprint,
                Reason: null);
        }
        catch (Exception ex)
        {
            // WinVerifyTrust passed but we couldn't pull the cert info —
            // very rare (would mean the file was tampered between calls)
            // but fail closed.
            return new AuthenticodeVerifyResult(
                IsValid: false,
                SignerSubject: null,
                RootThumbprintSha1Hex: null,
                Reason: $"signer-cert extract failed: {ex.Message}");
        }
    }

    // ---- Win32 P/Invoke surface for WinVerifyTrust -------------------

    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_WHOLECHAIN = 1;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;

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

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = false)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    private static int InvokeWinVerifyTrust(string filePath)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

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

            var actionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            var result = WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);

            // Always close to release the WinTrust state regardless of result.
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            _ = WinVerifyTrust(IntPtr.Zero, ref actionId, ref data);
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }
}
