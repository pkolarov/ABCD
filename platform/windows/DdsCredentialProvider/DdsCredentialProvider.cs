// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DDS Windows Credential Provider — .NET STUB (SUPERSEDED)
//
// *** This .NET stub has been superseded by the native C++ Credential
// *** Provider at platform/windows/native/DdsCredentialProvider/.
// *** The native implementation is forked from the Crayonic Credential
// *** Provider and provides production-quality COM integration, BLE/FIDO2
// *** auth via the DDS Auth Bridge service, and proper LSA hand-off.
// ***
// *** This file is kept for reference and for the DdsLocalClient HTTP
// *** client which may still be useful for .NET integration tests.
//
// ORIGINAL DESCRIPTION:
// This file is intentionally a *stub* of the Windows Credential
// Provider COM surface. We declare the COM-visible types with the
// expected GUIDs and the `ICredentialProvider` shape, but we do NOT
// implement the full COM marshalling required for production
// registration. Full registration requires:
//
//   1. A `regsvr32`-style installer that writes to
//      HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\
//      Credential Providers\{CLSID}
//   2. A 64-bit native shim that hosts the .NET assembly via
//      `comhost.dll`, registered under HKLM\SOFTWARE\Classes\CLSID\{CLSID}.
//   3. PInvoke / ICredentialProviderCredential implementations that
//      hand the resulting `SessionDocument` to LSA via
//      `KerbInteractiveLogon` or a custom Authentication Package.
//
// All of the above is outside the scope of Phase 2. What this file
// *does* provide:
//
//   - The HTTP integration with dds-node's `/v1/session` endpoint.
//   - A passkey-derived subject URN helper.
//   - A class with `[ComVisible]` and `[Guid(...)]` attributes that
//     mirrors the public surface a real provider would expose.
//   - Strongly-typed deserialization of the SessionDocument JSON
//     returned from dds-node.
//
// See README.md in this folder for the registration story and what
// is stubbed.

using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace DDS.CredentialProvider
{
    /// <summary>
    /// Stable CLSID for the DDS credential provider. A real installer
    /// would use this value when writing registry keys for both
    /// HKLM\SOFTWARE\Classes\CLSID and the Authentication\Credential
    /// Providers list.
    /// </summary>
    public static class DdsClsid
    {
        public const string Provider = "8C0DBE9A-5E27-4DDA-9A4B-3B5C8A6E2A11";
    }

    /// <summary>
    /// Result of a successful local session issuance.
    /// </summary>
    public sealed class DdsSessionResult
    {
        [JsonPropertyName("session_id")]
        public string SessionId { get; set; } = string.Empty;

        [JsonPropertyName("token_cbor_b64")]
        public string TokenBase64 { get; set; } = string.Empty;

        [JsonPropertyName("expires_at")]
        public long ExpiresAt { get; set; }
    }

    /// <summary>
    /// Request body for POST /v1/session against dds-node.
    /// Mirrors `dds_node::http::SessionRequestBody`.
    /// </summary>
    internal sealed class DdsSessionRequest
    {
        [JsonPropertyName("subject_urn")]
        public string SubjectUrn { get; set; } = string.Empty;

        [JsonPropertyName("device_urn")]
        public string? DeviceUrn { get; set; }

        [JsonPropertyName("requested_resources")]
        public string[] RequestedResources { get; set; } = Array.Empty<string>();

        [JsonPropertyName("duration_secs")]
        public ulong DurationSecs { get; set; } = 3600;

        [JsonPropertyName("mfa_verified")]
        public bool MfaVerified { get; set; } = true;

        [JsonPropertyName("tls_binding")]
        public string? TlsBinding { get; set; }
    }

    /// <summary>
    /// Thin client over the dds-node HTTP API on 127.0.0.1.
    /// </summary>
    public sealed class DdsLocalClient : IDisposable
    {
        private readonly HttpClient _http;
        private readonly Uri _baseUri;

        public DdsLocalClient(int port = 5551)
        {
            _baseUri = new Uri($"http://127.0.0.1:{port}/");
            _http = new HttpClient { BaseAddress = _baseUri, Timeout = TimeSpan.FromSeconds(5) };
        }

        /// <summary>
        /// Derive the DDS subject URN from a FIDO2 credential ID. The
        /// real DDS scheme uses Vouchsafe URNs (`urn:vouchsafe:label.<hash>`);
        /// here we hash the credential id and label it `passkey`.
        /// </summary>
        public static string SubjectUrnForCredential(string credentialId)
        {
            if (string.IsNullOrWhiteSpace(credentialId))
            {
                throw new ArgumentException("credentialId required", nameof(credentialId));
            }

            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(Encoding.UTF8.GetBytes(credentialId));
            // base32 encode (lowercase, no padding) to match Vouchsafe.
            var b32 = Base32.Encode(hash).ToLowerInvariant().TrimEnd('=');
            return $"urn:vouchsafe:passkey.{b32}";
        }

        /// <summary>
        /// POST /v1/session and parse the SessionDocument response.
        /// </summary>
        public async Task<DdsSessionResult> IssueSessionAsync(
            string subjectUrn,
            string[] resources,
            CancellationToken ct = default)
        {
            var body = new DdsSessionRequest
            {
                SubjectUrn = subjectUrn,
                RequestedResources = resources,
                MfaVerified = true,
                DurationSecs = 3600,
            };
            using var resp = await _http.PostAsJsonAsync("v1/session", body, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            var result = await resp.Content.ReadFromJsonAsync<DdsSessionResult>(cancellationToken: ct).ConfigureAwait(false);
            if (result is null)
            {
                throw new InvalidOperationException("dds-node returned an empty session response");
            }
            return result;
        }

        public void Dispose() => _http.Dispose();
    }

    /// <summary>
    /// Stand-in for the unmanaged ICredentialProvider COM interface.
    /// In a real implementation we would `[ComImport]` Microsoft's
    /// definition from credentialprovider.h. We expose a minimal
    /// managed shape so callers can be unit-tested without the COM
    /// runtime present.
    /// </summary>
    public interface ICredentialProvider
    {
        /// <summary>
        /// Called by LogonUI when the user selects this provider.
        /// </summary>
        DdsSessionResult Authenticate(string credentialId, string[] requestedResources);
    }

    /// <summary>
    /// The DDS credential provider. Marked COM-visible with the stable
    /// CLSID so a real installer can register it. The actual logon
    /// hand-off (LSA / Authentication Package) is stubbed — see README.
    /// </summary>
    [ComVisible(true)]
    [Guid(DdsClsid.Provider)]
    [ClassInterface(ClassInterfaceType.None)]
    public sealed class DdsCredentialProvider : ICredentialProvider, IDisposable
    {
        private readonly DdsLocalClient _client;

        public DdsCredentialProvider() : this(new DdsLocalClient())
        {
        }

        public DdsCredentialProvider(DdsLocalClient client)
        {
            _client = client;
        }

        /// <inheritdoc />
        public DdsSessionResult Authenticate(string credentialId, string[] requestedResources)
        {
            var subject = DdsLocalClient.SubjectUrnForCredential(credentialId);
            // Block synchronously — credential providers run on a STA
            // worker thread and can't easily await.
            return _client
                .IssueSessionAsync(subject, requestedResources)
                .GetAwaiter()
                .GetResult();
        }

        public void Dispose() => _client.Dispose();
    }

    /// <summary>
    /// Minimal RFC 4648 base32 encoder. Vouchsafe URNs use lower-case
    /// base32 without padding. We avoid pulling in a full crate so the
    /// assembly stays small.
    /// </summary>
    internal static class Base32
    {
        private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        public static string Encode(byte[] data)
        {
            if (data.Length == 0)
            {
                return string.Empty;
            }

            var sb = new StringBuilder((data.Length * 8 + 4) / 5);
            int buffer = data[0];
            int next = 1;
            int bitsLeft = 8;

            while (bitsLeft > 0 || next < data.Length)
            {
                if (bitsLeft < 5)
                {
                    if (next < data.Length)
                    {
                        buffer <<= 8;
                        buffer |= data[next++] & 0xFF;
                        bitsLeft += 8;
                    }
                    else
                    {
                        int pad = 5 - bitsLeft;
                        buffer <<= pad;
                        bitsLeft = 5;
                    }
                }

                int index = 0x1F & (buffer >> (bitsLeft - 5));
                bitsLeft -= 5;
                sb.Append(Alphabet[index]);
            }

            return sb.ToString();
        }
    }
}
