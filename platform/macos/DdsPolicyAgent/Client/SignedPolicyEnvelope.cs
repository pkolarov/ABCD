// SPDX-License-Identifier: MIT OR Apache-2.0

using System.Text.Json.Serialization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace DDS.PolicyAgent.MacOS.Client;

/// <summary>
/// Wire shape of the <c>SignedPolicyEnvelope</c> returned by the
/// dds-node <c>/v1/macos/{policies,software}</c> endpoints.
///
/// <para>
/// <b>H-3 (security review)</b>: the macOS agent runs as root and
/// applies managed preferences, launchd plists, local-account
/// changes, and software installs based on the response body.
/// Without an application-layer signature, a local process that
/// hijacks the localhost endpoint can drive the agent into
/// root-level actions. The envelope binds the JSON payload to
/// the issuing node's Ed25519 signing key, pinned at provisioning.
/// </para>
/// </summary>
public sealed class SignedPolicyEnvelope
{
    [JsonPropertyName("version")]
    public byte Version { get; set; }

    [JsonPropertyName("kind")]
    public string Kind { get; set; } = string.Empty;

    [JsonPropertyName("device_urn")]
    public string DeviceUrn { get; set; } = string.Empty;

    [JsonPropertyName("issued_at")]
    public ulong IssuedAt { get; set; }

    [JsonPropertyName("payload_b64")]
    public string PayloadB64 { get; set; } = string.Empty;

    [JsonPropertyName("signature_b64")]
    public string SignatureB64 { get; set; } = string.Empty;

    [JsonPropertyName("node_urn")]
    public string NodeUrn { get; set; } = string.Empty;

    [JsonPropertyName("node_pubkey_b64")]
    public string NodePubkeyB64 { get; set; } = string.Empty;
}

public static class EnvelopeKind
{
    public const string MacOsPolicies = "macos-policies";
    public const string MacOsSoftware = "macos-software";
}

/// <summary>
/// Verifies <see cref="SignedPolicyEnvelope"/> instances against a
/// pinned Ed25519 node public key. See the Windows agent's
/// equivalent file for the full trust-model discussion; the
/// implementation is intentionally byte-for-byte identical so both
/// platforms decode the same Rust-side signing layout.
/// </summary>
public sealed class EnvelopeVerifier
{
    private static readonly byte[] DomainTag =
        System.Text.Encoding.ASCII.GetBytes("dds-policy-envelope-v1");

    private readonly byte[] _pinnedPubkey;
    private readonly string _expectedDeviceUrn;
    private readonly TimeSpan _maxClockSkew;

    public EnvelopeVerifier(
        byte[] pinnedPubkey, string expectedDeviceUrn, TimeSpan? maxClockSkew = null)
    {
        if (pinnedPubkey is null || pinnedPubkey.Length != 32)
            throw new ArgumentException("pinned Ed25519 public key must be 32 bytes", nameof(pinnedPubkey));
        if (string.IsNullOrWhiteSpace(expectedDeviceUrn))
            throw new ArgumentException("expectedDeviceUrn is required", nameof(expectedDeviceUrn));

        _pinnedPubkey = (byte[])pinnedPubkey.Clone();
        _expectedDeviceUrn = expectedDeviceUrn;
        _maxClockSkew = maxClockSkew ?? TimeSpan.FromSeconds(300);
    }

    public byte[] VerifyAndUnwrap(SignedPolicyEnvelope env, string expectedKind)
    {
        ArgumentNullException.ThrowIfNull(env);
        if (env.Version != 1)
            throw new EnvelopeVerificationException("unsupported envelope version");

        if (!string.Equals(env.Kind, expectedKind, StringComparison.Ordinal))
            throw new EnvelopeVerificationException("envelope kind mismatch");

        if (!string.Equals(env.DeviceUrn, _expectedDeviceUrn, StringComparison.Ordinal))
            throw new EnvelopeVerificationException("envelope device_urn mismatch");

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var skew = Math.Abs(now - (long)env.IssuedAt);
        if (skew > (long)_maxClockSkew.TotalSeconds)
            throw new EnvelopeVerificationException("envelope issued_at outside clock-skew window");

        byte[] serverPubkey;
        try { serverPubkey = Convert.FromBase64String(env.NodePubkeyB64); }
        catch (FormatException) { throw new EnvelopeVerificationException("node_pubkey_b64 malformed"); }
        if (serverPubkey.Length != 32 || !CryptographicEquals(serverPubkey, _pinnedPubkey))
            throw new EnvelopeVerificationException("server-claimed pubkey differs from pinned pubkey");

        byte[] payload;
        try { payload = Convert.FromBase64String(env.PayloadB64); }
        catch (FormatException) { throw new EnvelopeVerificationException("payload_b64 malformed"); }

        byte[] signature;
        try { signature = Convert.FromBase64String(env.SignatureB64); }
        catch (FormatException) { throw new EnvelopeVerificationException("signature_b64 malformed"); }
        if (signature.Length != 64)
            throw new EnvelopeVerificationException("signature must be 64 bytes");

        var msg = BuildSigningBytes(env.DeviceUrn, env.Kind, env.IssuedAt, payload);
        if (!VerifyEd25519(_pinnedPubkey, msg, signature))
            throw new EnvelopeVerificationException("signature did not verify");

        return payload;
    }

    internal static byte[] BuildSigningBytes(
        string deviceUrn, string envelopeKind, ulong issuedAt, byte[] payload)
    {
        var deviceBytes = System.Text.Encoding.UTF8.GetBytes(deviceUrn);
        var kindBytes = System.Text.Encoding.UTF8.GetBytes(envelopeKind);

        var total = DomainTag.Length
            + 4 + deviceBytes.Length
            + 4 + kindBytes.Length
            + 8
            + 4 + payload.Length;

        var buf = new byte[total];
        var offset = 0;

        Buffer.BlockCopy(DomainTag, 0, buf, offset, DomainTag.Length);
        offset += DomainTag.Length;

        WriteUInt32LE(buf, offset, (uint)deviceBytes.Length); offset += 4;
        Buffer.BlockCopy(deviceBytes, 0, buf, offset, deviceBytes.Length);
        offset += deviceBytes.Length;

        WriteUInt32LE(buf, offset, (uint)kindBytes.Length); offset += 4;
        Buffer.BlockCopy(kindBytes, 0, buf, offset, kindBytes.Length);
        offset += kindBytes.Length;

        WriteUInt64LE(buf, offset, issuedAt); offset += 8;

        WriteUInt32LE(buf, offset, (uint)payload.Length); offset += 4;
        Buffer.BlockCopy(payload, 0, buf, offset, payload.Length);

        return buf;
    }

    private static void WriteUInt32LE(byte[] buf, int offset, uint v)
    {
        buf[offset] = (byte)v;
        buf[offset + 1] = (byte)(v >> 8);
        buf[offset + 2] = (byte)(v >> 16);
        buf[offset + 3] = (byte)(v >> 24);
    }

    private static void WriteUInt64LE(byte[] buf, int offset, ulong v)
    {
        buf[offset] = (byte)v;
        buf[offset + 1] = (byte)(v >> 8);
        buf[offset + 2] = (byte)(v >> 16);
        buf[offset + 3] = (byte)(v >> 24);
        buf[offset + 4] = (byte)(v >> 32);
        buf[offset + 5] = (byte)(v >> 40);
        buf[offset + 6] = (byte)(v >> 48);
        buf[offset + 7] = (byte)(v >> 56);
    }

    private static bool VerifyEd25519(byte[] pubkey, byte[] msg, byte[] signature)
    {
        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(pubkey, 0));
        verifier.BlockUpdate(msg, 0, msg.Length);
        return verifier.VerifySignature(signature);
    }

    private static bool CryptographicEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }
}

public sealed class EnvelopeVerificationException : Exception
{
    public EnvelopeVerificationException(string message) : base(message) { }
}
