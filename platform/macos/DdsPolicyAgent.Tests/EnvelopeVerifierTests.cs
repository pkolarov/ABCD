// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent.MacOS.Client;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace DDS.PolicyAgent.MacOS.Tests;

/// <summary>
/// Mirror of the Windows agent's envelope-verifier tests. Both
/// suites exercise the same <c>dds_core::envelope</c> wire format
/// via BouncyCastle Ed25519.
/// </summary>
public class EnvelopeVerifierTests
{
    private const string DeviceUrn = "urn:vouchsafe:dev.abc123";
    private const string Kind = EnvelopeKind.MacOsPolicies;

    private static (byte[] pub, Ed25519PrivateKeyParameters priv) GenerateKey()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair = gen.GenerateKeyPair();
        var priv = (Ed25519PrivateKeyParameters)pair.Private;
        var pub = ((Ed25519PublicKeyParameters)pair.Public).GetEncoded();
        return (pub, priv);
    }

    private static SignedPolicyEnvelope BuildEnvelope(
        byte[] pub, Ed25519PrivateKeyParameters priv,
        string deviceUrn, string kind, ulong issuedAt, byte[] payload)
    {
        var msg = EnvelopeVerifier.BuildSigningBytes(deviceUrn, kind, issuedAt, payload);
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, priv);
        signer.BlockUpdate(msg, 0, msg.Length);
        var sig = signer.GenerateSignature();
        return new SignedPolicyEnvelope
        {
            Version = 1,
            Kind = kind,
            DeviceUrn = deviceUrn,
            IssuedAt = issuedAt,
            PayloadB64 = Convert.ToBase64String(payload),
            SignatureB64 = Convert.ToBase64String(sig),
            NodeUrn = "urn:vouchsafe:node.xyz",
            NodePubkeyB64 = Convert.ToBase64String(pub),
        };
    }

    [Fact]
    public void RoundTripVerifies()
    {
        var (pub, priv) = GenerateKey();
        var payload = System.Text.Encoding.UTF8.GetBytes("{\"policies\":[]}");
        var now = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var env = BuildEnvelope(pub, priv, DeviceUrn, Kind, now, payload);

        var verifier = new EnvelopeVerifier(pub, DeviceUrn);
        var got = verifier.VerifyAndUnwrap(env, Kind);
        Assert.Equal(payload, got);
    }

    [Fact]
    public void KindSpliceRejected()
    {
        var (pub, priv) = GenerateKey();
        var payload = System.Text.Encoding.UTF8.GetBytes("{}");
        var now = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var env = BuildEnvelope(pub, priv, DeviceUrn, EnvelopeKind.MacOsPolicies, now, payload);

        var verifier = new EnvelopeVerifier(pub, DeviceUrn);
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, EnvelopeKind.MacOsSoftware));
    }

    [Fact]
    public void DeviceUrnMismatchRejected()
    {
        var (pub, priv) = GenerateKey();
        var payload = System.Text.Encoding.UTF8.GetBytes("{}");
        var now = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var env = BuildEnvelope(pub, priv, "urn:vouchsafe:dev.evil", Kind, now, payload);

        var verifier = new EnvelopeVerifier(pub, DeviceUrn);
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, Kind));
    }

    [Fact]
    public void ServerClaimedPubkeyMismatchRejected()
    {
        var (pub, priv) = GenerateKey();
        var (otherPub, _) = GenerateKey();
        var payload = System.Text.Encoding.UTF8.GetBytes("{}");
        var now = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var env = BuildEnvelope(pub, priv, DeviceUrn, Kind, now, payload);
        env.NodePubkeyB64 = Convert.ToBase64String(otherPub);

        var verifier = new EnvelopeVerifier(pub, DeviceUrn);
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, Kind));
    }

    [Fact]
    public void TamperedPayloadRejected()
    {
        var (pub, priv) = GenerateKey();
        var payload = System.Text.Encoding.UTF8.GetBytes("{\"policies\":[]}");
        var now = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var env = BuildEnvelope(pub, priv, DeviceUrn, Kind, now, payload);
        env.PayloadB64 = Convert.ToBase64String(
            System.Text.Encoding.UTF8.GetBytes("{\"policies\":[{\"p\":\"evil\"}]}"));

        var verifier = new EnvelopeVerifier(pub, DeviceUrn);
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, Kind));
    }

    [Fact]
    public void StaleIssuedAtRejected()
    {
        var (pub, priv) = GenerateKey();
        var payload = System.Text.Encoding.UTF8.GetBytes("{}");
        var past = (ulong)DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        var env = BuildEnvelope(pub, priv, DeviceUrn, Kind, past, payload);

        var verifier = new EnvelopeVerifier(pub, DeviceUrn, TimeSpan.FromSeconds(30));
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, Kind));
    }

    [Fact]
    public void SigningBytesLayoutPinned()
    {
        var bytes = EnvelopeVerifier.BuildSigningBytes(
            "d", "k", 0x0102030405060708UL, new byte[] { (byte)'p' });
        Assert.Equal(45, bytes.Length);
        var tag = System.Text.Encoding.ASCII.GetBytes("dds-policy-envelope-v1");
        Assert.True(bytes.AsSpan(0, tag.Length).SequenceEqual(tag));
        Assert.Equal(new byte[] { 1, 0, 0, 0 }, bytes[tag.Length..(tag.Length + 4)]);
        Assert.Equal((byte)'d', bytes[tag.Length + 4]);
    }

    /// <summary>
    /// <b>Cross-language interop fixture</b> (H-3). Matches the
    /// Windows test and Rust's
    /// <c>envelope::tests::interop_vector_is_stable</c>.
    /// </summary>
    [Fact]
    public void InteropVectorAcceptsRustSignature()
    {
        var pubkey = HexDecode(
            "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664");
        var signature = HexDecode(
            "ec6c05fcf6ab6744ff8cba07ac93f6ac6fb69d1d214fdcc3b6f709a2fc63deaf37956c367c60185fc9e5dd91ff1c01bf4a4edfa7e5d7d25e595c861a98015c05");
        const string deviceUrn = "urn:vouchsafe:dev.abc";
        const string kind = "windows-policies"; // envelope kind pinned by Rust vector
        const ulong issuedAt = 1_700_000_000UL;
        var payload = System.Text.Encoding.UTF8.GetBytes("{\"policies\":[]}");

        var msg = EnvelopeVerifier.BuildSigningBytes(deviceUrn, kind, issuedAt, payload);
        var verifier = new Ed25519Signer();
        verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(pubkey, 0));
        verifier.BlockUpdate(msg, 0, msg.Length);
        Assert.True(verifier.VerifySignature(signature),
            "Rust-emitted signature must verify under the C# Ed25519 verifier");
    }

    private static byte[] HexDecode(string hex)
    {
        var buf = new byte[hex.Length / 2];
        for (int i = 0; i < buf.Length; i++)
            buf[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        return buf;
    }
}
