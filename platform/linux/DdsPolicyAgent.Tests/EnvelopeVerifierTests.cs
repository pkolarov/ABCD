// SPDX-License-Identifier: MIT OR Apache-2.0

using DDS.PolicyAgent.Linux.Client;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace DDS.PolicyAgent.Linux.Tests;

public sealed class EnvelopeVerifierTests
{
    private static (byte[] pubKey, byte[] privKey) GenerateEd25519KeyPair()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        var pub = ((Ed25519PublicKeyParameters)kp.Public).GetEncoded();
        var priv = (Ed25519PrivateKeyParameters)kp.Private;
        var privBytes = new byte[32];
        priv.Encode(privBytes, 0);
        return (pub, privBytes);
    }

    private static byte[] SignEnvelope(byte[] privKeyBytes, string deviceUrn, string kind, ulong issuedAt, byte[] payload)
    {
        var priv = new Ed25519PrivateKeyParameters(privKeyBytes, 0);
        var msg = EnvelopeVerifier.BuildSigningBytes(deviceUrn, kind, issuedAt, payload);
        var signer = new Ed25519Signer();
        signer.Init(forSigning: true, priv);
        signer.BlockUpdate(msg, 0, msg.Length);
        return signer.GenerateSignature();
    }

    [Fact]
    public void AcceptsValidLinuxPolicyEnvelope()
    {
        var (pub, priv) = GenerateEd25519KeyPair();
        const string deviceUrn = "urn:dds:device:linux-test";
        var payload = "{}"u8.ToArray();
        var issuedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var sig = SignEnvelope(priv, deviceUrn, EnvelopeKind.LinuxPolicies, issuedAt, payload);

        var env = new SignedPolicyEnvelope
        {
            Version = 1,
            Kind = EnvelopeKind.LinuxPolicies,
            DeviceUrn = deviceUrn,
            IssuedAt = issuedAt,
            PayloadB64 = Convert.ToBase64String(payload),
            SignatureB64 = Convert.ToBase64String(sig),
            NodePubkeyB64 = Convert.ToBase64String(pub),
        };

        var verifier = new EnvelopeVerifier(pub, deviceUrn);
        var result = verifier.VerifyAndUnwrap(env, EnvelopeKind.LinuxPolicies);

        Assert.Equal(payload, result);
    }

    [Fact]
    public void VersionMismatchRejected()
    {
        var (pub, priv) = GenerateEd25519KeyPair();
        const string deviceUrn = "urn:dds:device:linux-test";
        var payload = "{}"u8.ToArray();
        var issuedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var sig = SignEnvelope(priv, deviceUrn, EnvelopeKind.LinuxPolicies, issuedAt, payload);

        var env = new SignedPolicyEnvelope
        {
            Version = 2,
            Kind = EnvelopeKind.LinuxPolicies,
            DeviceUrn = deviceUrn,
            IssuedAt = issuedAt,
            PayloadB64 = Convert.ToBase64String(payload),
            SignatureB64 = Convert.ToBase64String(sig),
            NodePubkeyB64 = Convert.ToBase64String(pub),
        };

        var verifier = new EnvelopeVerifier(pub, deviceUrn);
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, EnvelopeKind.LinuxPolicies));
    }

    [Fact]
    public void RejectsMalformedBase64Signature()
    {
        var (pub, _) = GenerateEd25519KeyPair();
        const string deviceUrn = "urn:dds:device:linux-test";
        var payload = "{}"u8.ToArray();
        var env = new SignedPolicyEnvelope
        {
            Version = 1,
            Kind = EnvelopeKind.LinuxPolicies,
            DeviceUrn = deviceUrn,
            IssuedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            PayloadB64 = Convert.ToBase64String(payload),
            SignatureB64 = "!!NOT_VALID_BASE64!!",
            NodePubkeyB64 = Convert.ToBase64String(pub),
        };

        var verifier = new EnvelopeVerifier(pub, deviceUrn);
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, EnvelopeKind.LinuxPolicies));
    }

    [Fact]
    public void RejectsWrongEnvelopeKindBeforeSignatureCheck()
    {
        var verifier = new EnvelopeVerifier(new byte[32], "urn:dds:device:linux-test");
        var env = new SignedPolicyEnvelope
        {
            Version = 1,
            Kind = EnvelopeKind.LinuxSoftware,
            DeviceUrn = "urn:dds:device:linux-test",
            IssuedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };

        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, EnvelopeKind.LinuxPolicies));
    }

    [Fact]
    public void RejectsWrongDeviceUrnBeforeSignatureCheck()
    {
        var verifier = new EnvelopeVerifier(new byte[32], "urn:dds:device:linux-test");
        var env = new SignedPolicyEnvelope
        {
            Version = 1,
            Kind = EnvelopeKind.LinuxPolicies,
            DeviceUrn = "urn:dds:device:other",
            IssuedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        };

        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, EnvelopeKind.LinuxPolicies));
    }

    [Fact]
    public void ServerClaimedPubkeyMismatchRejected()
    {
        var (pub, priv) = GenerateEd25519KeyPair();
        var (otherPub, _) = GenerateEd25519KeyPair();
        const string deviceUrn = "urn:dds:device:linux-test";
        var payload = "{}"u8.ToArray();
        var issuedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var sig = SignEnvelope(priv, deviceUrn, EnvelopeKind.LinuxPolicies, issuedAt, payload);

        var env = new SignedPolicyEnvelope
        {
            Version = 1,
            Kind = EnvelopeKind.LinuxPolicies,
            DeviceUrn = deviceUrn,
            IssuedAt = issuedAt,
            PayloadB64 = Convert.ToBase64String(payload),
            SignatureB64 = Convert.ToBase64String(sig),
            NodePubkeyB64 = Convert.ToBase64String(otherPub),
        };

        var verifier = new EnvelopeVerifier(pub, deviceUrn);
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, EnvelopeKind.LinuxPolicies));
    }

    [Fact]
    public void TamperedPayloadRejected()
    {
        var (pub, priv) = GenerateEd25519KeyPair();
        const string deviceUrn = "urn:dds:device:linux-test";
        var payload = "{}"u8.ToArray();
        var issuedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var sig = SignEnvelope(priv, deviceUrn, EnvelopeKind.LinuxPolicies, issuedAt, payload);

        var env = new SignedPolicyEnvelope
        {
            Version = 1,
            Kind = EnvelopeKind.LinuxPolicies,
            DeviceUrn = deviceUrn,
            IssuedAt = issuedAt,
            PayloadB64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("{\"evil\":1}")),
            SignatureB64 = Convert.ToBase64String(sig),
            NodePubkeyB64 = Convert.ToBase64String(pub),
        };

        var verifier = new EnvelopeVerifier(pub, deviceUrn);
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, EnvelopeKind.LinuxPolicies));
    }

    [Fact]
    public void StaleIssuedAtRejected()
    {
        var (pub, priv) = GenerateEd25519KeyPair();
        const string deviceUrn = "urn:dds:device:linux-test";
        var payload = "{}"u8.ToArray();
        var past = (ulong)DateTimeOffset.UtcNow.AddHours(-1).ToUnixTimeSeconds();
        var sig = SignEnvelope(priv, deviceUrn, EnvelopeKind.LinuxPolicies, past, payload);

        var env = new SignedPolicyEnvelope
        {
            Version = 1,
            Kind = EnvelopeKind.LinuxPolicies,
            DeviceUrn = deviceUrn,
            IssuedAt = past,
            PayloadB64 = Convert.ToBase64String(payload),
            SignatureB64 = Convert.ToBase64String(sig),
            NodePubkeyB64 = Convert.ToBase64String(pub),
        };

        var verifier = new EnvelopeVerifier(pub, deviceUrn, TimeSpan.FromSeconds(30));
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, EnvelopeKind.LinuxPolicies));
    }

    [Fact]
    public void SignatureWrongLengthRejected()
    {
        var (pub, priv) = GenerateEd25519KeyPair();
        const string deviceUrn = "urn:dds:device:linux-test";
        var payload = "{}"u8.ToArray();
        var issuedAt = (ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var sig = SignEnvelope(priv, deviceUrn, EnvelopeKind.LinuxPolicies, issuedAt, payload);

        var env = new SignedPolicyEnvelope
        {
            Version = 1,
            Kind = EnvelopeKind.LinuxPolicies,
            DeviceUrn = deviceUrn,
            IssuedAt = issuedAt,
            PayloadB64 = Convert.ToBase64String(payload),
            SignatureB64 = Convert.ToBase64String(new byte[32]),
            NodePubkeyB64 = Convert.ToBase64String(pub),
        };

        var verifier = new EnvelopeVerifier(pub, deviceUrn);
        Assert.Throws<EnvelopeVerificationException>(
            () => verifier.VerifyAndUnwrap(env, EnvelopeKind.LinuxPolicies));
    }

    [Fact]
    public void CtorRejectsBadPubkey()
    {
        Assert.Throws<ArgumentException>(
            () => new EnvelopeVerifier(new byte[31], "urn:dds:device:linux-test"));
        Assert.Throws<ArgumentException>(
            () => new EnvelopeVerifier(new byte[32], ""));
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
    /// Cross-language interop fixture. Matches the macOS/Windows tests and
    /// Rust's <c>envelope::tests::interop_vector_is_stable</c>.
    /// </summary>
    [Fact]
    public void InteropVectorAcceptsRustSignature()
    {
        var pubkey = HexDecode(
            "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664");
        var signature = HexDecode(
            "ec6c05fcf6ab6744ff8cba07ac93f6ac6fb69d1d214fdcc3b6f709a2fc63deaf" +
            "37956c367c60185fc9e5dd91ff1c01bf4a4edfa7e5d7d25e595c861a98015c05");
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
