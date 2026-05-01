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
}
