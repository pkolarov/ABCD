// DDS C# unit tests — requires NUnit and libdds_ffi in search path.
//
// Build & run:
//   dotnet test
//
// Prerequisites:
//   cargo build -p dds-ffi --release
//   Copy libdds_ffi.dylib / libdds_ffi.so / dds_ffi.dll to test output dir

using System.Text.Json;
using NUnit.Framework;
using Vouchsafe.DDS;

namespace Vouchsafe.DDS.Tests
{
    [TestFixture]
    public class VersionTests
    {
        [Test]
        public void Version_ReturnsSemver()
        {
            var v = Client.Version();
            Assert.That(v, Does.Contain("."));
            var parts = v.Split(".");
            Assert.That(parts.Length, Is.GreaterThanOrEqualTo(2));
        }
    }

    [TestFixture]
    public class IdentityTests
    {
        [Test]
        public void Create_ReturnsValidUrn()
        {
            using var doc = Identity.Create("csharp-alice");
            var root = doc.RootElement;
            Assert.That(root.GetProperty("urn").GetString(), Does.StartWith("urn:vouchsafe:csharp-alice."));
            Assert.That(root.GetProperty("scheme").GetString(), Is.EqualTo("Ed25519"));
            Assert.That(root.GetProperty("pubkey_len").GetInt32(), Is.EqualTo(32));
        }

        [Test]
        public void CreateHybrid_Returns1984ByteKey()
        {
            using var doc = Identity.CreateHybrid("csharp-quantum");
            var root = doc.RootElement;
            Assert.That(root.GetProperty("scheme").GetString(), Is.EqualTo("Ed25519+ML-DSA-65"));
            Assert.That(root.GetProperty("pubkey_len").GetInt32(), Is.EqualTo(1984));
        }

        [Test]
        public void ParseUrn_Valid()
        {
            using var doc = Identity.ParseUrn("urn:vouchsafe:alice.abc123");
            var root = doc.RootElement;
            Assert.That(root.GetProperty("label").GetString(), Is.EqualTo("alice"));
            Assert.That(root.GetProperty("hash").GetString(), Is.EqualTo("abc123"));
        }

        [Test]
        public void ParseUrn_Invalid_Throws()
        {
            Assert.Throws<DDSException>(() => Identity.ParseUrn("not-a-urn"));
        }

        [Test]
        public void Create_ThenParse_Roundtrip()
        {
            using var created = Identity.Create("csharp-roundtrip");
            var urn = created.RootElement.GetProperty("urn").GetString()!;
            using var parsed = Identity.ParseUrn(urn);
            Assert.That(parsed.RootElement.GetProperty("label").GetString(), Is.EqualTo("csharp-roundtrip"));
        }
    }

    [TestFixture]
    public class TokenTests
    {
        [Test]
        public void CreateAttest_ThenValidate()
        {
            var config = JsonSerializer.Serialize(new { label = "csharp-token" });
            using var created = TokenOps.CreateAttest(config);
            var hex = created.RootElement.GetProperty("token_cbor_hex").GetString()!;
            Assert.That(hex.Length, Is.GreaterThan(0));

            using var validated = TokenOps.Validate(hex);
            Assert.That(validated.RootElement.GetProperty("valid").GetBoolean(), Is.True);
            Assert.That(validated.RootElement.GetProperty("kind").GetString(), Is.EqualTo("Attest"));
        }

        [Test]
        public void Validate_InvalidHex_Throws()
        {
            Assert.Throws<DDSException>(() => TokenOps.Validate("not-hex!!"));
        }
    }

    [TestFixture]
    public class PolicyTests
    {
        [Test]
        public void Evaluate_DenyNoTrust()
        {
            var config = JsonSerializer.Serialize(new
            {
                subject_urn = "urn:vouchsafe:nobody.hash",
                resource = "repo:main",
                action = "read",
                trusted_roots = new string[] { },
                rules = new[] {
                    new { effect = "Allow", required_purpose = "group:dev",
                          resource = "repo:main", actions = new[] { "read" } }
                },
                tokens_cbor_hex = new string[] { }
            });
            using var doc = Policy.Evaluate(config);
            Assert.That(doc.RootElement.GetProperty("decision").GetString(), Is.EqualTo("DENY"));
        }
    }
}
