// DDS Kotlin unit tests — JUnit 5 + JNA.
//
// Prerequisites:
//   cargo build -p dds-ffi --release
//   Set -Djava.library.path=<workspace>/target/release

package vouchsafe.dds

import org.json.JSONObject
import org.junit.jupiter.api.*
import org.junit.jupiter.api.Assertions.*

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DDSTest {
    private lateinit var client: DDS

    @BeforeAll
    fun setup() {
        client = DDS()
    }

    // ---- Version ----
    @Test
    fun `version returns semver`() {
        val v = client.version()
        assertTrue(v.contains("."), "Version should be semver: $v")
    }

    // ---- Identity ----
    @Test
    fun `identity create classical`() {
        val result = client.identityCreate("kotlin-alice")
        assertTrue(result.getString("urn").startsWith("urn:vouchsafe:kotlin-alice."))
        assertEquals("Ed25519", result.getString("scheme"))
        assertEquals(32, result.getInt("pubkey_len"))
    }

    @Test
    fun `identity create hybrid`() {
        val result = client.identityCreateHybrid("kotlin-quantum")
        assertTrue(result.getString("urn").startsWith("urn:vouchsafe:kotlin-quantum."))
        assertEquals("Ed25519+ML-DSA-65", result.getString("scheme"))
        assertEquals(1984, result.getInt("pubkey_len"))
    }

    @Test
    fun `identity parse URN valid`() {
        val result = client.identityParseUrn("urn:vouchsafe:alice.abc123")
        assertEquals("alice", result.getString("label"))
        assertEquals("abc123", result.getString("hash"))
    }

    @Test
    fun `identity parse URN invalid throws`() {
        assertThrows(DDSException::class.java) {
            client.identityParseUrn("not-a-urn")
        }
    }

    @Test
    fun `identity create then parse roundtrip`() {
        val created = client.identityCreate("kotlin-rt")
        val urn = created.getString("urn")
        val parsed = client.identityParseUrn(urn)
        assertEquals("kotlin-rt", parsed.getString("label"))
    }

    // ---- Token ----
    @Test
    fun `token create and validate`() {
        val config = JSONObject().put("label", "kotlin-token")
        val created = client.tokenCreateAttest(config)
        assertTrue(created.getString("jti").startsWith("attest-"))

        val hex = created.getString("token_cbor_hex")
        val validated = client.tokenValidate(hex)
        assertTrue(validated.getBoolean("valid"))
        assertEquals("Attest", validated.getString("kind"))
    }

    @Test
    fun `token validate invalid hex throws`() {
        assertThrows(DDSException::class.java) {
            client.tokenValidate("not-hex!!")
        }
    }

    // ---- Policy ----
    @Test
    fun `policy deny no trust`() {
        val config = JSONObject()
            .put("subject_urn", "urn:vouchsafe:nobody.hash")
            .put("resource", "repo:main")
            .put("action", "read")
            .put("trusted_roots", listOf<String>())
            .put("rules", listOf(
                JSONObject()
                    .put("effect", "Allow")
                    .put("required_purpose", "group:dev")
                    .put("resource", "repo:main")
                    .put("actions", listOf("read"))
            ))
            .put("tokens_cbor_hex", listOf<String>())

        val result = client.policyEvaluate(config)
        assertEquals("DENY", result.getString("decision"))
    }
}
