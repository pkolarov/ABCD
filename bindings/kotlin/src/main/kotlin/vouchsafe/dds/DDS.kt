// DDS Kotlin bindings — JNA wrapper for libdds_ffi.
//
// Usage:
//   val client = DDS()
//   val ident = client.identityCreate("alice")
//   println(ident.getString("urn"))
//
// Requires JNA and org.json on classpath.
// Native library must be in java.library.path.

package vouchsafe.dds

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference
import org.json.JSONObject

/** Error codes from the DDS library. */
object DDSError {
    const val OK = 0
    const val INVALID_INPUT = -1
    const val CRYPTO = -2
    const val TOKEN = -3
    const val TRUST = -4
    const val POLICY_DENIED = -5
    const val INTERNAL = -99
}

class DDSException(val code: Int, message: String) : Exception("DDS error $code: $message")

/** JNA interface for the native library. */
internal interface DDSNative : Library {
    fun dds_identity_create(label: String, out: PointerByReference): Int
    fun dds_identity_create_hybrid(label: String, out: PointerByReference): Int
    fun dds_identity_parse_urn(urn: String, out: PointerByReference): Int
    fun dds_token_create_attest(configJson: String, out: PointerByReference): Int
    fun dds_token_validate(tokenHex: String, out: PointerByReference): Int
    fun dds_policy_evaluate(configJson: String, out: PointerByReference): Int
    fun dds_version(out: PointerByReference): Int
    fun dds_free_string(s: Pointer)
}

/** DDS client — wraps the native library. */
class DDS(libName: String = "dds_ffi") {
    private val lib: DDSNative = Native.load(libName, DDSNative::class.java)

    private fun callJson(block: (PointerByReference) -> Int): JSONObject {
        val out = PointerByReference()
        val rc = block(out)
        val ptr = out.value
        val json = if (ptr != null) ptr.getString(0) else "{}"
        if (ptr != null) lib.dds_free_string(ptr)
        if (rc != DDSError.OK) throw DDSException(rc, json)
        return JSONObject(json)
    }

    fun version(): String {
        val out = PointerByReference()
        val rc = lib.dds_version(out)
        if (rc != DDSError.OK) throw DDSException(rc, "version failed")
        val v = out.value.getString(0)
        lib.dds_free_string(out.value)
        return v
    }

    fun identityCreate(label: String): JSONObject =
        callJson { lib.dds_identity_create(label, it) }

    fun identityCreateHybrid(label: String): JSONObject =
        callJson { lib.dds_identity_create_hybrid(label, it) }

    fun identityParseUrn(urn: String): JSONObject =
        callJson { lib.dds_identity_parse_urn(urn, it) }

    fun tokenCreateAttest(config: JSONObject): JSONObject =
        callJson { lib.dds_token_create_attest(config.toString(), it) }

    fun tokenValidate(tokenCborHex: String): JSONObject =
        callJson { lib.dds_token_validate(tokenCborHex, it) }

    fun policyEvaluate(config: JSONObject): JSONObject =
        callJson { lib.dds_policy_evaluate(config.toString(), it) }
}
