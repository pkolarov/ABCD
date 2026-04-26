/**
 * DDS — Decentralized Directory Service
 * C API Header
 *
 * All functions use JSON strings for complex data exchange.
 * Caller must free returned strings with dds_free_string().
 * Return values: 0 = success, negative = error code.
 */

#ifndef DDS_H
#define DDS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define DDS_OK              0
#define DDS_ERR_INVALID_INPUT -1
#define DDS_ERR_CRYPTO      -2
#define DDS_ERR_TOKEN       -3
#define DDS_ERR_TRUST       -4
#define DDS_ERR_POLICY_DENIED -5
#define DDS_ERR_INTERNAL    -99

/* ---- Identity ---- */

/**
 * Generate a classical (Ed25519) identity.
 * Output JSON: { "urn", "scheme", "pubkey_len" }
 *
 * The secret signing key is not returned across the FFI (closes I-9):
 * the freshly generated identity is dropped after the URN/pubkey
 * metadata is serialised, so caller languages cannot retain plaintext
 * key material in GC'd strings. To sign a token, use the higher-level
 * dds_token_create_attest entry point, which keeps the signing key
 * confined to the FFI.
 */
int32_t dds_identity_create(const char* label, char** out);

/**
 * Generate a hybrid (Ed25519+ML-DSA-65) identity.
 * Output JSON: { "urn", "scheme", "pubkey_len" }
 * Only available when built with PQ feature.
 */
int32_t dds_identity_create_hybrid(const char* label, char** out);

/**
 * Parse and validate a Vouchsafe URN.
 * Output JSON: { "label", "hash", "urn" }
 */
int32_t dds_identity_parse_urn(const char* urn, char** out);

/* ---- Token ---- */

/**
 * Create and sign an attestation token.
 * Input JSON: { "label": "name", "purpose"?: "..." }
 * Output JSON: { "jti", "urn", "token_cbor_hex", "payload_hash" }
 */
int32_t dds_token_create_attest(const char* config_json, char** out);

/**
 * Validate a token from hex-encoded CBOR bytes.
 * Output JSON: { "valid": bool, "jti", "iss", "kind", "error"? }
 */
int32_t dds_token_validate(const char* token_hex, char** out);

/* ---- Policy ---- */

/**
 * Evaluate a policy decision.
 * Input JSON: {
 *   "subject_urn": "...",
 *   "resource": "...",
 *   "action": "...",
 *   "trusted_roots": ["..."],
 *   "rules": [{ "effect", "required_purpose", "resource", "actions" }],
 *   "tokens_cbor_hex": ["..."]
 * }
 * Output JSON: { "decision": "ALLOW"|"DENY", "reason": "..." }
 */
int32_t dds_policy_evaluate(const char* config_json, char** out);

/* ---- Utility ---- */

/** Free a string returned by any DDS function. */
void dds_free_string(char* s);

/** Get the library version string. */
int32_t dds_version(char** out);

#ifdef __cplusplus
}
#endif

#endif /* DDS_H */
