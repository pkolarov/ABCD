// ctap2_pin_protocol.h
// CTAP2 PIN/UV Auth Protocol 1 — ECDH P-256 key agreement + hmac-secret
// salt encryption/decryption.
//
// Used during:
//   - Enrollment:     MakeCredential with hmac-secret extension enabled,
//                     then GetAssertion to derive the initial HMAC output
//                     (the 32-byte key used to AES-GCM encrypt the password).
//   - Authentication: GetAssertion with encrypted salt → HMAC output →
//                     AES-GCM decrypt stored password.
//
// PIN Protocol 1 shared-secret derivation (CTAP2 spec §6.5.4):
//   sharedSecret = SHA-256( ECDH(d_platform, Q_authenticator).x )
//
// Salt encryption:
//   saltEnc  = AES-256-CBC( key=sharedSecret, iv=zeros(16), plaintext=salt )
//   saltAuth = LEFT( HMAC-SHA-256( sharedSecret, saltEnc ), 16 )
//
// Output decryption (authenticator response):
//   hmacOutput = AES-256-CBC-decrypt( key=sharedSecret, iv=zeros(16),
//                                     ciphertext=outputEnc )
//

#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

// ============================================================================
// COSE EC2 key (P-256) — used for key agreement in hmac-secret extension
// ============================================================================

struct CoseEcKey
{
    uint8_t x[32]{};   // x-coordinate (32 bytes)
    uint8_t y[32]{};   // y-coordinate (32 bytes)
    bool    valid{ false };
};

// ============================================================================
// CCtapPinProtocol
//
// Usage:
//   1. Call GeneratePlatformKey() once per CTAP2 session.
//   2. Call SetAuthenticatorKey() with the COSE key from getKeyAgreement.
//   3. Call DeriveSharedSecret() — must succeed before Encrypt/Decrypt.
//   4. Call EncryptSalt() to produce saltEnc + saltAuth for GetAssertion.
//   5. Call DecryptOutput() to recover the 32-byte hmac-secret result.
//   6. Call Reset() between sessions if reusing the object.
// ============================================================================

class CCtapPinProtocol
{
public:
    CCtapPinProtocol();
    ~CCtapPinProtocol();

    // ----- Key generation -----

    // Generate a fresh P-256 ephemeral key pair.
    // Must be called before DeriveSharedSecret().
    bool GeneratePlatformKey();

    // Return the platform's public key (x,y) for sending to the authenticator.
    // Returns false if GeneratePlatformKey() was not called.
    bool GetPlatformPublicKey(CoseEcKey& outKey) const;

    // Encode the platform public key as a CTAP2 COSE map (CBOR byte vector).
    // Format: {1:2, 3:-25, -1:1, -2:x_bytes, -3:y_bytes}
    bool GetPlatformPublicKeyCbor(std::vector<uint8_t>& outCbor) const;

    // ----- Authenticator key -----

    // Store the authenticator's public key (from getKeyAgreement response).
    void SetAuthenticatorKey(const CoseEcKey& authKey);

    // Parse the COSE key from raw CBOR bytes (getKeyAgreement response payload).
    // Fills the internal authenticator key and returns true on success.
    bool ParseAuthenticatorKeyCbor(const uint8_t* cbor, size_t cborLen);

    // ----- Shared secret -----

    // Compute sharedSecret = SHA-256( ECDH(d_platform, Q_auth).x ).
    // Requires both keys to be set.
    bool DeriveSharedSecret();

    // ----- Salt operations -----

    // Encrypt a 32-byte salt for the hmac-secret GetAssertion extension.
    //   saltEnc  = AES-256-CBC(sharedSecret, zeros_iv, salt)
    //   saltAuth = LEFT(HMAC-SHA-256(sharedSecret, saltEnc), 16)
    bool EncryptSalt(
        const uint8_t salt[32],
        std::vector<uint8_t>& outSaltEnc,
        std::vector<uint8_t>& outSaltAuth
    ) const;

    // Decrypt the 32-byte hmac-secret output returned by the authenticator.
    //   plaintext = AES-256-CBC-decrypt(sharedSecret, zeros_iv, ciphertext)
    bool DecryptOutput(
        const std::vector<uint8_t>& encOutput,
        std::vector<uint8_t>& outPlaintext
    ) const;

    // ----- Lifetime -----

    // Clear all key material and reset to initial state.
    void Reset();

    bool IsReady() const { return m_sharedSecretReady; }

private:
    BCRYPT_ALG_HANDLE  m_hEcdhAlg{ nullptr };
    BCRYPT_ALG_HANDLE  m_hAesAlg{ nullptr };
    BCRYPT_KEY_HANDLE  m_hPlatformKey{ nullptr };   // ephemeral P-256 key pair

    CoseEcKey          m_platformPub{};
    CoseEcKey          m_authPub{};
    uint8_t            m_sharedSecret[32]{};
    bool               m_sharedSecretReady{ false };

    // Helpers
    bool AesCbcEncrypt(const uint8_t* plaintext, size_t len,
                        std::vector<uint8_t>& out) const;
    bool AesCbcDecrypt(const uint8_t* ciphertext, size_t len,
                        std::vector<uint8_t>& out) const;
    bool HmacSha256(const uint8_t* data, size_t dataLen,
                     uint8_t outMac[32]) const;
    void CloseHandles();
};
