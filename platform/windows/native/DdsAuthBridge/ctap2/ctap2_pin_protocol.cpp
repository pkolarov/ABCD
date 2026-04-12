// ctap2_pin_protocol.cpp
// CTAP2 PIN/UV Auth Protocol 1 — ECDH P-256 + hmac-secret
//

#include "ctap2_pin_protocol.h"
#include "cbor.h"
#include <cstring>
#include <cstdio>

// BCrypt ECDH P-256 public-key blob magic (from bcrypt.h)
#ifndef BCRYPT_ECDH_PUBLIC_P256_MAGIC
#define BCRYPT_ECDH_PUBLIC_P256_MAGIC 0x314B4345
#endif

// ============================================================================
// CCtapPinProtocol
// ============================================================================

CCtapPinProtocol::CCtapPinProtocol()
{
    BCryptOpenAlgorithmProvider(&m_hEcdhAlg, BCRYPT_ECDH_P256_ALGORITHM, nullptr, 0);
    BCryptOpenAlgorithmProvider(&m_hAesAlg,  BCRYPT_AES_ALGORITHM,       nullptr, 0);
    if (m_hAesAlg)
        BCryptSetProperty(m_hAesAlg, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
            (ULONG)((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(wchar_t)), 0);
}

CCtapPinProtocol::~CCtapPinProtocol()
{
    Reset();
    CloseHandles();
}

void CCtapPinProtocol::CloseHandles()
{
    if (m_hPlatformKey) { BCryptDestroyKey(m_hPlatformKey); m_hPlatformKey = nullptr; }
    if (m_hAesAlg)      { BCryptCloseAlgorithmProvider(m_hAesAlg, 0); m_hAesAlg = nullptr; }
    if (m_hEcdhAlg)     { BCryptCloseAlgorithmProvider(m_hEcdhAlg, 0); m_hEcdhAlg = nullptr; }
}

void CCtapPinProtocol::Reset()
{
    if (m_hPlatformKey) { BCryptDestroyKey(m_hPlatformKey); m_hPlatformKey = nullptr; }
    SecureZeroMemory(m_sharedSecret, sizeof(m_sharedSecret));
    m_sharedSecretReady = false;
    m_platformPub = {};
    m_authPub     = {};
}

// ============================================================================
// Platform key generation
// ============================================================================

bool CCtapPinProtocol::GeneratePlatformKey()
{
    if (!m_hEcdhAlg) return false;

    if (m_hPlatformKey) { BCryptDestroyKey(m_hPlatformKey); m_hPlatformKey = nullptr; }

    NTSTATUS st = BCryptGenerateKeyPair(m_hEcdhAlg, &m_hPlatformKey, 256, 0);
    if (!BCRYPT_SUCCESS(st)) return false;

    st = BCryptFinalizeKeyPair(m_hPlatformKey, 0);
    if (!BCRYPT_SUCCESS(st)) { BCryptDestroyKey(m_hPlatformKey); m_hPlatformKey = nullptr; return false; }

    // Export public coordinates
    ULONG exported = 0;
    st = BCryptExportKey(m_hPlatformKey, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &exported, 0);
    if (!BCRYPT_SUCCESS(st)) return false;

    std::vector<uint8_t> blob(exported);
    st = BCryptExportKey(m_hPlatformKey, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                         blob.data(), exported, &exported, 0);
    if (!BCRYPT_SUCCESS(st)) return false;

    // BCRYPT_ECCKEY_BLOB = { ULONG Magic; ULONG cbKey; } followed by x[cbKey] + y[cbKey]
    if (exported < 8 + 64) return false;
    ULONG cbKey = *reinterpret_cast<ULONG*>(blob.data() + 4);
    if (cbKey != 32) return false;

    memcpy(m_platformPub.x, blob.data() + 8,      32);
    memcpy(m_platformPub.y, blob.data() + 8 + 32, 32);
    m_platformPub.valid = true;
    return true;
}

bool CCtapPinProtocol::GetPlatformPublicKey(CoseEcKey& outKey) const
{
    if (!m_platformPub.valid) return false;
    outKey = m_platformPub;
    return true;
}

// ============================================================================
// Platform public key → CBOR COSE map
//   {1:2, 3:-25, -1:1, -2:<x>, -3:<y>}
// ============================================================================

bool CCtapPinProtocol::GetPlatformPublicKeyCbor(std::vector<uint8_t>& outCbor) const
{
    if (!m_platformPub.valid) return false;

    CborMap m;
    m.push_back({ CborValue::Uint(1),    CborValue::Uint(2)    });  // kty = EC2
    m.push_back({ CborValue::NegInt(-7), CborValue::NegInt(-25)});  // alg = ECDH-ES+HKDF-256
    m.push_back({ CborValue::NegInt(-1), CborValue::Uint(1)    });  // crv = P-256
    m.push_back({ CborValue::NegInt(-2), CborValue::Bytes(m_platformPub.x, 32) });
    m.push_back({ CborValue::NegInt(-3), CborValue::Bytes(m_platformPub.y, 32) });

    CborEncoder enc;
    if (!enc.Encode(CborValue::Map(m))) return false;
    outCbor.assign(enc.GetData(), enc.GetData() + enc.GetSize());
    return true;
}

// ============================================================================
// Authenticator key
// ============================================================================

void CCtapPinProtocol::SetAuthenticatorKey(const CoseEcKey& authKey)
{
    m_authPub = authKey;
    m_sharedSecretReady = false;
}

// Parse authenticator COSE key from CBOR
// Expected map keys: 1=kty, 3=alg, -1=crv, -2=x, -3=y
bool CCtapPinProtocol::ParseAuthenticatorKeyCbor(const uint8_t* cbor, size_t cborLen)
{
    if (!cbor || cborLen < 2) return false;

    CborDecoder dec;
    CborValue root;
    if (!dec.Decode(cbor, cborLen, root)) return false;
    if (root.type != CborType::Map) return false;

    CoseEcKey key;
    // Keys can be uint (+) or negint (-)
    auto findBytes = [&](int64_t intKey, uint8_t out[32]) -> bool {
        for (auto& kv : root.mapVal)
        {
            int64_t k = 0;
            if (kv.first.type == CborType::UnsignedInt) k = (int64_t)kv.first.uintVal;
            else if (kv.first.type == CborType::NegativeInt) k = kv.first.intVal;
            else continue;
            if (k != intKey) continue;
            if (kv.second.type != CborType::ByteString) return false;
            if (kv.second.bytesVal.size() != 32) return false;
            memcpy(out, kv.second.bytesVal.data(), 32);
            return true;
        }
        return false;
    };

    if (!findBytes(-2, key.x)) return false;
    if (!findBytes(-3, key.y)) return false;
    key.valid = true;
    SetAuthenticatorKey(key);
    return true;
}

// ============================================================================
// ECDH shared secret derivation
// ============================================================================

bool CCtapPinProtocol::DeriveSharedSecret()
{
    if (!m_hPlatformKey || !m_authPub.valid || !m_hEcdhAlg) return false;

    // Build BCRYPT_ECCPUBLIC_BLOB for authenticator key
    // Layout: { ULONG Magic=0x314B4345; ULONG cbKey=32; } + x[32] + y[32]
    uint8_t authBlob[8 + 64]{};
    *reinterpret_cast<ULONG*>(authBlob)     = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    *reinterpret_cast<ULONG*>(authBlob + 4) = 32;
    memcpy(authBlob + 8,      m_authPub.x, 32);
    memcpy(authBlob + 8 + 32, m_authPub.y, 32);

    BCRYPT_KEY_HANDLE hAuthKey = nullptr;
    NTSTATUS st = BCryptImportKeyPair(m_hEcdhAlg, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                                       &hAuthKey, authBlob, sizeof(authBlob), 0);
    if (!BCRYPT_SUCCESS(st)) return false;

    BCRYPT_SECRET_HANDLE hSecret = nullptr;
    st = BCryptSecretAgreement(m_hPlatformKey, hAuthKey, &hSecret, 0);
    BCryptDestroyKey(hAuthKey);
    if (!BCRYPT_SUCCESS(st)) return false;

    // Derive key: KDF = HASH (SHA-256 of the raw x-coordinate)
    // Per CTAP2 PIN protocol 1: sharedSecret = SHA-256(z) where z = x-coord of ECDH point
    BCryptBuffer kdfBuf = {};
    kdfBuf.cbBuffer = (ULONG)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(wchar_t));
    kdfBuf.BufferType = KDF_HASH_ALGORITHM;
    kdfBuf.pvBuffer = (PVOID)BCRYPT_SHA256_ALGORITHM;

    BCryptBufferDesc kdfDesc = {};
    kdfDesc.ulVersion = BCRYPTBUFFER_VERSION;
    kdfDesc.cBuffers  = 1;
    kdfDesc.pBuffers  = &kdfBuf;

    ULONG derivedLen = 0;
    st = BCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, &kdfDesc,
                          m_sharedSecret, 32, &derivedLen, 0);
    BCryptDestroySecret(hSecret);

    if (!BCRYPT_SUCCESS(st) || derivedLen != 32) return false;
    m_sharedSecretReady = true;
    return true;
}

// ============================================================================
// AES-256-CBC encrypt/decrypt (IV = all zeros, no padding — input must be
// a multiple of 16 bytes; 32-byte salt fits exactly in 2 blocks)
// ============================================================================

bool CCtapPinProtocol::AesCbcEncrypt(const uint8_t* plaintext, size_t len,
                                       std::vector<uint8_t>& out) const
{
    if (!m_hAesAlg || !m_sharedSecretReady) return false;
    if (len == 0 || (len % 16) != 0) return false;

    // Import raw key
    BCRYPT_KEY_HANDLE hKey = nullptr;
    struct { BCRYPT_KEY_DATA_BLOB_HEADER hdr; uint8_t key[32]; } keyBlob{};
    keyBlob.hdr.dwMagic   = BCRYPT_KEY_DATA_BLOB_MAGIC;
    keyBlob.hdr.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    keyBlob.hdr.cbKeyData = 32;
    memcpy(keyBlob.key, m_sharedSecret, 32);

    NTSTATUS st = BCryptImportKey(m_hAesAlg, nullptr, BCRYPT_KEY_DATA_BLOB,
                                   &hKey, nullptr, 0,
                                   (PUCHAR)&keyBlob, sizeof(keyBlob), 0);
    SecureZeroMemory(keyBlob.key, 32);
    if (!BCRYPT_SUCCESS(st)) return false;

    // IV = zeros
    uint8_t iv[16]{};
    ULONG outLen = 0;
    out.resize(len + 16); // AES-CBC can expand by at most one block

    st = BCryptEncrypt(hKey, (PUCHAR)plaintext, (ULONG)len,
                        nullptr, iv, 16,
                        out.data(), (ULONG)out.size(), &outLen, 0);
    BCryptDestroyKey(hKey);
    if (!BCRYPT_SUCCESS(st)) return false;
    out.resize(outLen);
    return true;
}

bool CCtapPinProtocol::AesCbcDecrypt(const uint8_t* ciphertext, size_t len,
                                       std::vector<uint8_t>& out) const
{
    if (!m_hAesAlg || !m_sharedSecretReady) return false;
    if (len == 0 || (len % 16) != 0) return false;

    BCRYPT_KEY_HANDLE hKey = nullptr;
    struct { BCRYPT_KEY_DATA_BLOB_HEADER hdr; uint8_t key[32]; } keyBlob{};
    keyBlob.hdr.dwMagic   = BCRYPT_KEY_DATA_BLOB_MAGIC;
    keyBlob.hdr.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    keyBlob.hdr.cbKeyData = 32;
    memcpy(keyBlob.key, m_sharedSecret, 32);

    NTSTATUS st = BCryptImportKey(m_hAesAlg, nullptr, BCRYPT_KEY_DATA_BLOB,
                                   &hKey, nullptr, 0,
                                   (PUCHAR)&keyBlob, sizeof(keyBlob), 0);
    SecureZeroMemory(keyBlob.key, 32);
    if (!BCRYPT_SUCCESS(st)) return false;

    uint8_t iv[16]{};
    ULONG outLen = 0;
    out.resize(len);

    st = BCryptDecrypt(hKey, (PUCHAR)ciphertext, (ULONG)len,
                        nullptr, iv, 16,
                        out.data(), (ULONG)out.size(), &outLen, 0);
    BCryptDestroyKey(hKey);
    if (!BCRYPT_SUCCESS(st)) return false;
    out.resize(outLen);
    return true;
}

// ============================================================================
// HMAC-SHA-256
// ============================================================================

bool CCtapPinProtocol::HmacSha256(const uint8_t* data, size_t dataLen,
                                    uint8_t outMac[32]) const
{
    if (!m_sharedSecretReady) return false;

    BCRYPT_ALG_HANDLE hHmacAlg = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hHmacAlg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                               BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(st)) return false;

    BCRYPT_HASH_HANDLE hHash = nullptr;
    st = BCryptCreateHash(hHmacAlg, &hHash, nullptr, 0,
                           (PUCHAR)m_sharedSecret, 32, 0);
    if (!BCRYPT_SUCCESS(st)) { BCryptCloseAlgorithmProvider(hHmacAlg, 0); return false; }

    st = BCryptHashData(hHash, (PUCHAR)data, (ULONG)dataLen, 0);
    if (BCRYPT_SUCCESS(st))
        st = BCryptFinishHash(hHash, outMac, 32, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hHmacAlg, 0);
    return BCRYPT_SUCCESS(st);
}

// ============================================================================
// EncryptSalt — produce saltEnc + saltAuth for GetAssertion hmac-secret
// ============================================================================

bool CCtapPinProtocol::EncryptSalt(
    const uint8_t salt[32],
    std::vector<uint8_t>& outSaltEnc,
    std::vector<uint8_t>& outSaltAuth) const
{
    if (!m_sharedSecretReady) return false;

    // saltEnc = AES-256-CBC(sharedSecret, iv=zeros, salt)
    if (!AesCbcEncrypt(salt, 32, outSaltEnc)) return false;
    if (outSaltEnc.size() != 32) return false;

    // saltAuth = LEFT(HMAC-SHA-256(sharedSecret, saltEnc), 16)
    uint8_t mac[32]{};
    if (!HmacSha256(outSaltEnc.data(), outSaltEnc.size(), mac)) return false;

    outSaltAuth.assign(mac, mac + 16);
    SecureZeroMemory(mac, sizeof(mac));
    return true;
}

// ============================================================================
// DecryptOutput — recover 32-byte hmac-secret from authenticator response
// ============================================================================

bool CCtapPinProtocol::DecryptOutput(
    const std::vector<uint8_t>& encOutput,
    std::vector<uint8_t>& outPlaintext) const
{
    if (!m_sharedSecretReady) return false;
    if (encOutput.size() != 32 && encOutput.size() != 64) return false; // 1 or 2 salts

    return AesCbcDecrypt(encOutput.data(), encOutput.size(), outPlaintext);
}
