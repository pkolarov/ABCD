// ctap2_protocol.h
// FIDO2 CTAP2 protocol implementation for authenticatorGetAssertion
// with hmac-secret extension support.
//
// Reference: FIDO Client to Authenticator Protocol v2.1
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html
//

#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>
#include <string>
#include "cbor.h"

// ============================================================================
// CTAP2 Command Codes
// ============================================================================

namespace CTAP2_CMD
{
    constexpr uint8_t MAKE_CREDENTIAL   = 0x01;
    constexpr uint8_t GET_ASSERTION     = 0x02;
    constexpr uint8_t GET_INFO          = 0x04;
    constexpr uint8_t CLIENT_PIN        = 0x06;
    constexpr uint8_t RESET             = 0x07;
    constexpr uint8_t GET_NEXT_ASSERTION = 0x08;
}

// ============================================================================
// CTAP2 Status Codes
// ============================================================================

namespace CTAP2_ERR
{
    constexpr uint8_t SUCCESS                   = 0x00;
    constexpr uint8_t INVALID_COMMAND           = 0x01;
    constexpr uint8_t INVALID_PARAMETER         = 0x02;
    constexpr uint8_t INVALID_LENGTH            = 0x03;
    constexpr uint8_t INVALID_SEQ               = 0x04;
    constexpr uint8_t TIMEOUT                   = 0x05;
    constexpr uint8_t CHANNEL_BUSY              = 0x06;
    constexpr uint8_t LOCK_REQUIRED             = 0x0A;
    constexpr uint8_t INVALID_CHANNEL           = 0x0B;
    constexpr uint8_t CBOR_UNEXPECTED_TYPE      = 0x11;
    constexpr uint8_t INVALID_CBOR              = 0x12;
    constexpr uint8_t MISSING_PARAMETER         = 0x14;
    constexpr uint8_t LIMIT_EXCEEDED            = 0x15;
    constexpr uint8_t UNSUPPORTED_EXTENSION     = 0x16;
    constexpr uint8_t CREDENTIAL_EXCLUDED       = 0x19;
    constexpr uint8_t PROCESSING                = 0x21;  // Not an error — used in keepalive
    constexpr uint8_t INVALID_CREDENTIAL        = 0x22;
    constexpr uint8_t USER_ACTION_PENDING       = 0x23;
    constexpr uint8_t OPERATION_PENDING         = 0x24;
    constexpr uint8_t NO_OPERATIONS             = 0x25;
    constexpr uint8_t UNSUPPORTED_ALGORITHM     = 0x26;
    constexpr uint8_t OPERATION_DENIED          = 0x27;
    constexpr uint8_t KEY_STORE_FULL            = 0x28;
    constexpr uint8_t NO_OPERATION_PENDING      = 0x2A;
    constexpr uint8_t UNSUPPORTED_OPTION        = 0x2B;
    constexpr uint8_t INVALID_OPTION            = 0x2C;
    constexpr uint8_t KEEPALIVE_CANCEL          = 0x2D;
    constexpr uint8_t NO_CREDENTIALS            = 0x2E;
    constexpr uint8_t USER_ACTION_TIMEOUT       = 0x2F;
    constexpr uint8_t NOT_ALLOWED               = 0x30;
    constexpr uint8_t PIN_INVALID               = 0x31;
    constexpr uint8_t PIN_BLOCKED               = 0x32;
    constexpr uint8_t PIN_AUTH_INVALID           = 0x33;
    constexpr uint8_t PIN_AUTH_BLOCKED           = 0x34;
    constexpr uint8_t PIN_NOT_SET               = 0x35;
    constexpr uint8_t PIN_REQUIRED              = 0x36;
    constexpr uint8_t PIN_POLICY_VIOLATION      = 0x37;
    constexpr uint8_t PIN_TOKEN_EXPIRED         = 0x38;
    constexpr uint8_t UV_BLOCKED                = 0x3C;
    constexpr uint8_t OTHER                     = 0x7F;
}

// ============================================================================
// GetAssertion Request Parameters
// ============================================================================

struct Ctap2GetAssertionRequest
{
    // Required
    std::string rpId;                           // 0x01: Relying party identifier
    std::vector<uint8_t> clientDataHash;        // 0x02: SHA-256 of clientData (32 bytes)

    // Optional
    struct AllowListEntry
    {
        std::string type;                       // "public-key"
        std::vector<uint8_t> id;                // Credential ID
    };
    std::vector<AllowListEntry> allowList;      // 0x03: List of allowed credentials

    // Extensions (0x04)
    bool useHmacSecret;                         // hmac-secret extension
    std::vector<uint8_t> hmacSecretSalt;        // Salt for hmac-secret (32 or 64 bytes)
    // Note: In a full implementation, hmac-secret requires key agreement
    // (platform key + authenticator key via ECDH). For now, this holds the
    // encrypted salt structure that gets sent to the authenticator.
    std::vector<uint8_t> hmacSecretKeyAgreement; // Platform public key for ECDH
    std::vector<uint8_t> hmacSecretSaltEnc;      // Encrypted salt
    std::vector<uint8_t> hmacSecretSaltAuth;     // HMAC of encrypted salt

    // Options (0x05)
    bool optionUP;                              // User Presence (default true)
    bool optionUV;                              // User Verification
    bool hasOptionUP;
    bool hasOptionUV;

    // PIN/UV (0x06, 0x07)
    std::vector<uint8_t> pinUvAuthParam;        // 0x06: PIN/UV auth parameter
    uint32_t pinUvAuthProtocol;                 // 0x07: PIN/UV protocol version

    Ctap2GetAssertionRequest()
        : useHmacSecret(false)
        , optionUP(true), optionUV(false)
        , hasOptionUP(false), hasOptionUV(false)
        , pinUvAuthProtocol(0)
    {}
};

// ============================================================================
// GetAssertion Response
// ============================================================================

struct Ctap2GetAssertionResponse
{
    // 0x01: Credential (PublicKeyCredentialDescriptor)
    struct Credential
    {
        std::string type;                       // "public-key"
        std::vector<uint8_t> id;                // Credential ID
    };
    Credential credential;

    // 0x02: Authenticator data
    std::vector<uint8_t> authData;

    // 0x03: Signature
    std::vector<uint8_t> signature;

    // 0x04: User (PublicKeyCredentialUserEntity)
    struct User
    {
        std::vector<uint8_t> id;
        std::string name;
        std::string displayName;
    };
    User user;

    // 0x05: numberOfCredentials
    uint32_t numberOfCredentials;

    // Extensions — hmac-secret output
    std::vector<uint8_t> hmacSecretOutput;      // Encrypted hmac-secret result

    // Parsed authenticator data fields
    std::vector<uint8_t> rpIdHash;              // First 32 bytes of authData
    uint8_t flags;                              // Byte 32 of authData
    uint32_t signCount;                         // Bytes 33-36 of authData

    // Flags
    bool flagUP() const { return (flags & 0x01) != 0; }
    bool flagUV() const { return (flags & 0x04) != 0; }
    bool flagAT() const { return (flags & 0x40) != 0; }
    bool flagED() const { return (flags & 0x80) != 0; }

    Ctap2GetAssertionResponse() : numberOfCredentials(0), flags(0), signCount(0) {}
};

// ============================================================================
// MakeCredential Request Parameters (for enrollment)
// ============================================================================

struct Ctap2MakeCredentialRequest
{
    std::vector<uint8_t> clientDataHash;        // 0x01

    // RP (0x02)
    std::string rpId;
    std::string rpName;

    // User (0x03)
    std::vector<uint8_t> userId;
    std::string userName;
    std::string userDisplayName;

    // PubKeyCredParams (0x04)
    struct PubKeyCredParam
    {
        std::string type;           // "public-key"
        int32_t alg;                // COSE algorithm ID (-7 = ES256, -257 = RS256)
    };
    std::vector<PubKeyCredParam> pubKeyCredParams;

    // Extensions (0x06)
    bool useHmacSecret;
    uint8_t credProtect;                        // 1, 2, or 3

    // Options (0x07)
    bool residentKey;                           // rk: true for discoverable credential
    bool userVerification;                      // uv: true

    Ctap2MakeCredentialRequest()
        : useHmacSecret(false), credProtect(0)
        , residentKey(false), userVerification(false)
    {}
};

// ============================================================================
// ClientPIN subcommands (authenticatorClientPIN, cmd 0x06)
// ============================================================================

namespace CTAP2_CLIENT_PIN_CMD
{
    constexpr uint8_t GET_PIN_RETRIES           = 0x01;
    constexpr uint8_t GET_KEY_AGREEMENT         = 0x02;
    constexpr uint8_t SET_PIN                   = 0x03;
    constexpr uint8_t CHANGE_PIN                = 0x04;
    constexpr uint8_t GET_PIN_TOKEN             = 0x05;
    constexpr uint8_t GET_UV_TOKEN_PERMISSIONS  = 0x06;
}

// ============================================================================
// CTAP2 Protocol Functions
// ============================================================================

class CCtap2Protocol
{
public:
    // Build the CBOR-encoded command bytes for authenticatorGetAssertion.
    // The output includes the command byte prefix (0x02).
    static bool BuildGetAssertionCommand(
        const Ctap2GetAssertionRequest& request,
        std::vector<uint8_t>& outCommandBytes
    );

    // Parse a CTAP2 response (status byte + CBOR payload) into a GetAssertionResponse.
    // Returns the CTAP2 status code (0x00 = success).
    static uint8_t ParseGetAssertionResponse(
        const uint8_t* responseData,
        size_t responseLen,
        Ctap2GetAssertionResponse& outResponse
    );

    // Build the CBOR-encoded command bytes for authenticatorMakeCredential.
    // The output includes the command byte prefix (0x01).
    static bool BuildMakeCredentialCommand(
        const Ctap2MakeCredentialRequest& request,
        std::vector<uint8_t>& outCommandBytes
    );

    // Build authenticatorGetInfo command (0x04, no parameters).
    static bool BuildGetInfoCommand(std::vector<uint8_t>& outCommandBytes);

    // Build authenticatorClientPIN(getKeyAgreement) command.
    // pinUvAuthProtocol: 1 or 2 (we use 1).
    // Response is a CBOR map with key 0x01 = COSE EC key.
    static bool BuildClientPINGetKeyAgreementCommand(
        std::vector<uint8_t>& outCommandBytes,
        uint8_t pinUvAuthProtocol = 1);

    // Parse a ClientPIN response — extract the authenticator's COSE key.
    // Returns the x and y coordinates (each 32 bytes) on success.
    // outX and outY must be 32-byte buffers.
    static bool ParseClientPINKeyAgreementResponse(
        const uint8_t* responseData,
        size_t responseLen,
        uint8_t outX[32],
        uint8_t outY[32]);

    // Parse authenticator data from a GetAssertion response.
    static bool ParseAuthData(
        const std::vector<uint8_t>& authData,
        Ctap2GetAssertionResponse& outResponse
    );

    // Generate a random clientDataHash (32-byte challenge).
    static bool GenerateChallenge(std::vector<uint8_t>& outChallenge);

    // Get a human-readable error string for a CTAP2 status code.
    static const char* StatusToString(uint8_t status);
};
