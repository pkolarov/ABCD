// WebAuthnHelper.h
// Wrappers around the Windows WebAuthn API (webauthn.h) for FIDO2
// MakeCredential and GetAssertion operations with hmac-secret support.

#pragma once

#include <windows.h>
#include <webauthn.h>
#include <vector>
#include <string>
#include <cstdint>

#pragma comment(lib, "webauthn.lib")

// Result of WebAuthNAuthenticatorMakeCredential
struct MakeCredentialResult
{
    bool                    success;
    std::vector<uint8_t>    credentialId;
    std::vector<uint8_t>    attestationObject;
    std::vector<uint8_t>    clientDataHash;     // SHA-256(clientDataJSON)
    std::string             errorMessage;
};

// Result of WebAuthNAuthenticatorGetAssertion
struct GetAssertionResult
{
    bool                    success;
    std::vector<uint8_t>    authenticatorData;
    std::vector<uint8_t>    signature;
    std::vector<uint8_t>    clientDataHash;     // SHA-256(clientDataJSON)
    std::vector<uint8_t>    credentialId;
    std::vector<uint8_t>    hmacSecretOutput;   // 32 bytes (when hmac-secret requested)
    std::string             errorMessage;
};

class CWebAuthnHelper
{
public:
    // Register a new FIDO2 credential.
    //
    // hwnd:        Parent window for the WebAuthn UI prompt.
    // rpId:        Relying party identifier (e.g., "dds.local").
    // userId:      Opaque user ID bytes (e.g., UTF-16 SID).
    // displayName: Human-readable name shown in the prompt.
    // hmacSecret:  If true, request the hmac-secret extension.
    static MakeCredentialResult MakeCredential(
        HWND hwnd,
        const std::string& rpId,
        const std::vector<uint8_t>& userId,
        const std::wstring& displayName,
        bool hmacSecret
    );

    // Get an assertion with hmac-secret output for password decryption.
    //
    // credentialId: The credential to use (from MakeCredential).
    // salt:         32-byte salt for the hmac-secret extension.
    static GetAssertionResult GetAssertionHmacSecret(
        HWND hwnd,
        const std::string& rpId,
        const std::vector<uint8_t>& credentialId,
        const std::vector<uint8_t>& salt
    );

    // Get an assertion as a proof-of-presence (no hmac-secret).
    // Used for admin vouch operations.
    static GetAssertionResult GetAssertionProof(
        HWND hwnd,
        const std::string& rpId,
        const std::vector<uint8_t>& credentialId
    );

private:
    // Build a synthetic clientDataJSON and return its SHA-256 hash.
    static std::vector<uint8_t> BuildClientDataHash(
        const std::string& type,
        const std::string& rpId
    );

    // Format a HRESULT / WebAuthn error into a readable string.
    static std::string FormatWebAuthnError(HRESULT hr);
};
