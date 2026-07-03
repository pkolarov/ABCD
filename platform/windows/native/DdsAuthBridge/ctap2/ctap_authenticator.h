// ctap_authenticator.h
// Raw CTAP2-over-HID getAssertion + hmac-secret for the pre-first-logon fallback.
//
// When the credential provider's WebAuthNAuthenticatorGetAssertion fails at the
// lock screen with 0x8000401A (the Interactive-User UX broker cannot activate
// before the first interactive logon of a boot), the bridge — running as
// LocalSystem in session 0, which CAN open FIDO HID devices directly — performs
// the assertion itself with no UI broker. This reproduces exactly what
// webauthn.dll would have returned:
//   * the WebAuthn PRF salt transform SHA-256("WebAuthn PRF" || 0x00 || salt)
//     (webauthn.dll applies this to hmac-secret salts; proven required by the
//     parity self-test), and
//   * user presence (up=true) — a fingerprint key auto-verifies on touch, so the
//     UV state matches webauthn.dll's DISCOURAGED enrollment.
//
// The decrypted hmac-secret output decrypts the vault password; the assertion
// (authenticatorData + signature) is POSTed to dds-node just like the CP path.

#pragma once

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <utility>

struct CtapAssertion
{
    bool success = false;
    std::vector<uint8_t> authenticatorData;  // for /v1/session/assert
    std::vector<uint8_t> signature;          // for /v1/session/assert
    std::vector<uint8_t> credentialId;       // the credential the key actually used
    std::vector<uint8_t> hmacSecret;         // 32-byte decrypted hmac-secret output
    int  uvFlag = -1;                        // UV bit from the assertion authData
    bool noCredentialPresent = false;        // every offered credential returned NO_CREDENTIALS
    bool timedOut = false;                    // user never touched within the window
    bool cancelled = false;                   // aborted via the cancel event
    std::string error;
};

class CtapAuthenticator
{
public:
    // Perform a raw-CTAP getAssertion+hmac-secret over USB HID, without
    // webauthn.dll. `creds` is the list of (rawCredentialId, rawSalt) pairs to
    // offer — each credential is tried (allowList of one) until the physically
    // present one is found (others return NO_CREDENTIALS without a touch). The
    // raw salt is PRF-transformed internally. `clientDataHash` is the 32-byte
    // SHA-256 of the clientDataJSON the caller built (bound into the signature).
    // hCancel: optional manual-reset event; when signaled, an in-flight HID wait
    // aborts promptly and the result has cancelled=true.
    static CtapAssertion GetAssertionWithHmac(
        const std::string& rpId,
        const uint8_t clientDataHash[32],
        const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& creds,
        DWORD timeoutMs,
        HANDLE hCancel = nullptr);

    // The WebAuthn PRF salt transform webauthn.dll applies before the CTAP call:
    //   out = SHA-256(UTF8("WebAuthn PRF") || 0x00 || rawSalt)
    // Exposed for tests. Returns false only on a BCrypt failure.
    static bool PrfTransformSalt(const std::vector<uint8_t>& rawSalt, uint8_t out32[32]);
};
