// ctap_authenticator.cpp  — see ctap_authenticator.h

#include "ctap_authenticator.h"
#include "ctaphid_transport.h"
#include "ctap2_protocol.h"
#include "ctap2_pin_protocol.h"
#include "../FileLog.h"

#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

static const uint8_t CTAP2_NO_CREDENTIALS = 0x2E;
static const uint8_t CTAP2_PIN_REQUIRED   = 0x36;

bool CtapAuthenticator::PrfTransformSalt(const std::vector<uint8_t>& rawSalt, uint8_t out32[32])
{
    // SHA-256( "WebAuthn PRF" || 0x00 || rawSalt )
    static const char PRF[] = "WebAuthn PRF";           // 12 bytes, no NUL
    std::vector<uint8_t> in(PRF, PRF + (sizeof(PRF) - 1));
    in.push_back(0x00);
    in.insert(in.end(), rawSalt.begin(), rawSalt.end());

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return false;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0)))
    {
        if (BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)in.data(), (ULONG)in.size(), 0)) &&
            BCRYPT_SUCCESS(BCryptFinishHash(hHash, out32, 32, 0)))
            ok = true;
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// One getAssertion attempt against a single credential + already-transformed
// salt. Returns the CTAP status (0 = success) or 0xFF on a local/transport
// failure (err set). On success, fills authData/sig/credId/hmac in `out`.
static uint8_t AssertOne(CCtapHidDevice& dev, const std::string& rpId,
                         const uint8_t clientDataHash[32],
                         const std::vector<uint8_t>& credId,
                         const uint8_t prfSalt[32],
                         DWORD timeoutMs, CtapAssertion& out, bool& timedOut,
                         std::string& err)
{
    timedOut = false;

    std::vector<uint8_t> cmd, resp;
    if (!CCtap2Protocol::BuildClientPINGetKeyAgreementCommand(cmd, 1)) { err = "build getKeyAgreement"; return 0xFF; }
    if (!dev.Cbor(cmd, resp, 5000, err)) return 0xFF;
    uint8_t ax[32], ay[32];
    if (!CCtap2Protocol::ParseClientPINKeyAgreementResponse(resp.data(), resp.size(), ax, ay))
    { err = "parse getKeyAgreement (no hmac-secret / PIN proto 1?)"; return 0xFF; }

    CCtapPinProtocol pin;
    if (!pin.GeneratePlatformKey()) { err = "GeneratePlatformKey"; return 0xFF; }
    CoseEcKey ak; memcpy(ak.x, ax, 32); memcpy(ak.y, ay, 32); ak.valid = true;
    pin.SetAuthenticatorKey(ak);
    if (!pin.DeriveSharedSecret()) { err = "DeriveSharedSecret"; return 0xFF; }

    std::vector<uint8_t> saltEnc, saltAuth, kac;
    if (!pin.EncryptSalt(prfSalt, saltEnc, saltAuth)) { err = "EncryptSalt"; return 0xFF; }
    if (!pin.GetPlatformPublicKeyCbor(kac)) { err = "platform COSE key"; return 0xFF; }

    Ctap2GetAssertionRequest req;
    req.rpId = rpId;
    req.clientDataHash.assign(clientDataHash, clientDataHash + 32);
    Ctap2GetAssertionRequest::AllowListEntry ale; ale.type = "public-key"; ale.id = credId;
    req.allowList.push_back(ale);
    req.useHmacSecret = true;
    req.hmacSecretKeyAgreement = kac;
    req.hmacSecretSaltEnc = saltEnc;
    req.hmacSecretSaltAuth = saltAuth;
    req.hasOptionUP = true; req.optionUP = true;   // presence; bio key auto-verifies → UV=1
    if (!CCtap2Protocol::BuildGetAssertionCommand(req, cmd)) { err = "build getAssertion"; return 0xFF; }

    if (!dev.Cbor(cmd, resp, timeoutMs, err, &timedOut)) return 0xFF;

    Ctap2GetAssertionResponse ga;
    uint8_t st = CCtap2Protocol::ParseGetAssertionResponse(resp.data(), resp.size(), ga);
    if (st != 0x00) return st;

    if (ga.hmacSecretOutput.size() != 32 && ga.hmacSecretOutput.size() != 64) { err = "no/odd hmac output"; return 0xFF; }
    std::vector<uint8_t> hmac;
    if (!pin.DecryptOutput(ga.hmacSecretOutput, hmac) || hmac.size() < 32) { err = "DecryptOutput"; return 0xFF; }
    hmac.resize(32);

    out.authenticatorData = ga.authData;
    out.signature = ga.signature;
    // Prefer the credential id the authenticator echoed; fall back to the offered id.
    out.credentialId = ga.credential.id.empty() ? credId : ga.credential.id;
    out.hmacSecret = std::move(hmac);
    out.uvFlag = ga.flagUV() ? 1 : 0;
    return 0x00;
}

CtapAssertion CtapAuthenticator::GetAssertionWithHmac(
    const std::string& rpId,
    const uint8_t clientDataHash[32],
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& creds,
    DWORD timeoutMs,
    HANDLE hCancel)
{
    CtapAssertion result;

    if (creds.empty()) { result.error = "no credentials offered"; return result; }

    CCtapHidDevice dev;
    std::string err;
    if (!dev.OpenFirst(err)) { result.error = err; return result; }
    dev.SetCancelEvent(hCancel);

    bool anyPresent = false;
    for (const auto& c : creds)
    {
        // Honor cancellation between credential attempts.
        if (hCancel && WaitForSingleObject(hCancel, 0) == WAIT_OBJECT_0)
        { result.cancelled = true; result.error = "cancelled"; return result; }

        const std::vector<uint8_t>& credId  = c.first;
        const std::vector<uint8_t>& rawSalt = c.second;
        if (credId.empty() || rawSalt.size() != 32)
            continue;

        uint8_t prfSalt[32];
        if (!PrfTransformSalt(rawSalt, prfSalt)) { result.error = "PRF salt transform failed"; return result; }

        bool timedOut = false;
        std::string e2;
        uint8_t st = AssertOne(dev, rpId, clientDataHash, credId, prfSalt, timeoutMs, result, timedOut, e2);
        SecureZeroMemory(prfSalt, sizeof(prfSalt));

        // A cancel during the HID wait surfaces as a transport failure (0xFF);
        // distinguish it so the caller doesn't treat it as a real error.
        if (st == 0xFF && dev.WasCancelled())
        { result.cancelled = true; result.error = "cancelled"; return result; }

        if (st == 0x00)
        {
            result.success = true;
            FileLog::Writef("ctap-fallback: assertion OK (uv=%d authDataLen=%zu hmac=32)\n",
                            result.uvFlag, result.authenticatorData.size());
            return result;
        }
        if (st == CTAP2_NO_CREDENTIALS)
        {
            // This credential isn't on the inserted key — try the next one.
            continue;
        }
        if (st == 0xFF)
        {
            if (timedOut) { result.timedOut = true; result.error = "no touch within timeout"; return result; }
            result.error = e2.empty() ? "CTAP transport error" : e2;
            return result;
        }
        if (st == CTAP2_PIN_REQUIRED)
        {
            result.error = "authenticator requires a PIN/UV token (not supported by the fallback)";
            return result;
        }
        // Any other CTAP error status — report it.
        char b[64]; sprintf_s(b, "CTAP status 0x%02X (%s)", st, CCtap2Protocol::StatusToString(st));
        result.error = b;
        return result;
    }

    (void)anyPresent;
    result.noCredentialPresent = true;
    result.error = "none of the offered credentials is on the inserted authenticator";
    return result;
}
