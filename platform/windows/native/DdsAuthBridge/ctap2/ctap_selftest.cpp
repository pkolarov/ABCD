// ctap_selftest.cpp  — see ctap_selftest.h

#include "ctap_selftest.h"
#include "ctaphid_transport.h"
#include "ctap2_protocol.h"
#include "ctap2_pin_protocol.h"
#include "cbor.h"
#include "../CredentialVault.h"
#include "../FileLog.h"

#include <windows.h>
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

// CTAP2 status codes we branch on.
static const uint8_t CTAP2_NO_CREDENTIALS = 0x2E;
static const uint8_t CTAP2_PIN_REQUIRED   = 0x36;

// Per-entry / per-attempt outcome.
enum { R_PASS = 1, R_SKIP = 0, R_HARDFAIL = -1, R_NEEDS_UV = -2 };

// Log to both the console (operator is watching) and authbridge.log (durable).
static void Say(const char* fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    printf("%s\n", buf);
    FileLog::Writef("ctap-selftest: %s\n", buf);
}

static std::string HexPrefix(const std::vector<uint8_t>& v, size_t n)
{
    static const char* hex = "0123456789abcdef";
    std::string out;
    size_t m = (v.size() < n) ? v.size() : n;
    for (size_t i = 0; i < m; ++i) { out.push_back(hex[v[i] >> 4]); out.push_back(hex[v[i] & 0xF]); }
    return out;
}

static bool Sha256(const std::vector<uint8_t>& in, uint8_t out[32])
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        return false;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    bool ok = false;
    if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0)))
    {
        if (BCRYPT_SUCCESS(BCryptHashData(hHash, (PUCHAR)in.data(), (ULONG)in.size(), 0)) &&
            BCRYPT_SUCCESS(BCryptFinishHash(hHash, out, 32, 0)))
            ok = true;
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

// Authenticator capability flags (diagnostic only).
struct AuthInfo
{
    bool queried = false, clientPin = false, uvBuiltin = false, alwaysUv = false, hmacSecret = false;
};

// authenticatorGetInfo (0x04) → log options + extensions.
static AuthInfo QueryAuthInfo(CCtapHidDevice& dev, int index)
{
    AuthInfo info;
    std::vector<uint8_t> cmd, resp;
    std::string err;
    if (!CCtap2Protocol::BuildGetInfoCommand(cmd)) return info;
    if (!dev.Cbor(cmd, resp, 3000, err)) { Say("[entry %d] getInfo transport failed: %s", index, err.c_str()); return info; }
    if (resp.empty() || resp[0] != 0x00) return info;

    CborDecoder dec;
    CborValue root;
    if (!dec.Decode(resp.data() + 1, resp.size() - 1, root) || root.type != CborType::Map) return info;
    info.queried = true;

    std::string optStr;
    const CborValue* opts = root.MapLookup(static_cast<uint64_t>(0x04));
    if (opts && opts->type == CborType::Map)
        for (const auto& kv : opts->mapVal)
        {
            if (kv.first.type != CborType::TextString || kv.second.type != CborType::Boolean) continue;
            const std::string& k = kv.first.strVal; const bool v = kv.second.boolVal;
            optStr += k + "=" + (v ? "1 " : "0 ");
            if (k == "clientPin") info.clientPin = v;
            else if (k == "uv") info.uvBuiltin = v;
            else if (k == "alwaysUv") info.alwaysUv = v;
        }

    const CborValue* exts = root.MapLookup(static_cast<uint64_t>(0x02));
    if (exts && exts->type == CborType::Array)
        for (const auto& e : exts->arrayVal)
            if (e.type == CborType::TextString && e.strVal == "hmac-secret") info.hmacSecret = true;

    Say("[entry %d] authenticator: options[ %s] hmac-secret=%d", index, optStr.c_str(), info.hmacSecret ? 1 : 0);
    return info;
}

// Run one raw-CTAP getAssertion+hmac-secret for a specific 32-byte salt and return
// the decrypted 32-byte hmac output + the assertion UV flag. Fresh key agreement
// each call. Returns R_PASS (out filled), R_SKIP (credential not present / no
// touch), R_NEEDS_UV (0x36), or R_HARDFAIL (err set).
static int RawHmacForSalt(CCtapHidDevice& dev, const VaultEntry& entry,
                          const uint8_t salt32[32], std::vector<uint8_t>& out32,
                          int& uvFlag, std::string& err)
{
    std::vector<uint8_t> cmd, resp;
    if (!CCtap2Protocol::BuildClientPINGetKeyAgreementCommand(cmd, 1)) { err = "build getKeyAgreement"; return R_HARDFAIL; }
    if (!dev.Cbor(cmd, resp, 5000, err)) return R_HARDFAIL;
    uint8_t ax[32], ay[32];
    if (!CCtap2Protocol::ParseClientPINKeyAgreementResponse(resp.data(), resp.size(), ax, ay))
    { err = "parse getKeyAgreement (no hmac-secret/PIN proto 1?)"; return R_HARDFAIL; }

    CCtapPinProtocol pin;
    if (!pin.GeneratePlatformKey()) { err = "GeneratePlatformKey"; return R_HARDFAIL; }
    CoseEcKey ak; memcpy(ak.x, ax, 32); memcpy(ak.y, ay, 32); ak.valid = true;
    pin.SetAuthenticatorKey(ak);
    if (!pin.DeriveSharedSecret()) { err = "DeriveSharedSecret"; return R_HARDFAIL; }

    std::vector<uint8_t> saltEnc, saltAuth, kac;
    if (!pin.EncryptSalt(salt32, saltEnc, saltAuth)) { err = "EncryptSalt"; return R_HARDFAIL; }
    if (!pin.GetPlatformPublicKeyCbor(kac)) { err = "platform COSE key"; return R_HARDFAIL; }

    Ctap2GetAssertionRequest req;
    req.rpId = entry.rpId;
    req.clientDataHash.resize(32);
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, req.clientDataHash.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    { err = "BCryptGenRandom"; return R_HARDFAIL; }
    Ctap2GetAssertionRequest::AllowListEntry ale; ale.type = "public-key"; ale.id = entry.credentialId;
    req.allowList.push_back(ale);
    req.useHmacSecret = true;
    req.hmacSecretKeyAgreement = kac;
    req.hmacSecretSaltEnc = saltEnc;
    req.hmacSecretSaltAuth = saltAuth;
    req.hasOptionUP = true; req.optionUP = true;
    if (!CCtap2Protocol::BuildGetAssertionCommand(req, cmd)) { err = "build getAssertion"; return R_HARDFAIL; }

    bool timedOut = false;
    if (!dev.Cbor(cmd, resp, 30000, err, &timedOut)) { if (timedOut) return R_SKIP; return R_HARDFAIL; }

    Ctap2GetAssertionResponse ga;
    uint8_t stx = CCtap2Protocol::ParseGetAssertionResponse(resp.data(), resp.size(), ga);
    if (stx == CTAP2_NO_CREDENTIALS) return R_SKIP;
    if (stx == CTAP2_PIN_REQUIRED) return R_NEEDS_UV;
    if (stx != 0x00) { char b[48]; sprintf_s(b, "CTAP status 0x%02X", stx); err = b; return R_HARDFAIL; }

    uvFlag = ga.flagUV() ? 1 : 0;
    if (ga.hmacSecretOutput.size() != 32 && ga.hmacSecretOutput.size() != 64) { err = "no/odd hmac output"; return R_HARDFAIL; }
    if (!pin.DecryptOutput(ga.hmacSecretOutput, out32) || out32.size() < 32) { err = "DecryptOutput"; return R_HARDFAIL; }
    out32.resize(32);
    return R_PASS;
}

// One credential's parity attempt: hunt the salt transform webauthn.dll applies
// by testing candidates and seeing which raw-CTAP output decrypts the vault.
static int TryEntry(const VaultEntry& entry, int index)
{
    Say("[entry %d] rp='%s' credId[0..8]=%s encPwLen=%zu",
        index, entry.rpId.c_str(), HexPrefix(entry.credentialId, 8).c_str(), entry.encryptedPassword.size());

    if (entry.credentialId.empty() || entry.salt.size() != 32 ||
        entry.encryptedPassword.empty() || entry.iv.empty() || entry.authTag.empty())
    { Say("[entry %d] SKIP — incomplete vault entry", index); return R_SKIP; }
    if (entry.rpId.empty())
    { Say("[entry %d] FAIL — vault entry has no rpId", index); return R_HARDFAIL; }

    CCtapHidDevice dev;
    std::string err;
    if (!dev.OpenFirst(err)) { Say("[entry %d] FAIL — %s", index, err.c_str()); return R_HARDFAIL; }

    (void)QueryAuthInfo(dev, index);

    // webauthn.dll may transform the raw salt before the CTAP hmac-secret call —
    // notably the WebAuthn PRF transform SHA-256("WebAuthn PRF"\0 || salt). The
    // vault was sealed with whatever webauthn produced, so try each candidate salt
    // and see which one's raw-CTAP output decrypts the vault (ground truth).
    struct Cand { std::string name; std::vector<uint8_t> salt; };
    std::vector<Cand> cands;
    cands.push_back({ "raw(salt)", entry.salt });
    {
        static const char PRF[] = "WebAuthn PRF";
        std::vector<uint8_t> in(PRF, PRF + (sizeof(PRF) - 1));
        in.push_back(0x00);
        in.insert(in.end(), entry.salt.begin(), entry.salt.end());
        uint8_t h[32];
        if (Sha256(in, h)) cands.push_back({ "prf: SHA256(\"WebAuthn PRF\"\\0|salt)", std::vector<uint8_t>(h, h + 32) });
    }
    {
        uint8_t h[32];
        if (Sha256(entry.salt, h)) cands.push_back({ "sha256(salt)", std::vector<uint8_t>(h, h + 32) });
    }

    for (const Cand& c : cands)
    {
        Say("[entry %d] >>> touch your security key now (candidate salt: %s)...", index, c.name.c_str());
        std::vector<uint8_t> out; int uv = -1; std::string e2;
        int r = RawHmacForSalt(dev, entry, c.salt.data(), out, uv, e2);
        if (r == R_SKIP)     { Say("[entry %d] skip — credential not on inserted key / no touch", index); return R_SKIP; }
        if (r == R_NEEDS_UV) { Say("[entry %d] NEEDS-UV — key forces UV (0x36)", index); return R_NEEDS_UV; }
        if (r != R_PASS)
        { Say("[entry %d] FAIL — %s (candidate %s)", index, e2.c_str(), c.name.c_str());
          if (!out.empty()) SecureZeroMemory(out.data(), out.size()); return R_HARDFAIL; }

        std::wstring pw;
        bool dec = CCredentialVault::DecryptPassword(out.data(), 32, entry, pw);
        if (!pw.empty()) SecureZeroMemory(&pw[0], pw.size() * sizeof(wchar_t));
        SecureZeroMemory(out.data(), out.size());
        Say("[entry %d] candidate '%s': UV=%d decrypts=%d", index, c.name.c_str(), uv, dec ? 1 : 0);

        if (dec)
        {
            Say("[entry %d] PASS — salt transform '%s' reproduces webauthn's hmac-secret. PARITY CONFIRMED.",
                index, c.name.c_str());
            Say("[entry %d]   → Stage 2 recipe: apply salt transform '%s' before the CTAP hmac-secret call.",
                index, c.name.c_str());
            return R_PASS;
        }
    }

    Say("[entry %d] FAIL — no salt-transform candidate (raw/prf/sha256) decrypted the vault. "
        "Divergence is elsewhere (e.g. PIN/UV protocol 2 encryption, or a different transform).", index);
    return R_HARDFAIL;
}

int RunCtapHmacParitySelfTest()
{
    FileLog::Init();
    Say("==== raw-CTAP2 hmac-secret parity self-test ====");

    CCredentialVault vault;
    if (!vault.Load())
    {
        Say("FAIL — could not load the vault. Expected at %%ProgramData%%\\DDS\\vault.dat "
            "(or DDS_VAULT_PATH). Check the file exists and is readable; the blob is "
            "machine-scoped DPAPI so any local process can decrypt it once the file opens.");
        return 2;
    }
    const std::vector<VaultEntry>& entries = vault.GetEntries();
    Say("vault entries: %zu", entries.size());
    if (entries.empty())
    {
        Say("FAIL — no enrolled credentials in the vault; enroll a FIDO2 key first.");
        return 2;
    }

    int passes = 0, hardFails = 0, needsUv = 0, tested = 0;
    for (size_t i = 0; i < entries.size(); ++i)
    {
        int r = TryEntry(entries[i], (int)i);
        if      (r == R_PASS)     { passes++;    tested++; }
        else if (r == R_HARDFAIL) { hardFails++; tested++; }
        else if (r == R_NEEDS_UV) { needsUv++;   tested++; }
    }

    Say("==== summary: %d passed, %d failed, %d needs-UV, %zu entries (%d exercised) ====",
        passes, hardFails, needsUv, entries.size(), tested);

    // Exit codes (mirrored in ctap_selftest.h):
    //   0 confirmed | 1 mixed | 2 no-vault | 3 inconclusive | 4 all-failed | 5 needs-UV
    if (passes > 0 && hardFails == 0 && needsUv == 0)
    { Say("RESULT: PARITY CONFIRMED — Stage 2 (raw-CTAP logon fallback) is viable."); return 0; }
    if (passes > 0 && hardFails > 0)
    { Say("RESULT: MIXED — some credentials matched, some failed; investigate before Stage 2."); return 1; }
    if (needsUv > 0 && hardFails == 0)
    { Say("RESULT: NEEDS UV TOKEN — the key forces UV; Stage 2 must implement pinUvAuthToken support."); return 5; }
    if (tested == 0)
    { Say("RESULT: INCONCLUSIVE — no enrolled credential was present on the inserted key."); return 3; }
    Say("RESULT: PARITY FAILED — raw-CTAP hmac-secret does not match enrollment.");
    return 4;
}
