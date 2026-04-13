// WebAuthnHelper.cpp
// Windows WebAuthn API wrappers for FIDO2 MakeCredential and GetAssertion.

#include "WebAuthnHelper.h"
#include "FileLog.h"
#include <bcrypt.h>
#include <string>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), len);
    return w;
}

// Build a minimal clientDataJSON string. The Windows WebAuthn API takes
// the raw JSON and hashes it internally, so we return the JSON bytes, not
// a hash.  We also compute and return the SHA-256 hash separately because
// dds-node needs it in its assertion/enrollment request JSON.
struct ClientData
{
    std::vector<uint8_t> json;    // raw clientDataJSON bytes
    std::vector<uint8_t> hash;    // SHA-256(json)
};

static ClientData BuildClientData(
    const std::string& type,
    const std::string& rpId)
{
    // Base64url-encode a random challenge
    uint8_t randomBytes[32];
    BCryptGenRandom(NULL, randomBytes, sizeof(randomBytes),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string challenge;
    challenge.reserve(43);
    for (int i = 0; i < 32; i += 3)
    {
        uint32_t n = static_cast<uint32_t>(randomBytes[i]) << 16;
        if (i + 1 < 32) n |= static_cast<uint32_t>(randomBytes[i + 1]) << 8;
        if (i + 2 < 32) n |= static_cast<uint32_t>(randomBytes[i + 2]);
        challenge.push_back(table[(n >> 18) & 0x3F]);
        challenge.push_back(table[(n >> 12) & 0x3F]);
        if (i + 1 < 32) challenge.push_back(table[(n >> 6) & 0x3F]);
        if (i + 2 < 32) challenge.push_back(table[n & 0x3F]);
    }

    std::string cdj = "{\"type\":\"" + type + "\","
                      "\"challenge\":\"" + challenge + "\","
                      "\"origin\":\"https://" + rpId + "\"}";

    ClientData cd;
    cd.json.assign(cdj.begin(), cdj.end());

    // SHA-256 the clientDataJSON for dds-node
    cd.hash.resize(32);
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
    {
        if (BCRYPT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0)))
        {
            BCryptHashData(hHash, cd.json.data(), (ULONG)cd.json.size(), 0);
            BCryptFinishHash(hHash, cd.hash.data(), 32, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    SecureZeroMemory(randomBytes, sizeof(randomBytes));
    return cd;
}

std::string CWebAuthnHelper::FormatWebAuthnError(HRESULT hr)
{
    char buf[256];
    sprintf_s(buf, "WebAuthn error 0x%08lX", (unsigned long)hr);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// MakeCredential
// ---------------------------------------------------------------------------

MakeCredentialResult CWebAuthnHelper::MakeCredential(
    HWND hwnd,
    const std::string& rpId,
    const std::vector<uint8_t>& userId,
    const std::wstring& displayName,
    bool hmacSecret)
{
    MakeCredentialResult result = {};

    FileLog::Writef("WebAuthn.MakeCredential: rpId='%s' hmacSecret=%d\n",
                    rpId.c_str(), hmacSecret ? 1 : 0);

    // Build client data (raw JSON + its SHA-256 hash)
    auto cd = BuildClientData("webauthn.create", rpId);
    result.clientDataHash = cd.hash;

    // RP entity
    std::wstring rpIdW = Utf8ToWide(rpId);
    WEBAUTHN_RP_ENTITY_INFORMATION rpEntity = {};
    rpEntity.dwVersion = WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION;
    rpEntity.pwszId = rpIdW.c_str();
    rpEntity.pwszName = rpIdW.c_str();

    // User entity
    WEBAUTHN_USER_ENTITY_INFORMATION userEntity = {};
    userEntity.dwVersion = WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION;
    userEntity.cbId = (DWORD)userId.size();
    userEntity.pbId = const_cast<PBYTE>(userId.data());
    userEntity.pwszName = displayName.c_str();
    userEntity.pwszDisplayName = displayName.c_str();

    // Credential parameters — prefer ES256, fall back to RS256
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER coseParams[2] = {};
    coseParams[0].dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    coseParams[0].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    coseParams[0].lAlg = WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256;
    coseParams[1].dwVersion = WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION;
    coseParams[1].pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;
    coseParams[1].lAlg = WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256;

    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS coseParamsList = {};
    coseParamsList.cCredentialParameters = 2;
    coseParamsList.pCredentialParameters = coseParams;

    // Client data — pass the raw JSON, the API hashes it internally
    WEBAUTHN_CLIENT_DATA clientData = {};
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)cd.json.size();
    clientData.pbClientDataJSON = cd.json.data();
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // Authenticator make-credential options
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS options = {};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.dwAttestationConveyancePreference = WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT;
    options.dwAuthenticatorAttachment = WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY;
    options.bRequireResidentKey = FALSE;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;

    // hmac-secret extension
    WEBAUTHN_EXTENSION hmacExt = {};
    BOOL hmacTrue = TRUE;
    if (hmacSecret)
    {
        hmacExt.pwszExtensionIdentifier = WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET;
        hmacExt.cbExtension = sizeof(BOOL);
        hmacExt.pvExtension = &hmacTrue;

        options.Extensions.cExtensions = 1;
        options.Extensions.pExtensions = &hmacExt;
    }

    // Call the platform API
    PWEBAUTHN_CREDENTIAL_ATTESTATION pAttestation = nullptr;
    HRESULT hr = WebAuthNAuthenticatorMakeCredential(
        hwnd,
        &rpEntity,
        &userEntity,
        &coseParamsList,
        &clientData,
        &options,
        &pAttestation
    );

    if (FAILED(hr) || pAttestation == nullptr)
    {
        result.success = false;
        result.errorMessage = FormatWebAuthnError(hr);
        FileLog::Writef("WebAuthn.MakeCredential: FAILED hr=0x%08lX\n", (unsigned long)hr);
        return result;
    }

    // Extract credential ID
    result.credentialId.assign(
        pAttestation->pbCredentialId,
        pAttestation->pbCredentialId + pAttestation->cbCredentialId);

    // Extract attestation object
    result.attestationObject.assign(
        pAttestation->pbAttestationObject,
        pAttestation->pbAttestationObject + pAttestation->cbAttestationObject);

    result.success = true;

    FileLog::Writef("WebAuthn.MakeCredential: OK credIdLen=%zu attestLen=%zu\n",
                    result.credentialId.size(), result.attestationObject.size());

    WebAuthNFreeCredentialAttestation(pAttestation);
    return result;
}

// ---------------------------------------------------------------------------
// GetAssertion with hmac-secret
// ---------------------------------------------------------------------------

GetAssertionResult CWebAuthnHelper::GetAssertionHmacSecret(
    HWND hwnd,
    const std::string& rpId,
    const std::vector<uint8_t>& credentialId,
    const std::vector<uint8_t>& salt)
{
    GetAssertionResult result = {};

    FileLog::Writef("WebAuthn.GetAssertionHmac: rpId='%s' credIdLen=%zu saltLen=%zu\n",
                    rpId.c_str(), credentialId.size(), salt.size());

    if (salt.size() != 32)
    {
        result.success = false;
        result.errorMessage = "hmac-secret salt must be 32 bytes";
        return result;
    }

    auto cd = BuildClientData("webauthn.get", rpId);
    result.clientDataHash = cd.hash;

    std::wstring rpIdW = Utf8ToWide(rpId);

    // Client data — pass the raw JSON
    WEBAUTHN_CLIENT_DATA clientData = {};
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)cd.json.size();
    clientData.pbClientDataJSON = cd.json.data();
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // Allow-list: only this specific credential
    WEBAUTHN_CREDENTIAL allowCred = {};
    allowCred.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
    allowCred.cbId = (DWORD)credentialId.size();
    allowCred.pbId = const_cast<PBYTE>(credentialId.data());
    allowCred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

    WEBAUTHN_CREDENTIALS allowList = {};
    allowList.cCredentials = 1;
    allowList.pCredentials = &allowCred;

    // hmac-secret salt via the dedicated pHmacSecretSaltValues field
    // (available from OPTIONS_VERSION_6+, current SDK is v9).
    WEBAUTHN_HMAC_SECRET_SALT hmacSalt = {};
    hmacSalt.cbFirst = (DWORD)salt.size();
    hmacSalt.pbFirst = const_cast<PBYTE>(salt.data());

    WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT credSalt = {};
    credSalt.cbCredID = (DWORD)credentialId.size();
    credSalt.pbCredID = const_cast<PBYTE>(credentialId.data());
    credSalt.pHmacSecretSalt = &hmacSalt;

    WEBAUTHN_HMAC_SECRET_SALT_VALUES saltValues = {};
    saltValues.pGlobalHmacSalt = &hmacSalt;
    saltValues.cCredWithHmacSecretSaltList = 1;
    saltValues.pCredWithHmacSecretSaltList = &credSalt;

    // Options
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = {};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.CredentialList = allowList;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;
    options.pHmacSecretSaltValues = &saltValues;

    PWEBAUTHN_ASSERTION pAssertion = nullptr;
    HRESULT hr = WebAuthNAuthenticatorGetAssertion(
        hwnd,
        rpIdW.c_str(),
        &clientData,
        &options,
        &pAssertion
    );

    if (FAILED(hr) || pAssertion == nullptr)
    {
        result.success = false;
        result.errorMessage = FormatWebAuthnError(hr);
        FileLog::Writef("WebAuthn.GetAssertionHmac: FAILED hr=0x%08lX\n", (unsigned long)hr);
        return result;
    }

    // Extract assertion fields
    result.authenticatorData.assign(
        pAssertion->pbAuthenticatorData,
        pAssertion->pbAuthenticatorData + pAssertion->cbAuthenticatorData);
    result.signature.assign(
        pAssertion->pbSignature,
        pAssertion->pbSignature + pAssertion->cbSignature);
    result.credentialId.assign(
        pAssertion->Credential.pbId,
        pAssertion->Credential.pbId + pAssertion->Credential.cbId);

    // Extract hmac-secret output from extensions
    if (pAssertion->dwVersion >= 2 &&
        pAssertion->pHmacSecret != nullptr &&
        pAssertion->pHmacSecret->cbFirst >= 32)
    {
        result.hmacSecretOutput.assign(
            pAssertion->pHmacSecret->pbFirst,
            pAssertion->pHmacSecret->pbFirst + 32);
    }
    else
    {
        FileLog::Write("WebAuthn.GetAssertionHmac: WARNING - no hmac-secret in response\n");
    }

    result.success = true;

    FileLog::Writef("WebAuthn.GetAssertionHmac: OK authDataLen=%zu sigLen=%zu hmacLen=%zu\n",
                    result.authenticatorData.size(), result.signature.size(),
                    result.hmacSecretOutput.size());

    WebAuthNFreeAssertion(pAssertion);
    return result;
}

// ---------------------------------------------------------------------------
// GetAssertion proof-of-presence (no hmac-secret)
// ---------------------------------------------------------------------------

GetAssertionResult CWebAuthnHelper::GetAssertionProof(
    HWND hwnd,
    const std::string& rpId,
    const std::vector<uint8_t>& credentialId)
{
    GetAssertionResult result = {};

    FileLog::Writef("WebAuthn.GetAssertionProof: rpId='%s' credIdLen=%zu\n",
                    rpId.c_str(), credentialId.size());

    auto cd = BuildClientData("webauthn.get", rpId);
    result.clientDataHash = cd.hash;

    std::wstring rpIdW = Utf8ToWide(rpId);

    // Client data — pass the raw JSON
    WEBAUTHN_CLIENT_DATA clientData = {};
    clientData.dwVersion = WEBAUTHN_CLIENT_DATA_CURRENT_VERSION;
    clientData.cbClientDataJSON = (DWORD)cd.json.size();
    clientData.pbClientDataJSON = cd.json.data();
    clientData.pwszHashAlgId = WEBAUTHN_HASH_ALGORITHM_SHA_256;

    // Allow-list
    WEBAUTHN_CREDENTIAL allowCred = {};
    allowCred.dwVersion = WEBAUTHN_CREDENTIAL_CURRENT_VERSION;
    allowCred.cbId = (DWORD)credentialId.size();
    allowCred.pbId = const_cast<PBYTE>(credentialId.data());
    allowCred.pwszCredentialType = WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY;

    WEBAUTHN_CREDENTIALS allowList = {};
    allowList.cCredentials = 1;
    allowList.pCredentials = &allowCred;

    // Options — no extensions needed for proof-of-presence
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS options = {};
    options.dwVersion = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION;
    options.dwTimeoutMilliseconds = 60000;
    options.CredentialList = allowList;
    options.dwUserVerificationRequirement = WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED;

    PWEBAUTHN_ASSERTION pAssertion = nullptr;
    HRESULT hr = WebAuthNAuthenticatorGetAssertion(
        hwnd,
        rpIdW.c_str(),
        &clientData,
        &options,
        &pAssertion
    );

    if (FAILED(hr) || pAssertion == nullptr)
    {
        result.success = false;
        result.errorMessage = FormatWebAuthnError(hr);
        FileLog::Writef("WebAuthn.GetAssertionProof: FAILED hr=0x%08lX\n", (unsigned long)hr);
        return result;
    }

    result.authenticatorData.assign(
        pAssertion->pbAuthenticatorData,
        pAssertion->pbAuthenticatorData + pAssertion->cbAuthenticatorData);
    result.signature.assign(
        pAssertion->pbSignature,
        pAssertion->pbSignature + pAssertion->cbSignature);
    result.credentialId.assign(
        pAssertion->Credential.pbId,
        pAssertion->Credential.pbId + pAssertion->Credential.cbId);

    result.success = true;

    FileLog::Writef("WebAuthn.GetAssertionProof: OK authDataLen=%zu sigLen=%zu\n",
                    result.authenticatorData.size(), result.signature.size());

    WebAuthNFreeAssertion(pAssertion);
    return result;
}
