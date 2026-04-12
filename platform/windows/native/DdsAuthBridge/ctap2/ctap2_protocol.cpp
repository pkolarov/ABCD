// ctap2_protocol.cpp
// FIDO2 CTAP2 protocol implementation.
//

#include "ctap2_protocol.h"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// ============================================================================
// BuildGetAssertionCommand
// ============================================================================

bool CCtap2Protocol::BuildGetAssertionCommand(
    const Ctap2GetAssertionRequest& request,
    std::vector<uint8_t>& outCommandBytes)
{
    // authenticatorGetAssertion(0x02) parameters are a CBOR map:
    //   0x01: rpId (text string)
    //   0x02: clientDataHash (byte string, 32 bytes)
    //   0x03: allowList (array of PublicKeyCredentialDescriptor) [optional]
    //   0x04: extensions (map) [optional]
    //   0x05: options (map) [optional]
    //   0x06: pinUvAuthParam (byte string) [optional]
    //   0x07: pinUvAuthProtocol (unsigned int) [optional]

    CborMap params;

    // 0x01: rpId
    params.push_back({ CborValue::Uint(0x01), CborValue::String(request.rpId) });

    // 0x02: clientDataHash
    params.push_back({ CborValue::Uint(0x02), CborValue::Bytes(request.clientDataHash) });

    // 0x03: allowList
    if (!request.allowList.empty())
    {
        CborArray allowArr;
        for (const auto& entry : request.allowList)
        {
            CborMap desc;
            desc.push_back({ CborValue::String("type"), CborValue::String(entry.type) });
            desc.push_back({ CborValue::String("id"), CborValue::Bytes(entry.id) });
            allowArr.push_back(CborValue::Map(desc));
        }
        params.push_back({ CborValue::Uint(0x03), CborValue::Array(allowArr) });
    }

    // 0x04: extensions
    if (request.useHmacSecret)
    {
        CborMap extensions;

        // hmac-secret extension value is a map:
        //   0x01: keyAgreement (COSE_Key — platform public key)
        //   0x02: saltEnc (encrypted salt)
        //   0x03: saltAuth (HMAC of encrypted salt)
        if (!request.hmacSecretSaltEnc.empty())
        {
            CborMap hmacSecretMap;

            // For simplified implementation: if keyAgreement is provided, include it
            if (!request.hmacSecretKeyAgreement.empty())
            {
                // Key agreement is a COSE_Key — we pass the pre-encoded bytes
                // In a full implementation, this would be constructed from EC public key
                CborValue keyAgreementVal;
                CborDecoder decoder;
                if (decoder.Decode(request.hmacSecretKeyAgreement.data(),
                    request.hmacSecretKeyAgreement.size(), keyAgreementVal))
                {
                    hmacSecretMap.push_back({ CborValue::Uint(0x01), keyAgreementVal });
                }
            }

            hmacSecretMap.push_back({ CborValue::Uint(0x02), CborValue::Bytes(request.hmacSecretSaltEnc) });
            hmacSecretMap.push_back({ CborValue::Uint(0x03), CborValue::Bytes(request.hmacSecretSaltAuth) });

            extensions.push_back({ CborValue::String("hmac-secret"), CborValue::Map(hmacSecretMap) });
        }
        else if (!request.hmacSecretSalt.empty())
        {
            // Simplified mode: just request hmac-secret = true
            extensions.push_back({ CborValue::String("hmac-secret"), CborValue::Bool(true) });
        }

        params.push_back({ CborValue::Uint(0x04), CborValue::Map(extensions) });
    }

    // 0x05: options
    if (request.hasOptionUP || request.hasOptionUV)
    {
        CborMap options;
        if (request.hasOptionUP)
            options.push_back({ CborValue::String("up"), CborValue::Bool(request.optionUP) });
        if (request.hasOptionUV)
            options.push_back({ CborValue::String("uv"), CborValue::Bool(request.optionUV) });
        params.push_back({ CborValue::Uint(0x05), CborValue::Map(options) });
    }

    // 0x06: pinUvAuthParam
    if (!request.pinUvAuthParam.empty())
    {
        params.push_back({ CborValue::Uint(0x06), CborValue::Bytes(request.pinUvAuthParam) });
    }

    // 0x07: pinUvAuthProtocol
    if (request.pinUvAuthProtocol > 0)
    {
        params.push_back({ CborValue::Uint(0x07), CborValue::Uint(request.pinUvAuthProtocol) });
    }

    // Encode
    CborEncoder encoder;
    if (!encoder.Encode(CborValue::Map(params)))
        return false;

    // Prepend command byte
    outCommandBytes.clear();
    outCommandBytes.push_back(CTAP2_CMD::GET_ASSERTION);
    outCommandBytes.insert(outCommandBytes.end(),
        encoder.GetData(), encoder.GetData() + encoder.GetSize());

    return true;
}

// ============================================================================
// ParseGetAssertionResponse
// ============================================================================

uint8_t CCtap2Protocol::ParseGetAssertionResponse(
    const uint8_t* responseData,
    size_t responseLen,
    Ctap2GetAssertionResponse& outResponse)
{
    if (responseData == nullptr || responseLen == 0)
        return CTAP2_ERR::OTHER;

    // First byte is status code
    uint8_t status = responseData[0];
    if (status != CTAP2_ERR::SUCCESS)
        return status;

    if (responseLen < 2)
        return CTAP2_ERR::INVALID_CBOR;

    // Decode CBOR payload (everything after status byte)
    CborDecoder decoder;
    CborValue root;
    if (!decoder.Decode(responseData + 1, responseLen - 1, root))
        return CTAP2_ERR::INVALID_CBOR;

    if (root.type != CborType::Map)
        return CTAP2_ERR::CBOR_UNEXPECTED_TYPE;

    // 0x01: credential
    const CborValue* pCred = root.MapLookup(static_cast<uint64_t>(0x01));
    if (pCred && pCred->type == CborType::Map)
    {
        const CborValue* pType = pCred->MapLookup("type");
        if (pType) outResponse.credential.type = pType->AsString();

        const CborValue* pId = pCred->MapLookup("id");
        if (pId) outResponse.credential.id = pId->AsBytes();
    }

    // 0x02: authData
    const CborValue* pAuthData = root.MapLookup(static_cast<uint64_t>(0x02));
    if (pAuthData && pAuthData->type == CborType::ByteString)
    {
        outResponse.authData = pAuthData->bytesVal;
        ParseAuthData(outResponse.authData, outResponse);
    }

    // 0x03: signature
    const CborValue* pSig = root.MapLookup(static_cast<uint64_t>(0x03));
    if (pSig && pSig->type == CborType::ByteString)
        outResponse.signature = pSig->bytesVal;

    // 0x04: user
    const CborValue* pUser = root.MapLookup(static_cast<uint64_t>(0x04));
    if (pUser && pUser->type == CborType::Map)
    {
        const CborValue* pId = pUser->MapLookup("id");
        if (pId) outResponse.user.id = pId->AsBytes();

        const CborValue* pName = pUser->MapLookup("name");
        if (pName) outResponse.user.name = pName->AsString();

        const CborValue* pDisplayName = pUser->MapLookup("displayName");
        if (pDisplayName) outResponse.user.displayName = pDisplayName->AsString();
    }

    // 0x05: numberOfCredentials
    const CborValue* pNum = root.MapLookup(static_cast<uint64_t>(0x05));
    if (pNum && pNum->type == CborType::UnsignedInt)
        outResponse.numberOfCredentials = static_cast<uint32_t>(pNum->uintVal);

    // Extensions in authData — parse hmac-secret output if present
    // The hmac-secret output is in the extensions section of authData (if ED flag set)
    // For simplicity, we also check if there's a top-level extension response
    // (some authenticators return it in the response map at key 0x06 or in authData extensions)

    return CTAP2_ERR::SUCCESS;
}

// ============================================================================
// ParseAuthData
// ============================================================================

bool CCtap2Protocol::ParseAuthData(
    const std::vector<uint8_t>& authData,
    Ctap2GetAssertionResponse& outResponse)
{
    // Authenticator data structure:
    //   rpIdHash:  32 bytes
    //   flags:     1 byte
    //   signCount: 4 bytes (big-endian)
    //   [attestedCredentialData] if flags.AT set
    //   [extensions] if flags.ED set

    if (authData.size() < 37)
        return false;

    outResponse.rpIdHash.assign(authData.begin(), authData.begin() + 32);
    outResponse.flags = authData[32];
    outResponse.signCount = (static_cast<uint32_t>(authData[33]) << 24) |
                            (static_cast<uint32_t>(authData[34]) << 16) |
                            (static_cast<uint32_t>(authData[35]) << 8) |
                            static_cast<uint32_t>(authData[36]);

    // If ED flag is set, there are CBOR-encoded extensions after the fixed header
    // (and after attested credential data if AT flag is set)
    if (outResponse.flagED())
    {
        size_t extOffset = 37;

        // Skip attested credential data if present (only in MakeCredential, not GetAssertion)
        // For GetAssertion, AT flag is typically not set

        if (extOffset < authData.size())
        {
            CborDecoder decoder;
            CborValue extMap;
            if (decoder.Decode(authData.data() + extOffset, authData.size() - extOffset, extMap))
            {
                if (extMap.type == CborType::Map)
                {
                    const CborValue* pHmacSecret = extMap.MapLookup("hmac-secret");
                    if (pHmacSecret && pHmacSecret->type == CborType::ByteString)
                    {
                        outResponse.hmacSecretOutput = pHmacSecret->bytesVal;
                    }
                }
            }
        }
    }

    return true;
}

// ============================================================================
// BuildMakeCredentialCommand
// ============================================================================

bool CCtap2Protocol::BuildMakeCredentialCommand(
    const Ctap2MakeCredentialRequest& request,
    std::vector<uint8_t>& outCommandBytes)
{
    CborMap params;

    // 0x01: clientDataHash
    params.push_back({ CborValue::Uint(0x01), CborValue::Bytes(request.clientDataHash) });

    // 0x02: rp
    CborMap rp;
    rp.push_back({ CborValue::String("id"), CborValue::String(request.rpId) });
    if (!request.rpName.empty())
        rp.push_back({ CborValue::String("name"), CborValue::String(request.rpName) });
    params.push_back({ CborValue::Uint(0x02), CborValue::Map(rp) });

    // 0x03: user
    CborMap user;
    user.push_back({ CborValue::String("id"), CborValue::Bytes(request.userId) });
    if (!request.userName.empty())
        user.push_back({ CborValue::String("name"), CborValue::String(request.userName) });
    if (!request.userDisplayName.empty())
        user.push_back({ CborValue::String("displayName"), CborValue::String(request.userDisplayName) });
    params.push_back({ CborValue::Uint(0x03), CborValue::Map(user) });

    // 0x04: pubKeyCredParams
    CborArray credParams;
    for (const auto& p : request.pubKeyCredParams)
    {
        CborMap cp;
        cp.push_back({ CborValue::String("type"), CborValue::String(p.type) });
        cp.push_back({ CborValue::String("alg"), CborValue::NegInt(p.alg) });
        credParams.push_back(CborValue::Map(cp));
    }
    params.push_back({ CborValue::Uint(0x04), CborValue::Array(credParams) });

    // 0x06: extensions
    if (request.useHmacSecret || request.credProtect > 0)
    {
        CborMap extensions;
        if (request.useHmacSecret)
            extensions.push_back({ CborValue::String("hmac-secret"), CborValue::Bool(true) });
        if (request.credProtect > 0)
            extensions.push_back({ CborValue::String("credProtect"), CborValue::Uint(request.credProtect) });
        params.push_back({ CborValue::Uint(0x06), CborValue::Map(extensions) });
    }

    // 0x07: options
    CborMap options;
    if (request.residentKey)
        options.push_back({ CborValue::String("rk"), CborValue::Bool(true) });
    if (request.userVerification)
        options.push_back({ CborValue::String("uv"), CborValue::Bool(true) });
    if (!options.empty())
        params.push_back({ CborValue::Uint(0x07), CborValue::Map(options) });

    // Encode
    CborEncoder encoder;
    if (!encoder.Encode(CborValue::Map(params)))
        return false;

    outCommandBytes.clear();
    outCommandBytes.push_back(CTAP2_CMD::MAKE_CREDENTIAL);
    outCommandBytes.insert(outCommandBytes.end(),
        encoder.GetData(), encoder.GetData() + encoder.GetSize());

    return true;
}

// ============================================================================
// BuildGetInfoCommand
// ============================================================================

bool CCtap2Protocol::BuildGetInfoCommand(std::vector<uint8_t>& outCommandBytes)
{
    outCommandBytes.clear();
    outCommandBytes.push_back(CTAP2_CMD::GET_INFO);
    return true;
}

// ============================================================================
// BuildClientPINGetKeyAgreementCommand
//   Encodes: authenticatorClientPIN( {0x01: protocol, 0x02: getKeyAgreement} )
// ============================================================================

bool CCtap2Protocol::BuildClientPINGetKeyAgreementCommand(
    std::vector<uint8_t>& outCommandBytes,
    uint8_t pinUvAuthProtocol)
{
    CborMap params;
    params.push_back({ CborValue::Uint(0x01), CborValue::Uint(pinUvAuthProtocol) });
    params.push_back({ CborValue::Uint(0x02), CborValue::Uint(CTAP2_CLIENT_PIN_CMD::GET_KEY_AGREEMENT) });

    CborEncoder enc;
    if (!enc.Encode(CborValue::Map(params))) return false;

    outCommandBytes.clear();
    outCommandBytes.push_back(CTAP2_CMD::CLIENT_PIN);
    outCommandBytes.insert(outCommandBytes.end(), enc.GetData(), enc.GetData() + enc.GetSize());
    return true;
}

// ============================================================================
// ParseClientPINKeyAgreementResponse
//   Response CBOR map: { 0x01: {1:2, 3:-25, -1:1, -2:<x32>, -3:<y32>} }
// ============================================================================

bool CCtap2Protocol::ParseClientPINKeyAgreementResponse(
    const uint8_t* responseData,
    size_t responseLen,
    uint8_t outX[32],
    uint8_t outY[32])
{
    if (!responseData || responseLen < 2) return false;
    if (responseData[0] != CTAP2_ERR::SUCCESS)   return false;

    CborDecoder dec;
    CborValue root;
    if (!dec.Decode(responseData + 1, responseLen - 1, root)) return false;
    if (root.type != CborType::Map) return false;

    // Key 0x01 = keyAgreement (COSE map)
    const CborValue* pKeyAgreement = root.MapLookup(static_cast<uint64_t>(0x01));
    if (!pKeyAgreement || pKeyAgreement->type != CborType::Map) return false;

    // Extract -2 (x) and -3 (y) from COSE map
    auto findBytes32 = [&](const CborValue& coseMap, int64_t negKey, uint8_t out[32]) -> bool {
        for (auto& kv : coseMap.mapVal)
        {
            int64_t k = 0;
            if (kv.first.type == CborType::UnsignedInt)  k = (int64_t)kv.first.uintVal;
            else if (kv.first.type == CborType::NegativeInt) k = kv.first.intVal;
            else continue;
            if (k != negKey) continue;
            if (kv.second.type != CborType::ByteString) return false;
            if (kv.second.bytesVal.size() != 32) return false;
            memcpy(out, kv.second.bytesVal.data(), 32);
            return true;
        }
        return false;
    };

    if (!findBytes32(*pKeyAgreement, -2, outX)) return false;
    if (!findBytes32(*pKeyAgreement, -3, outY)) return false;
    return true;
}

// ============================================================================
// GenerateChallenge
// ============================================================================

bool CCtap2Protocol::GenerateChallenge(std::vector<uint8_t>& outChallenge)
{
    outChallenge.resize(32);
    NTSTATUS status = BCryptGenRandom(
        NULL,
        outChallenge.data(),
        32,
        BCRYPT_USE_SYSTEM_PREFERRED_RNG
    );
    return BCRYPT_SUCCESS(status);
}

// ============================================================================
// StatusToString
// ============================================================================

const char* CCtap2Protocol::StatusToString(uint8_t status)
{
    switch (status)
    {
    case CTAP2_ERR::SUCCESS:                return "Success";
    case CTAP2_ERR::INVALID_COMMAND:        return "Invalid command";
    case CTAP2_ERR::INVALID_PARAMETER:      return "Invalid parameter";
    case CTAP2_ERR::INVALID_LENGTH:         return "Invalid length";
    case CTAP2_ERR::TIMEOUT:                return "Timeout";
    case CTAP2_ERR::CHANNEL_BUSY:           return "Channel busy";
    case CTAP2_ERR::INVALID_CBOR:           return "Invalid CBOR";
    case CTAP2_ERR::MISSING_PARAMETER:      return "Missing parameter";
    case CTAP2_ERR::NO_CREDENTIALS:         return "No credentials";
    case CTAP2_ERR::NOT_ALLOWED:            return "Not allowed";
    case CTAP2_ERR::PIN_INVALID:            return "PIN invalid";
    case CTAP2_ERR::PIN_BLOCKED:            return "PIN blocked";
    case CTAP2_ERR::PIN_AUTH_INVALID:       return "PIN auth invalid";
    case CTAP2_ERR::PIN_NOT_SET:            return "PIN not set";
    case CTAP2_ERR::PIN_REQUIRED:           return "PIN required";
    case CTAP2_ERR::UV_BLOCKED:             return "UV blocked";
    case CTAP2_ERR::OPERATION_DENIED:       return "Operation denied";
    case CTAP2_ERR::USER_ACTION_TIMEOUT:    return "User action timeout";
    default:                                return "Unknown error";
    }
}
