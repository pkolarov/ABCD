// CredentialVault.cpp
// DPAPI-encrypted credential store implementation for DDS Auth Bridge.
//

#include "CredentialVault.h"
#include "FileLog.h"
#include <wincrypt.h>
#include <bcrypt.h>
#include <shlobj.h>
#include <string.h>
#include <algorithm>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

// Simple binary serialization tag
static constexpr uint32_t VAULT_MAGIC   = 0x44445342; // "DDSB"
static constexpr uint32_t VAULT_VERSION = 1;

CCredentialVault::CCredentialVault()
{
    m_vaultPath = GetVaultFilePath();
}

CCredentialVault::~CCredentialVault()
{
    // Securely clear any in-memory data
    for (auto& entry : m_entries)
    {
        SecureZeroMemory(entry.encryptedPassword.data(), entry.encryptedPassword.size());
        SecureZeroMemory(entry.salt.data(), entry.salt.size());
    }
}

std::wstring CCredentialVault::GetVaultFilePath()
{
    // Tests can override the vault path via the DDS_VAULT_PATH environment
    // variable so that running them never touches the real vault file.
    wchar_t override[MAX_PATH] = {};
    DWORD n = GetEnvironmentVariableW(L"DDS_VAULT_PATH", override, MAX_PATH);
    if (n > 0 && n < MAX_PATH)
    {
        return std::wstring(override);
    }

    wchar_t path[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, path)))
    {
        std::wstring dir = std::wstring(path) + L"\\DDS";

        // Ensure directory exists
        CreateDirectoryW(dir.c_str(), NULL);

        return dir + L"\\vault.dat";
    }
    return L"C:\\ProgramData\\DDS\\vault.dat";
}

// ============================================================================
// Load / Save
// ============================================================================

bool CCredentialVault::Load()
{
    HANDLE hFile = CreateFileW(m_vaultPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        // File doesn't exist -- start with empty vault
        m_entries.clear();
        return true;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0 || fileSize == INVALID_FILE_SIZE)
    {
        CloseHandle(hFile);
        m_entries.clear();
        return true;
    }

    std::vector<uint8_t> encrypted(fileSize);
    DWORD bytesRead = 0;
    BOOL ok = ReadFile(hFile, encrypted.data(), fileSize, &bytesRead, NULL);
    CloseHandle(hFile);

    if (!ok || bytesRead != fileSize)
        return false;

    // DPAPI decrypt
    std::vector<uint8_t> plaintext;
    if (!DpapiDecrypt(encrypted, plaintext))
    {
        OutputDebugStringW(L"DdsAuthBridge: Vault: DPAPI decryption failed");
        return false;
    }

    // Deserialize
    if (!DeserializeFromBlob(plaintext))
    {
        OutputDebugStringW(L"DdsAuthBridge: Vault: Deserialization failed");
        SecureZeroMemory(plaintext.data(), plaintext.size());
        return false;
    }

    SecureZeroMemory(plaintext.data(), plaintext.size());
    return true;
}

bool CCredentialVault::Save()
{
    // Serialize
    std::vector<uint8_t> plaintext;
    if (!SerializeToBlob(plaintext))
        return false;

    // DPAPI encrypt
    std::vector<uint8_t> encrypted;
    if (!DpapiEncrypt(plaintext, encrypted))
    {
        SecureZeroMemory(plaintext.data(), plaintext.size());
        return false;
    }
    SecureZeroMemory(plaintext.data(), plaintext.size());

    // Write to file atomically (write to temp, then rename)
    std::wstring tempPath = m_vaultPath + L".tmp";
    HANDLE hFile = CreateFileW(tempPath.c_str(), GENERIC_WRITE, 0,
        NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    DWORD bytesWritten = 0;
    BOOL ok = WriteFile(hFile, encrypted.data(), static_cast<DWORD>(encrypted.size()),
        &bytesWritten, NULL);
    CloseHandle(hFile);

    if (!ok || bytesWritten != static_cast<DWORD>(encrypted.size()))
    {
        DeleteFileW(tempPath.c_str());
        return false;
    }

    // Atomic replace
    if (!MoveFileExW(tempPath.c_str(), m_vaultPath.c_str(), MOVEFILE_REPLACE_EXISTING))
    {
        DeleteFileW(tempPath.c_str());
        return false;
    }

    return true;
}

// ============================================================================
// Enrollment
// ============================================================================

bool CCredentialVault::EnrollUser(const VaultEntry& entry)
{
    // Remove existing entry for this SID + credential ID
    m_entries.erase(
        std::remove_if(m_entries.begin(), m_entries.end(),
            [&](const VaultEntry& e) {
                return e.userSid == entry.userSid && e.credentialId == entry.credentialId;
            }),
        m_entries.end()
    );

    m_entries.push_back(entry);
    return Save();
}

bool CCredentialVault::UnenrollUser(const std::wstring& userSid)
{
    size_t before = m_entries.size();
    m_entries.erase(
        std::remove_if(m_entries.begin(), m_entries.end(),
            [&](const VaultEntry& e) { return e.userSid == userSid; }),
        m_entries.end()
    );

    if (m_entries.size() != before)
        return Save();

    return true;
}

// ============================================================================
// Lookup
// ============================================================================

std::vector<const VaultEntry*> CCredentialVault::FindByUserSid(const std::wstring& userSid) const
{
    std::vector<const VaultEntry*> results;
    for (const auto& e : m_entries)
    {
        if (e.userSid == userSid)
            results.push_back(&e);
    }
    return results;
}

const VaultEntry* CCredentialVault::FindByCredentialId(const std::vector<uint8_t>& credId) const
{
    for (const auto& e : m_entries)
    {
        if (e.credentialId == credId)
            return &e;
    }
    return nullptr;
}

// ============================================================================
// AES-256-GCM Encrypt/Decrypt
// ============================================================================

bool CCredentialVault::EncryptPassword(
    const uint8_t* hmacSecretOutput,
    size_t hmacSecretLen,
    const wchar_t* password,
    VaultEntry& outEntry)
{
    if (hmacSecretOutput == nullptr || hmacSecretLen != 32 || password == nullptr)
        return false;

    // A-4 (security review): the previous build logged the first four bytes of the
    // FIDO2 hmac-secret-derived AES-GCM key plus the cleartext password length to
    // %ProgramData%\DDS\authbridge.log. The directory inherits BUILTIN\Users:Read on
    // most SKUs, so any local user could correlate per-logon prefixes of long-lived
    // authenticator-binding key material. The diagnostic is removed outright.

    // Convert password to bytes
    size_t pwLen = wcslen(password) * sizeof(wchar_t);
    const uint8_t* pwBytes = reinterpret_cast<const uint8_t*>(password);

    // Generate random IV (12 bytes for GCM)
    outEntry.iv.resize(12);
    NTSTATUS status = BCryptGenRandom(NULL, outEntry.iv.data(), 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status))
        return false;

    // Open AES-GCM
    BCRYPT_ALG_HANDLE hAlg = NULL;
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
        return false;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Import key
    BCRYPT_KEY_HANDLE hKey = NULL;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)hmacSecretOutput, static_cast<ULONG>(hmacSecretLen), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Prepare auth info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = outEntry.iv.data();
    authInfo.cbNonce = static_cast<ULONG>(outEntry.iv.size());

    outEntry.authTag.resize(16);
    authInfo.pbTag = outEntry.authTag.data();
    authInfo.cbTag = static_cast<ULONG>(outEntry.authTag.size());

    // Encrypt
    outEntry.encryptedPassword.resize(pwLen);
    ULONG cbResult = 0;
    status = BCryptEncrypt(hKey, (PUCHAR)pwBytes, static_cast<ULONG>(pwLen),
        &authInfo, NULL, 0,
        outEntry.encryptedPassword.data(), static_cast<ULONG>(outEntry.encryptedPassword.size()),
        &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status))
    {
        outEntry.encryptedPassword.clear();
        outEntry.iv.clear();
        outEntry.authTag.clear();
        return false;
    }

    outEntry.encryptedPassword.resize(cbResult);
    return true;
}

bool CCredentialVault::DecryptPassword(
    const uint8_t* hmacSecretOutput,
    size_t hmacSecretLen,
    const VaultEntry& entry,
    std::wstring& outPassword)
{
    FileLog::Writef("DecryptPassword: encPwdLen=%zu ivLen=%zu tagLen=%zu\n",
        entry.encryptedPassword.size(), entry.iv.size(), entry.authTag.size());
    // A-4 (security review): the previous build also logged the first four bytes of
    // the hmac-secret-derived key here. Removed — the size triple above is enough to
    // diagnose vault-entry shape issues without disclosing key material.

    if (hmacSecretOutput == nullptr || hmacSecretLen != 32)
        return false;

    if (entry.encryptedPassword.empty() || entry.iv.size() != 12 || entry.authTag.size() != 16)
    {
        FileLog::Writef("DecryptPassword: bad vault entry sizes\n");
        return false;
    }

    // Open AES-GCM
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
        return false;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Import key
    BCRYPT_KEY_HANDLE hKey = NULL;
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)hmacSecretOutput, static_cast<ULONG>(hmacSecretLen), 0);
    if (!BCRYPT_SUCCESS(status))
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    // Prepare auth info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = const_cast<uint8_t*>(entry.iv.data());
    authInfo.cbNonce = static_cast<ULONG>(entry.iv.size());
    authInfo.pbTag = const_cast<uint8_t*>(entry.authTag.data());
    authInfo.cbTag = static_cast<ULONG>(entry.authTag.size());

    // Decrypt
    std::vector<uint8_t> plaintext(entry.encryptedPassword.size());
    ULONG cbResult = 0;
    status = BCryptDecrypt(hKey,
        const_cast<uint8_t*>(entry.encryptedPassword.data()),
        static_cast<ULONG>(entry.encryptedPassword.size()),
        &authInfo, NULL, 0,
        plaintext.data(), static_cast<ULONG>(plaintext.size()),
        &cbResult, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status))
    {
        FileLog::Writef("DecryptPassword: BCryptDecrypt FAILED status=0x%08lX\n", (unsigned long)status);
        SecureZeroMemory(plaintext.data(), plaintext.size());
        return false;
    }

    FileLog::Writef("DecryptPassword: OK cbResult=%lu\n", cbResult);
    // Convert bytes back to wstring
    outPassword.assign(
        reinterpret_cast<const wchar_t*>(plaintext.data()),
        cbResult / sizeof(wchar_t)
    );

    SecureZeroMemory(plaintext.data(), plaintext.size());
    return true;
}

// ============================================================================
// DPAPI Wrappers
// ============================================================================

bool CCredentialVault::DpapiEncrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& outCiphertext)
{
    DATA_BLOB input;
    input.pbData = const_cast<uint8_t*>(plaintext.data());
    input.cbData = static_cast<DWORD>(plaintext.size());

    DATA_BLOB output = {};

    // CRYPTPROTECT_LOCAL_MACHINE: machine-scope protection (accessible by any user on this machine running as SYSTEM)
    if (!CryptProtectData(&input, L"DdsAuthBridgeVault", NULL, NULL, NULL,
        CRYPTPROTECT_LOCAL_MACHINE, &output))
    {
        return false;
    }

    outCiphertext.assign(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return true;
}

bool CCredentialVault::DpapiDecrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& outPlaintext)
{
    DATA_BLOB input;
    input.pbData = const_cast<uint8_t*>(ciphertext.data());
    input.cbData = static_cast<DWORD>(ciphertext.size());

    DATA_BLOB output = {};

    if (!CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output))
    {
        return false;
    }

    outPlaintext.assign(output.pbData, output.pbData + output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    return true;
}

// ============================================================================
// Serialization (simple binary format -- NOT using JSON to avoid dependencies)
// ============================================================================

// Helper: write a length-prefixed buffer
static void WriteVec(std::vector<uint8_t>& out, const std::vector<uint8_t>& v)
{
    uint32_t len = static_cast<uint32_t>(v.size());
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + 4);
    out.insert(out.end(), v.begin(), v.end());
}

static void WriteWStr(std::vector<uint8_t>& out, const std::wstring& s)
{
    uint32_t len = static_cast<uint32_t>(s.size() * sizeof(wchar_t));
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + 4);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(s.data());
    out.insert(out.end(), p, p + len);
}

static void WriteStr(std::vector<uint8_t>& out, const std::string& s)
{
    uint32_t len = static_cast<uint32_t>(s.size());
    out.insert(out.end(), reinterpret_cast<uint8_t*>(&len), reinterpret_cast<uint8_t*>(&len) + 4);
    out.insert(out.end(), s.begin(), s.end());
}

// Helper: read a length-prefixed buffer
static bool ReadVec(const uint8_t*& p, size_t& remaining, std::vector<uint8_t>& v)
{
    if (remaining < 4) return false;
    uint32_t len;
    memcpy(&len, p, 4); p += 4; remaining -= 4;
    if (remaining < len) return false;
    v.assign(p, p + len); p += len; remaining -= len;
    return true;
}

static bool ReadWStr(const uint8_t*& p, size_t& remaining, std::wstring& s)
{
    if (remaining < 4) return false;
    uint32_t len;
    memcpy(&len, p, 4); p += 4; remaining -= 4;
    if (remaining < len || len % sizeof(wchar_t) != 0) return false;
    s.assign(reinterpret_cast<const wchar_t*>(p), len / sizeof(wchar_t));
    p += len; remaining -= len;
    return true;
}

static bool ReadStr(const uint8_t*& p, size_t& remaining, std::string& s)
{
    if (remaining < 4) return false;
    uint32_t len;
    memcpy(&len, p, 4); p += 4; remaining -= 4;
    if (remaining < len) return false;
    s.assign(reinterpret_cast<const char*>(p), len); p += len; remaining -= len;
    return true;
}

bool CCredentialVault::SerializeToBlob(std::vector<uint8_t>& outBlob) const
{
    outBlob.clear();
    outBlob.reserve(4096);

    // Header
    uint32_t magic = VAULT_MAGIC;
    uint32_t version = VAULT_VERSION;
    uint32_t count = static_cast<uint32_t>(m_entries.size());
    outBlob.insert(outBlob.end(), reinterpret_cast<uint8_t*>(&magic), reinterpret_cast<uint8_t*>(&magic) + 4);
    outBlob.insert(outBlob.end(), reinterpret_cast<uint8_t*>(&version), reinterpret_cast<uint8_t*>(&version) + 4);
    outBlob.insert(outBlob.end(), reinterpret_cast<uint8_t*>(&count), reinterpret_cast<uint8_t*>(&count) + 4);

    for (const auto& e : m_entries)
    {
        WriteWStr(outBlob, e.userSid);
        WriteWStr(outBlob, e.displayName);
        WriteVec(outBlob, e.credentialId);
        WriteVec(outBlob, e.aaguid);
        WriteStr(outBlob, e.rpId);
        WriteWStr(outBlob, e.deviceSerial);
        WriteVec(outBlob, e.encryptedPassword);
        WriteVec(outBlob, e.salt);
        WriteVec(outBlob, e.iv);
        WriteVec(outBlob, e.authTag);

        outBlob.insert(outBlob.end(), reinterpret_cast<const uint8_t*>(&e.enrollmentTime),
            reinterpret_cast<const uint8_t*>(&e.enrollmentTime) + 8);
        outBlob.insert(outBlob.end(), reinterpret_cast<const uint8_t*>(&e.authMethod),
            reinterpret_cast<const uint8_t*>(&e.authMethod) + 4);
    }

    return true;
}

bool CCredentialVault::DeserializeFromBlob(const std::vector<uint8_t>& blob)
{
    m_entries.clear();

    const uint8_t* p = blob.data();
    size_t remaining = blob.size();

    if (remaining < 12) return false;

    uint32_t magic, version, count;
    memcpy(&magic, p, 4); p += 4; remaining -= 4;
    memcpy(&version, p, 4); p += 4; remaining -= 4;
    memcpy(&count, p, 4); p += 4; remaining -= 4;

    if (magic != VAULT_MAGIC || version != VAULT_VERSION)
        return false;

    if (count > 1000) // Sanity check
        return false;

    for (uint32_t i = 0; i < count; i++)
    {
        VaultEntry e;
        if (!ReadWStr(p, remaining, e.userSid)) return false;
        if (!ReadWStr(p, remaining, e.displayName)) return false;
        if (!ReadVec(p, remaining, e.credentialId)) return false;
        if (!ReadVec(p, remaining, e.aaguid)) return false;
        if (!ReadStr(p, remaining, e.rpId)) return false;
        if (!ReadWStr(p, remaining, e.deviceSerial)) return false;
        if (!ReadVec(p, remaining, e.encryptedPassword)) return false;
        if (!ReadVec(p, remaining, e.salt)) return false;
        if (!ReadVec(p, remaining, e.iv)) return false;
        if (!ReadVec(p, remaining, e.authTag)) return false;

        if (remaining < 12) return false;
        memcpy(&e.enrollmentTime, p, 8); p += 8; remaining -= 8;
        memcpy(&e.authMethod, p, 4); p += 4; remaining -= 4;

        m_entries.push_back(std::move(e));
    }

    return true;
}
