// CredentialVault.h
// DPAPI-encrypted credential store for the FIDO2 password derivation model.
//
// Stores encrypted Windows passwords that can only be decrypted with the
// hmac-secret output from the correct authenticator + user biometric.
//

#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <cstdint>

// One enrolled credential entry
struct VaultEntry
{
    // Identity
    std::wstring        userSid;                // Windows user SID (e.g., "S-1-5-21-...")
    std::wstring        displayName;            // User display name for tile

    // FIDO2 binding
    std::vector<uint8_t> credentialId;          // FIDO2 credential ID from MakeCredential
    std::vector<uint8_t> aaguid;                // Authenticator AAGUID (16 bytes)
    std::string         rpId;                   // Relying party ID ("dds.local")
    std::wstring        deviceSerial;           // Authenticator serial number

    // Encrypted password
    std::vector<uint8_t> encryptedPassword;     // AES-256-GCM encrypted Windows password
    std::vector<uint8_t> salt;                  // Salt for hmac-secret (32 bytes)
    std::vector<uint8_t> iv;                    // AES-GCM IV/nonce (12 bytes)
    std::vector<uint8_t> authTag;               // AES-GCM authentication tag (16 bytes)

    // Metadata
    uint64_t            enrollmentTime;         // FILETIME of enrollment
    uint32_t            authMethod;             // 1=FIDO2, 2=PIV
};

class CCredentialVault
{
public:
    CCredentialVault();
    ~CCredentialVault();

    // Load vault from disk. Creates empty vault if file doesn't exist.
    bool Load();

    // Save vault to disk.
    bool Save();

    // --- Enrollment ---

    // Add or update a vault entry for a user.
    bool EnrollUser(const VaultEntry& entry);

    // Remove a user's enrollment.
    bool UnenrollUser(const std::wstring& userSid);

    // --- Lookup ---

    // Get all enrolled entries.
    const std::vector<VaultEntry>& GetEntries() const { return m_entries; }

    // Find entries for a specific user SID.
    std::vector<const VaultEntry*> FindByUserSid(const std::wstring& userSid) const;

    // Find entry matching a credential ID.
    const VaultEntry* FindByCredentialId(const std::vector<uint8_t>& credId) const;

    // Get count of enrolled users.
    size_t GetUserCount() const { return m_entries.size(); }

    // --- Crypto ---

    // Encrypt a password using the hmac-secret output as the key.
    // hmacSecretOutput: 32-byte key from FIDO2 hmac-secret extension.
    // password: plaintext Windows password (UTF-16LE).
    // outEntry: receives encrypted password, iv, authTag.
    static bool EncryptPassword(
        const uint8_t* hmacSecretOutput,
        size_t hmacSecretLen,
        const wchar_t* password,
        VaultEntry& outEntry
    );

    // Decrypt a password using the hmac-secret output.
    // Returns the plaintext password. Caller must SecureZeroMemory after use.
    static bool DecryptPassword(
        const uint8_t* hmacSecretOutput,
        size_t hmacSecretLen,
        const VaultEntry& entry,
        std::wstring& outPassword
    );

private:
    std::vector<VaultEntry> m_entries;
    std::wstring m_vaultPath;

    // Vault file path: %ProgramData%\DDS\vault.dat
    std::wstring GetVaultFilePath();

    // Serialize/deserialize vault to/from DPAPI-protected blob
    bool SerializeToBlob(std::vector<uint8_t>& outBlob) const;
    bool DeserializeFromBlob(const std::vector<uint8_t>& blob);

    // DPAPI wrappers
    static bool DpapiEncrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& outCiphertext);
    static bool DpapiDecrypt(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& outPlaintext);
};
