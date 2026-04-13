// test_components.cpp
// Non-interactive unit tests for DDS credential pipeline components.
// No FIDO2 authenticator required — validates everything from encryption
// through KERB serialization and LsaLogonUser.
//
// Build: see build_test_components.bat
// Run:   test_components.exe [optional: password to test LsaLogonUser]

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <cstring>
#include <ntsecapi.h>
#include <sddl.h>
#include <lm.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#include "CredentialVault.h"
#include "FileLog.h"
#include "../DdsBridgeIPC/ipc_messages.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "netapi32.lib")

static int g_passed = 0;
static int g_failed = 0;

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
            g_failed++; \
            return; \
        } \
    } while(0)

#define TEST_PASS(name) \
    do { \
        printf("  PASS: %s\n", name); \
        g_passed++; \
    } while(0)

// ============================================================================
// Test 1: AES-256-GCM encrypt/decrypt roundtrip with known key
// ============================================================================
static void Test_AesGcmRoundtrip()
{
    printf("\n[Test 1] AES-256-GCM encrypt/decrypt roundtrip\n");

    // Simulate a 32-byte hmac-secret key
    uint8_t key[32];
    BCryptGenRandom(NULL, key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    const wchar_t* testPassword = L"MyP@ssw0rd!123";
    VaultEntry entry = {};

    bool ok = CCredentialVault::EncryptPassword(key, 32, testPassword, entry);
    TEST_ASSERT(ok, "EncryptPassword failed");
    TEST_ASSERT(!entry.encryptedPassword.empty(), "encrypted password is empty");
    TEST_ASSERT(entry.iv.size() == 12, "IV should be 12 bytes");
    TEST_ASSERT(entry.authTag.size() == 16, "authTag should be 16 bytes");

    // Decrypt with same key
    std::wstring decrypted;
    ok = CCredentialVault::DecryptPassword(key, 32, entry, decrypted);
    TEST_ASSERT(ok, "DecryptPassword failed");
    TEST_ASSERT(decrypted == testPassword, "decrypted password mismatch");

    SecureZeroMemory(&decrypted[0], decrypted.size() * sizeof(wchar_t));
    TEST_PASS("AES-GCM encrypt/decrypt roundtrip");
}

// ============================================================================
// Test 2: AES-GCM decrypt with wrong key fails (auth tag mismatch)
// ============================================================================
static void Test_AesGcmWrongKey()
{
    printf("\n[Test 2] AES-256-GCM wrong key rejection\n");

    uint8_t key1[32], key2[32];
    BCryptGenRandom(NULL, key1, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, key2, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    VaultEntry entry = {};
    bool ok = CCredentialVault::EncryptPassword(key1, 32, L"TestPassword", entry);
    TEST_ASSERT(ok, "EncryptPassword failed");

    // Decrypt with different key should fail
    std::wstring decrypted;
    ok = CCredentialVault::DecryptPassword(key2, 32, entry, decrypted);
    TEST_ASSERT(!ok, "DecryptPassword should fail with wrong key");

    TEST_PASS("Wrong key correctly rejected");
}

// ============================================================================
// Test 3: Password encoding preserved through encrypt/decrypt
// ============================================================================
static void Test_PasswordEncoding()
{
    printf("\n[Test 3] Password encoding (UTF-16LE) preservation\n");

    uint8_t key[32];
    BCryptGenRandom(NULL, key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // Test various password patterns
    const wchar_t* passwords[] = {
        L"simple",
        L"P@$$w0rd!",
        L"a",  // single char
        L"1234567890123456789012345678901234567890",  // 40 chars
        L"\x00e9\x00f1\x00fc",  // accented chars: éñü
    };
    int numPasswords = sizeof(passwords) / sizeof(passwords[0]);

    for (int i = 0; i < numPasswords; i++)
    {
        VaultEntry entry = {};
        bool ok = CCredentialVault::EncryptPassword(key, 32, passwords[i], entry);

        if (!ok) {
            printf("  FAIL: EncryptPassword failed for password[%d]\n", i);
            g_failed++;
            return;
        }

        std::wstring decrypted;
        ok = CCredentialVault::DecryptPassword(key, 32, entry, decrypted);
        if (!ok || decrypted != passwords[i]) {
            printf("  FAIL: roundtrip mismatch for password[%d] (len=%zu vs %zu)\n",
                i, decrypted.size(), wcslen(passwords[i]));
            g_failed++;
            return;
        }

        if (!decrypted.empty())
            SecureZeroMemory(&decrypted[0], decrypted.size() * sizeof(wchar_t));
    }

    TEST_PASS("Password encoding preservation (multiple patterns)");
}

// ============================================================================
// Test 4: Vault serialization roundtrip
// ============================================================================
static void Test_VaultSerializationRoundtrip()
{
    printf("\n[Test 4] Vault serialization roundtrip\n");

    // Use a temp file for the vault — must set env var BEFORE constructing vault
    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    std::wstring vaultPath = std::wstring(tempDir) + L"dds_test_vault.dat";

    // Set env var FIRST so CCredentialVault constructor picks it up
    SetEnvironmentVariableW(L"DDS_VAULT_PATH", vaultPath.c_str());

    // Clean up any existing file
    DeleteFileW(vaultPath.c_str());

    // Create a vault with test entries
    {
        CCredentialVault vault;

        VaultEntry e1 = {};
        e1.userSid = L"S-1-5-21-1234567890-1234567890-1234567890-1001";
        e1.displayName = L"Test User 1";
        e1.credentialId = {0x01, 0x02, 0x03, 0x04, 0x05};
        e1.aaguid = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                     0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF};
        e1.rpId = "dds.local";
        e1.deviceSerial = L"YK-001";
        e1.encryptedPassword = {0x10, 0x20, 0x30, 0x40};
        e1.salt.resize(32);
        BCryptGenRandom(NULL, e1.salt.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        e1.iv = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C};
        e1.authTag.resize(16, 0xEE);
        e1.enrollmentTime = 1700000000ULL;
        e1.authMethod = 1;

        bool ok1 = vault.EnrollUser(e1);
        printf("  EnrollUser(e1) = %s, count=%zu\n", ok1 ? "true" : "false", vault.GetUserCount());

        VaultEntry e2 = {};
        e2.userSid = L"S-1-5-21-9999999999-8888888888-7777777777-1002";
        e2.displayName = L"Test User 2";
        e2.credentialId = {0x0A, 0x0B, 0x0C};
        e2.rpId = "dds.local";
        e2.salt.resize(32, 0x55);
        e2.iv.resize(12, 0x33);
        e2.authTag.resize(16, 0x77);
        e2.encryptedPassword = {0xDE, 0xAD};
        e2.enrollmentTime = 1700001000ULL;
        e2.authMethod = 1;

        bool ok2 = vault.EnrollUser(e2);
        printf("  EnrollUser(e2) = %s, count=%zu\n", ok2 ? "true" : "false", vault.GetUserCount());

        bool saved = vault.Save();
        if (!saved) {
            printf("  Vault save failed. Path: %ls\n", vaultPath.c_str());
            printf("  GetLastError: %lu\n", GetLastError());
        }
        TEST_ASSERT(saved, "Vault Save failed");
        TEST_ASSERT(vault.GetUserCount() == 2, "Expected 2 entries after save");
    }

    // Load in a new vault instance
    {
        CCredentialVault vault2;
        bool loaded = vault2.Load();
        TEST_ASSERT(loaded, "Vault Load failed");
        TEST_ASSERT(vault2.GetUserCount() == 2, "Expected 2 entries after load");

        auto results = vault2.FindByUserSid(L"S-1-5-21-1234567890-1234567890-1234567890-1001");
        TEST_ASSERT(results.size() == 1, "Expected 1 entry for SID 1001");

        const VaultEntry* e = results[0];
        TEST_ASSERT(e->displayName == L"Test User 1", "displayName mismatch");
        TEST_ASSERT(e->credentialId.size() == 5, "credentialId size mismatch");
        TEST_ASSERT(e->credentialId[0] == 0x01, "credentialId[0] mismatch");
        TEST_ASSERT(e->aaguid.size() == 16, "aaguid size mismatch");
        TEST_ASSERT(e->rpId == "dds.local", "rpId mismatch");
        TEST_ASSERT(e->deviceSerial == L"YK-001", "deviceSerial mismatch");
        TEST_ASSERT(e->iv.size() == 12, "iv size mismatch");
        TEST_ASSERT(e->authTag.size() == 16, "authTag size mismatch");
        TEST_ASSERT(e->enrollmentTime == 1700000000ULL, "enrollmentTime mismatch");
        TEST_ASSERT(e->authMethod == 1, "authMethod mismatch");

        // Test FindByCredentialId
        std::vector<uint8_t> searchId = {0x0A, 0x0B, 0x0C};
        auto found = vault2.FindByCredentialId(searchId);
        TEST_ASSERT(found != nullptr, "FindByCredentialId failed");
        TEST_ASSERT(found->displayName == L"Test User 2", "Wrong entry found by credId");
    }

    // Cleanup
    DeleteFileW(vaultPath.c_str());
    SetEnvironmentVariableW(L"DDS_VAULT_PATH", NULL);

    TEST_PASS("Vault serialization roundtrip (save + load + lookup)");
}

// ============================================================================
// Test 5: URN-to-SID extraction (same logic as DdsAuthBridgeMain)
// ============================================================================
static std::wstring ExtractSidFromUrn(const std::wstring& urn)
{
    size_t prefixEnd = urn.rfind(L':');
    size_t dotPos = urn.rfind(L'.');
    if (prefixEnd != std::wstring::npos && dotPos != std::wstring::npos && dotPos > prefixEnd + 1)
    {
        return urn.substr(prefixEnd + 1, dotPos - prefixEnd - 1);
    }
    return urn; // fallback
}

static void Test_UrnToSid()
{
    printf("\n[Test 5] URN-to-SID extraction\n");

    // Normal user URN
    {
        std::wstring urn = L"urn:vouchsafe:S-1-5-21-1234567890-1234567890-1234567890-1001.abc123";
        std::wstring sid = ExtractSidFromUrn(urn);
        TEST_ASSERT(sid == L"S-1-5-21-1234567890-1234567890-1234567890-1001",
            "SID extraction failed for normal URN");
    }

    // Admin URN
    {
        std::wstring urn = L"urn:vouchsafe:admin.ostp4wy6c6ip6675iw6akh6yrz6dgw2t4dy2jqzvmjntlfpvf3qa";
        std::wstring sid = ExtractSidFromUrn(urn);
        TEST_ASSERT(sid == L"admin", "SID extraction failed for admin URN");
    }

    // Short URN (no dots -> fallback to full URN)
    {
        std::wstring urn = L"urn:vouchsafe:nodot";
        std::wstring sid = ExtractSidFromUrn(urn);
        TEST_ASSERT(sid == urn, "Should fallback to full URN when no dot");
    }

    // URN with extra dots in SID (shouldn't happen but test edge case)
    // rfind('.') finds the last dot, which is what we want
    {
        std::wstring urn = L"urn:vouchsafe:S-1-5-21-123.456.hashvalue";
        std::wstring sid = ExtractSidFromUrn(urn);
        // Last dot is before "hashvalue", last colon is before "S-1-5-21-123.456.hashvalue"
        // So sid = "S-1-5-21-123.456" — this is correct for the rfind logic
        TEST_ASSERT(sid == L"S-1-5-21-123.456", "Edge case: dots in SID portion");
    }

    TEST_PASS("URN-to-SID extraction (4 cases)");
}

// ============================================================================
// Test 6: IPC struct sizes and alignment (pack(1))
// ============================================================================
static void Test_IpcStructLayout()
{
    printf("\n[Test 6] IPC struct sizes and field offsets\n");

    // DDS_AUTH_COMPLETE is the critical one — password field must be at the right offset
    IPC_RESP_DDS_AUTH_COMPLETE authComplete = {};
    authComplete.success = TRUE;
    wcscpy_s(authComplete.domain, L"TESTDOMAIN");
    wcscpy_s(authComplete.username, L"testuser");
    wcscpy_s(authComplete.password, L"MyP@ssw0rd");

    // Verify field positions by checking the data through raw memory
    const BYTE* raw = reinterpret_cast<const BYTE*>(&authComplete);

    // success is first field (4 bytes = BOOL)
    BOOL success;
    memcpy(&success, raw, sizeof(BOOL));
    TEST_ASSERT(success == TRUE, "success field position wrong");

    // domain follows success
    const WCHAR* domainPtr = reinterpret_cast<const WCHAR*>(raw + sizeof(BOOL));
    TEST_ASSERT(wcscmp(domainPtr, L"TESTDOMAIN") == 0, "domain field position wrong");

    // username follows domain
    const WCHAR* usernamePtr = reinterpret_cast<const WCHAR*>(
        raw + sizeof(BOOL) + IPC_MAX_DOMAIN_LEN * sizeof(WCHAR));
    TEST_ASSERT(wcscmp(usernamePtr, L"testuser") == 0, "username field position wrong");

    // password follows username
    const WCHAR* passwordPtr = reinterpret_cast<const WCHAR*>(
        raw + sizeof(BOOL) + (IPC_MAX_DOMAIN_LEN + IPC_MAX_USERNAME_LEN) * sizeof(WCHAR));
    TEST_ASSERT(wcscmp(passwordPtr, L"MyP@ssw0rd") == 0, "password field position wrong");

    // Verify struct is packed correctly (no padding between fields)
    size_t expectedOffset = sizeof(BOOL) +
        (IPC_MAX_DOMAIN_LEN + IPC_MAX_USERNAME_LEN + IPC_MAX_PASSWORD_LEN) * sizeof(WCHAR);
    size_t sessionOffset = offsetof(IPC_RESP_DDS_AUTH_COMPLETE, session_token);
    TEST_ASSERT(sessionOffset == expectedOffset,
        "session_token offset mismatch — struct may have unexpected padding");

    printf("  IPC_RESP_DDS_AUTH_COMPLETE: size=%zu\n", sizeof(IPC_RESP_DDS_AUTH_COMPLETE));
    printf("  password offset=%zu (expected=%zu)\n",
        offsetof(IPC_RESP_DDS_AUTH_COMPLETE, password),
        sizeof(BOOL) + (IPC_MAX_DOMAIN_LEN + IPC_MAX_USERNAME_LEN) * sizeof(WCHAR));

    TEST_PASS("IPC struct layout verification");
}

// ============================================================================
// Test 7: IPC password survives memcpy (simulates pipe transfer)
// ============================================================================
static void Test_IpcPasswordTransfer()
{
    printf("\n[Test 7] IPC password survives memcpy (simulates pipe transfer)\n");

    const wchar_t* testPassword = L"MyP@ssw0rd!123";

    // Simulate bridge side: fill AUTH_COMPLETE
    IPC_RESP_DDS_AUTH_COMPLETE sendBuf = {};
    sendBuf.success = TRUE;
    wcscpy_s(sendBuf.domain, L"WIN-TESTPC");
    wcscpy_s(sendBuf.username, L"PK");
    wcsncpy_s(sendBuf.password, testPassword, _TRUNCATE);

    // Simulate pipe transfer: raw memcpy
    IPC_RESP_DDS_AUTH_COMPLETE recvBuf = {};
    memcpy(&recvBuf, &sendBuf, sizeof(IPC_RESP_DDS_AUTH_COMPLETE));

    TEST_ASSERT(recvBuf.success == TRUE, "success lost in transfer");
    TEST_ASSERT(wcscmp(recvBuf.domain, L"WIN-TESTPC") == 0, "domain lost in transfer");
    TEST_ASSERT(wcscmp(recvBuf.username, L"PK") == 0, "username lost in transfer");
    TEST_ASSERT(wcscmp(recvBuf.password, testPassword) == 0, "password lost in transfer");

    // Verify password encoding byte-by-byte (UTF-16LE)
    size_t pwdLen = wcslen(testPassword);
    const uint8_t* pwdBytes = reinterpret_cast<const uint8_t*>(recvBuf.password);
    const uint8_t* expectedBytes = reinterpret_cast<const uint8_t*>(testPassword);
    bool bytesMatch = memcmp(pwdBytes, expectedBytes, pwdLen * sizeof(wchar_t)) == 0;
    TEST_ASSERT(bytesMatch, "password bytes differ after transfer");

    // Verify null terminator is present
    TEST_ASSERT(recvBuf.password[pwdLen] == L'\0', "password null terminator missing");

    TEST_PASS("IPC password transfer (memcpy roundtrip)");
}

// ============================================================================
// Test 8: KERB_INTERACTIVE_LOGON packing validation
// ============================================================================

// Minimal reimplementation of UnicodeStringInitWithString
static void InitUnicodeString(PCWSTR str, UNICODE_STRING* pus)
{
    USHORT len = (USHORT)(wcslen(str) * sizeof(WCHAR));
    pus->Length = len;
    pus->MaximumLength = len;
    pus->Buffer = const_cast<PWSTR>(str);
}

static void Test_KerbPacking()
{
    printf("\n[Test 8] KERB_INTERACTIVE_LOGON packing validation\n");

    wchar_t domain[] = L"WIN-TESTPC";
    wchar_t user[] = L"PK";
    wchar_t password[] = L"TestPass1";

    // Build KERB_INTERACTIVE_UNLOCK_LOGON (like KerbInteractiveUnlockLogonInit does)
    KERB_INTERACTIVE_UNLOCK_LOGON kiul = {};
    KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;
    pkil->MessageType = KerbInteractiveLogon;

    InitUnicodeString(domain, &pkil->LogonDomainName);
    InitUnicodeString(user, &pkil->UserName);
    InitUnicodeString(password, &pkil->Password);

    // Pack it (same as KerbInteractiveUnlockLogonPack)
    DWORD cb = sizeof(kiul) +
        pkil->LogonDomainName.Length +
        pkil->UserName.Length +
        pkil->Password.Length;

    std::vector<BYTE> packed(cb);
    KERB_INTERACTIVE_UNLOCK_LOGON* pOut = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(packed.data());
    ZeroMemory(&pOut->LogonId, sizeof(pOut->LogonId));

    BYTE* pbBuffer = packed.data() + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    KERB_INTERACTIVE_LOGON* pkilOut = &pOut->Logon;
    pkilOut->MessageType = pkil->MessageType;

    // Pack domain
    memcpy(pbBuffer, pkil->LogonDomainName.Buffer, pkil->LogonDomainName.Length);
    pkilOut->LogonDomainName.Length = pkil->LogonDomainName.Length;
    pkilOut->LogonDomainName.MaximumLength = pkil->LogonDomainName.Length;
    pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - packed.data());
    pbBuffer += pkil->LogonDomainName.Length;

    // Pack username
    memcpy(pbBuffer, pkil->UserName.Buffer, pkil->UserName.Length);
    pkilOut->UserName.Length = pkil->UserName.Length;
    pkilOut->UserName.MaximumLength = pkil->UserName.Length;
    pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - packed.data());
    pbBuffer += pkil->UserName.Length;

    // Pack password
    memcpy(pbBuffer, pkil->Password.Buffer, pkil->Password.Length);
    pkilOut->Password.Length = pkil->Password.Length;
    pkilOut->Password.MaximumLength = pkil->Password.Length;
    pkilOut->Password.Buffer = (PWSTR)(pbBuffer - packed.data());

    // Validate the packed buffer
    TEST_ASSERT(pkilOut->MessageType == KerbInteractiveLogon, "MessageType wrong");

    // Unpack domain from the buffer to verify
    DWORD domainOffset = (DWORD)(ULONG_PTR)pkilOut->LogonDomainName.Buffer;
    USHORT domainLen = pkilOut->LogonDomainName.Length;
    std::wstring unpackedDomain(reinterpret_cast<const wchar_t*>(packed.data() + domainOffset),
                                 domainLen / sizeof(wchar_t));
    TEST_ASSERT(unpackedDomain == L"WIN-TESTPC", "Unpacked domain mismatch");

    // Unpack username
    DWORD userOffset = (DWORD)(ULONG_PTR)pkilOut->UserName.Buffer;
    USHORT userLen = pkilOut->UserName.Length;
    std::wstring unpackedUser(reinterpret_cast<const wchar_t*>(packed.data() + userOffset),
                               userLen / sizeof(wchar_t));
    TEST_ASSERT(unpackedUser == L"PK", "Unpacked username mismatch");

    // Unpack password
    DWORD pwdOffset = (DWORD)(ULONG_PTR)pkilOut->Password.Buffer;
    USHORT pwdLen = pkilOut->Password.Length;
    std::wstring unpackedPwd(reinterpret_cast<const wchar_t*>(packed.data() + pwdOffset),
                              pwdLen / sizeof(wchar_t));
    TEST_ASSERT(unpackedPwd == L"TestPass1", "Unpacked password mismatch");

    printf("  packed buffer: %lu bytes (struct=%zu + strings=%u+%u+%u)\n",
        cb, sizeof(kiul), pkil->LogonDomainName.Length, pkil->UserName.Length, pkil->Password.Length);

    SecureZeroMemory(packed.data(), packed.size());
    TEST_PASS("KERB_INTERACTIVE_LOGON packing validation");
}

// ============================================================================
// Test 9: LsaLogonUser with real credentials (requires password argument)
// ============================================================================
static void Test_LsaLogonUser(const wchar_t* realPassword)
{
    printf("\n[Test 9] LsaLogonUser with real credentials\n");

    if (!realPassword || realPassword[0] == L'\0')
    {
        printf("  SKIP: pass your Windows password as argument to test LsaLogonUser\n");
        return;
    }

    // Get current computer name and username
    wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD compLen = ARRAYSIZE(compName);
    TEST_ASSERT(GetComputerNameW(compName, &compLen), "GetComputerName failed");

    wchar_t userName[256];
    DWORD userLen = ARRAYSIZE(userName);
    TEST_ASSERT(GetUserNameW(userName, &userLen), "GetUserName failed");

    printf("  domain='%ls' user='%ls' pwdLen=%zu\n",
        compName, userName, wcslen(realPassword));

    // Connect to LSA
    HANDLE hLsa = NULL;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    TEST_ASSERT(NT_SUCCESS(status), "LsaConnectUntrusted failed");

    // Look up Negotiate package
    LSA_STRING lsaPackageName;
    lsaPackageName.Buffer = (PCHAR)"Negotiate";
    lsaPackageName.Length = 9;
    lsaPackageName.MaximumLength = 10;

    ULONG authPackage = 0;
    status = LsaLookupAuthenticationPackage(hLsa, &lsaPackageName, &authPackage);
    if (!NT_SUCCESS(status))
    {
        printf("  FAIL: LsaLookupAuthenticationPackage status=0x%08lX\n", status);
        LsaDeregisterLogonProcess(hLsa);
        g_failed++;
        return;
    }
    printf("  authPackage=%lu\n", authPackage);

    // Build KERB_INTERACTIVE_UNLOCK_LOGON
    KERB_INTERACTIVE_UNLOCK_LOGON kiul = {};
    KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;
    pkil->MessageType = KerbInteractiveLogon;

    InitUnicodeString(compName, &pkil->LogonDomainName);
    InitUnicodeString(userName, &pkil->UserName);
    InitUnicodeString(realPassword, &pkil->Password);

    // Pack
    DWORD cb = sizeof(kiul) +
        pkil->LogonDomainName.Length +
        pkil->UserName.Length +
        pkil->Password.Length;

    BYTE* pPacked = (BYTE*)CoTaskMemAlloc(cb);
    TEST_ASSERT(pPacked != nullptr, "CoTaskMemAlloc failed");

    KERB_INTERACTIVE_UNLOCK_LOGON* pOut = reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(pPacked);
    ZeroMemory(&pOut->LogonId, sizeof(pOut->LogonId));

    BYTE* pbBuffer = pPacked + sizeof(KERB_INTERACTIVE_UNLOCK_LOGON);
    KERB_INTERACTIVE_LOGON* pkilOut = &pOut->Logon;
    pkilOut->MessageType = pkil->MessageType;

    memcpy(pbBuffer, pkil->LogonDomainName.Buffer, pkil->LogonDomainName.Length);
    pkilOut->LogonDomainName.Length = pkil->LogonDomainName.Length;
    pkilOut->LogonDomainName.MaximumLength = pkil->LogonDomainName.Length;
    pkilOut->LogonDomainName.Buffer = (PWSTR)(pbBuffer - pPacked);
    pbBuffer += pkil->LogonDomainName.Length;

    memcpy(pbBuffer, pkil->UserName.Buffer, pkil->UserName.Length);
    pkilOut->UserName.Length = pkil->UserName.Length;
    pkilOut->UserName.MaximumLength = pkil->UserName.Length;
    pkilOut->UserName.Buffer = (PWSTR)(pbBuffer - pPacked);
    pbBuffer += pkil->UserName.Length;

    memcpy(pbBuffer, pkil->Password.Buffer, pkil->Password.Length);
    pkilOut->Password.Length = pkil->Password.Length;
    pkilOut->Password.MaximumLength = pkil->Password.Length;
    pkilOut->Password.Buffer = (PWSTR)(pbBuffer - pPacked);

    // Call LsaLogonUser
    LSA_STRING originName;
    originName.Buffer = (PCHAR)"DdsTest";
    originName.Length = 7;
    originName.MaximumLength = 8;

    TOKEN_SOURCE tokenSource;
    memcpy(tokenSource.SourceName, "DdsTest", 8);
    AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);

    PVOID profileBuffer = NULL;
    ULONG profileLen = 0;
    LUID logonId = {};
    HANDLE hToken = NULL;
    QUOTA_LIMITS quotas = {};
    NTSTATUS subStatus = 0;

    status = LsaLogonUser(
        hLsa,
        &originName,
        Interactive,          // SECURITY_LOGON_TYPE
        authPackage,
        pPacked,
        cb,
        NULL,                 // LocalGroups
        &tokenSource,
        &profileBuffer,
        &profileLen,
        &logonId,
        &hToken,
        &quotas,
        &subStatus
    );

    // Clean up packed buffer
    SecureZeroMemory(pPacked, cb);
    CoTaskMemFree(pPacked);

    if (NT_SUCCESS(status))
    {
        printf("  LsaLogonUser SUCCEEDED! logonId=%lu:%lu\n",
            logonId.HighPart, logonId.LowPart);
        if (profileBuffer)
            LsaFreeReturnBuffer(profileBuffer);
        if (hToken)
            CloseHandle(hToken);
        TEST_PASS("LsaLogonUser with real credentials");
    }
    else
    {
        // Map NTSTATUS to meaningful error
        ULONG win32status = LsaNtStatusToWinError(status);
        printf("  FAIL: LsaLogonUser status=0x%08lX subStatus=0x%08lX win32=%lu\n",
            status, subStatus, win32status);

        if (status == 0xC000006DL) // STATUS_LOGON_FAILURE
            printf("  -> STATUS_LOGON_FAILURE: incorrect password or username\n");
        else if (status == 0xC000006AL) // STATUS_WRONG_PASSWORD
            printf("  -> STATUS_WRONG_PASSWORD: password is incorrect\n");
        else if (status == 0xC0000064L) // STATUS_NO_SUCH_USER
            printf("  -> STATUS_NO_SUCH_USER: username not found\n");
        else if (status == 0xC000015BL) // STATUS_LOGON_TYPE_NOT_GRANTED
            printf("  -> STATUS_LOGON_TYPE_NOT_GRANTED: user doesn't have interactive logon right\n");
        else if (status == 0xC000006EL) // STATUS_ACCOUNT_RESTRICTION
            printf("  -> STATUS_ACCOUNT_RESTRICTION: account policy prevents logon\n");

        g_failed++;
    }

    LsaDeregisterLogonProcess(hLsa);
}

// ============================================================================
// Test 10: Full pipeline — encrypt with known key, simulate IPC transfer,
//          then verify the received password works.
// ============================================================================
static void Test_FullPipeline()
{
    printf("\n[Test 10] Full pipeline: encrypt → IPC → verify password\n");

    const wchar_t* testPassword = L"P@$$w0rd!XyZ";

    // Simulate hmac-secret key
    uint8_t hmacKey[32];
    BCryptGenRandom(NULL, hmacKey, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // Step 1: Encrypt (simulates enrollment)
    VaultEntry entry = {};
    bool ok = CCredentialVault::EncryptPassword(hmacKey, 32, testPassword, entry);
    TEST_ASSERT(ok, "Pipeline: EncryptPassword failed");

    // Step 2: Decrypt (simulates auth bridge)
    std::wstring decryptedPwd;
    ok = CCredentialVault::DecryptPassword(hmacKey, 32, entry, decryptedPwd);
    TEST_ASSERT(ok, "Pipeline: DecryptPassword failed");
    TEST_ASSERT(decryptedPwd == testPassword, "Pipeline: decrypted password mismatch");

    // Step 3: Fill IPC_RESP_DDS_AUTH_COMPLETE (simulates bridge sending to CP)
    IPC_RESP_DDS_AUTH_COMPLETE authComplete = {};
    authComplete.success = TRUE;
    wcscpy_s(authComplete.domain, L"TESTPC");
    wcscpy_s(authComplete.username, L"testuser");
    wcsncpy_s(authComplete.password, decryptedPwd.c_str(), _TRUNCATE);
    SecureZeroMemory(&decryptedPwd[0], decryptedPwd.size() * sizeof(wchar_t));

    // Step 4: Simulate pipe transfer
    IPC_RESP_DDS_AUTH_COMPLETE received = {};
    memcpy(&received, &authComplete, sizeof(authComplete));
    SecureZeroMemory(&authComplete, sizeof(authComplete));

    // Step 5: Verify the received password matches original
    TEST_ASSERT(wcscmp(received.password, testPassword) == 0,
        "Pipeline: password differs after full pipeline");

    printf("  password survived: encrypt → decrypt → IPC fill → memcpy\n");

    SecureZeroMemory(&received, sizeof(received));
    TEST_PASS("Full pipeline roundtrip");
}

// ============================================================================
// Test 11: SID resolution (ConvertStringSidToSid + LookupAccountSid)
// ============================================================================
static void Test_SidResolution()
{
    printf("\n[Test 11] SID resolution via ConvertStringSidToSid + LookupAccountSid\n");

    // Get current user's SID
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        printf("  SKIP: cannot open process token\n");
        return;
    }

    DWORD tokenInfoLen = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLen);
    std::vector<BYTE> tokenInfo(tokenInfoLen);
    if (!GetTokenInformation(hToken, TokenUser, tokenInfo.data(), tokenInfoLen, &tokenInfoLen))
    {
        CloseHandle(hToken);
        printf("  SKIP: GetTokenInformation failed\n");
        return;
    }
    CloseHandle(hToken);

    TOKEN_USER* pUser = reinterpret_cast<TOKEN_USER*>(tokenInfo.data());
    LPWSTR sidStr = NULL;
    if (!ConvertSidToStringSidW(pUser->User.Sid, &sidStr))
    {
        printf("  SKIP: ConvertSidToStringSid failed\n");
        return;
    }

    printf("  Current user SID: %ls\n", sidStr);

    // Now do what the bridge does: ConvertStringSidToSid → LookupAccountSid
    PSID pSid = NULL;
    TEST_ASSERT(ConvertStringSidToSidW(sidStr, &pSid), "ConvertStringSidToSid failed");

    WCHAR userName[256], domainName[256];
    DWORD userLen = ARRAYSIZE(userName), domLen = ARRAYSIZE(domainName);
    SID_NAME_USE sidUse;
    TEST_ASSERT(LookupAccountSidW(NULL, pSid, userName, &userLen, domainName, &domLen, &sidUse),
        "LookupAccountSid failed");

    printf("  Resolved: domain='%ls' user='%ls'\n", domainName, userName);

    // Verify it matches GetUserName/GetComputerName
    wchar_t currentUser[256];
    DWORD currentUserLen = ARRAYSIZE(currentUser);
    GetUserNameW(currentUser, &currentUserLen);
    TEST_ASSERT(_wcsicmp(userName, currentUser) == 0, "Username mismatch vs GetUserName");

    LocalFree(pSid);
    LocalFree(sidStr);

    TEST_PASS("SID resolution matches current user");
}

// ============================================================================
// Test 12: Dump real vault and verify stored password matches
// ============================================================================
static void Test_VaultPasswordCheck(const wchar_t* realPassword)
{
    printf("\n[Test 12] Vault password verification (reads real vault)\n");

    if (!realPassword || realPassword[0] == L'\0')
    {
        printf("  SKIP: pass your Windows password as argument\n");
        return;
    }

    // Clear any test override so we read the REAL vault
    SetEnvironmentVariableW(L"DDS_VAULT_PATH", NULL);

    CCredentialVault vault;
    bool loaded = vault.Load();
    if (!loaded)
    {
        printf("  SKIP: could not load vault from %%ProgramData%%\\DDS\\vault.dat\n");
        return;
    }

    printf("  Vault entries: %zu\n", vault.GetUserCount());
    if (vault.GetUserCount() == 0)
    {
        printf("  SKIP: vault is empty (no enrollments)\n");
        return;
    }

    // Show all entries
    const auto& entries = vault.GetEntries();
    for (size_t i = 0; i < entries.size(); i++)
    {
        const auto& e = entries[i];
        char rpA[64]{};
        for (size_t j = 0; j < e.rpId.size() && j < 63; j++)
            rpA[j] = e.rpId[j];

        printf("  [%zu] sid='%ls' name='%ls' rp='%s' credIdLen=%zu saltLen=%zu encPwdLen=%zu\n",
            i, e.userSid.c_str(), e.displayName.c_str(), rpA,
            e.credentialId.size(), e.salt.size(), e.encryptedPassword.size());

        // Print salt hex (first 8 bytes)
        printf("       salt[0..7]=");
        for (size_t j = 0; j < 8 && j < e.salt.size(); j++)
            printf("%02x", e.salt[j]);
        printf("\n");

        // Print credentialId hex (first 8 bytes)
        printf("       credId[0..7]=");
        for (size_t j = 0; j < 8 && j < e.credentialId.size(); j++)
            printf("%02x", e.credentialId[j]);
        printf("\n");
    }

    // Note: We can't decrypt from vault without the FIDO2 hmac-secret key.
    // But we CAN verify that IF we had the right key, the password would match.
    // The hmac_roundtrip test already proved this path works.
    //
    // What we CAN check: encrypt the known password with a test key, then
    // compare the *structure* (encPwd length should equal password byte length).
    size_t expectedEncLen = wcslen(realPassword) * sizeof(wchar_t);
    bool foundMatch = false;
    for (const auto& e : entries)
    {
        if (e.encryptedPassword.size() == expectedEncLen)
        {
            printf("  Entry for '%ls': encPwdLen=%zu matches expected for '%ls' (len=%zu)\n",
                e.userSid.c_str(), e.encryptedPassword.size(),
                L"****", expectedEncLen);
            foundMatch = true;
        }
        else
        {
            printf("  Entry for '%ls': encPwdLen=%zu but expected %zu for a %zu-char password\n",
                e.userSid.c_str(), e.encryptedPassword.size(),
                expectedEncLen, wcslen(realPassword));
            printf("  *** PASSWORD LENGTH MISMATCH — enrollment may have stored wrong password!\n");
        }
    }

    if (foundMatch)
        TEST_PASS("Vault password length matches expected");
    else
    {
        printf("  FAIL: No vault entry has matching encrypted password length\n");
        g_failed++;
    }
}

// ============================================================================
// Main
// ============================================================================
int wmain(int argc, wchar_t* argv[])
{
    printf("=== DDS Component Tests ===\n");

    // Check for --dump-vault flag
    bool dumpVault = false;
    const wchar_t* password = nullptr;
    for (int i = 1; i < argc; i++)
    {
        if (wcscmp(argv[i], L"--dump-vault") == 0)
            dumpVault = true;
        else
            password = argv[i];
    }

    // Initialize logging (required by CredentialVault)
    FileLog::Init();

    // Non-interactive tests (no authenticator needed)
    Test_AesGcmRoundtrip();
    Test_AesGcmWrongKey();
    Test_PasswordEncoding();
    Test_VaultSerializationRoundtrip();
    Test_UrnToSid();
    Test_IpcStructLayout();
    Test_IpcPasswordTransfer();
    Test_KerbPacking();
    Test_FullPipeline();
    Test_SidResolution();

    // LsaLogonUser test (needs real password as argument)
    Test_LsaLogonUser(password);

    // Vault dump/check (needs real password)
    if (dumpVault || password)
        Test_VaultPasswordCheck(password);

    printf("\n=== Results: %d passed, %d failed ===\n", g_passed, g_failed);

    return g_failed > 0 ? 1 : 0;
}
