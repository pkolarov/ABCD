// test_hmac_roundtrip.cpp
// Interactive test: MakeCredential + GetAssertion(hmac) + encrypt/decrypt roundtrip.
// Verifies that two consecutive GetAssertion calls with the same salt produce the
// same hmac-secret output, and that encrypt→decrypt roundtrips correctly.
//
// Build: cl /EHsc /std:c++17 /I..\DdsBridgeIPC /I..\DdsAuthBridge /I..\DdsTrayAgent
//          test_hmac_roundtrip.cpp ..\DdsTrayAgent\WebAuthnHelper.cpp
//          ..\DdsAuthBridge\CredentialVault.cpp ..\DdsAuthBridge\FileLog.cpp
//          webauthn.lib bcrypt.lib crypt32.lib advapi32.lib shell32.lib
// Run:   test_hmac_roundtrip.exe
// Requires a FIDO2 authenticator attached. Will prompt for 3 touches.

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include "WebAuthnHelper.h"
#include "CredentialVault.h"
#include "FileLog.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

static void DumpHex(const char* label, const uint8_t* data, size_t len)
{
    printf("  %s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 16; i++)
        printf("%02x", data[i]);
    if (len > 16) printf("...");
    printf("\n");
}

int main()
{
    printf("=== HMAC-Secret Roundtrip Test ===\n\n");

    // Init FileLog so CredentialVault logging works
    FileLog::Init();

    // Console window doesn't work for WebAuthn — create a hidden top-level window
    WNDCLASSW wc = {};
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"HmacTestWnd";
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowW(L"HmacTestWnd", L"HMAC Test", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, NULL, NULL, wc.hInstance, NULL);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    std::string rpId = "dds.local";
    std::vector<uint8_t> userId = { 't','e','s','t','-','u','s','e','r' };
    std::wstring displayName = L"Test User";

    // Step 1: MakeCredential with hmac-secret
    printf("[Step 1] MakeCredential — touch your key...\n");
    auto makeResult = CWebAuthnHelper::MakeCredential(hwnd, rpId, userId, displayName, true);
    if (!makeResult.success)
    {
        printf("FAIL: MakeCredential: %s\n", makeResult.errorMessage.c_str());
        return 1;
    }
    printf("  OK: credIdLen=%zu\n", makeResult.credentialId.size());
    DumpHex("credentialId", makeResult.credentialId.data(), makeResult.credentialId.size());

    // Generate salt
    std::vector<uint8_t> salt(32);
    BCryptGenRandom(NULL, salt.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    DumpHex("salt", salt.data(), salt.size());

    // Step 2: GetAssertion #1 (enrollment path)
    printf("\n[Step 2] GetAssertion #1 (encrypt) — touch your key...\n");
    auto assert1 = CWebAuthnHelper::GetAssertionHmacSecret(hwnd, rpId, makeResult.credentialId, salt);
    if (!assert1.success)
    {
        printf("FAIL: GetAssertion #1: %s\n", assert1.errorMessage.c_str());
        return 1;
    }
    printf("  OK: hmacLen=%zu\n", assert1.hmacSecretOutput.size());
    DumpHex("hmac1", assert1.hmacSecretOutput.data(), assert1.hmacSecretOutput.size());

    // Encrypt a test password
    const wchar_t* testPassword = L"MyP@ssw0rd";
    VaultEntry entry = {};
    if (!CCredentialVault::EncryptPassword(
            assert1.hmacSecretOutput.data(), assert1.hmacSecretOutput.size(),
            testPassword, entry))
    {
        printf("FAIL: EncryptPassword\n");
        return 1;
    }
    printf("  Encrypted: encLen=%zu ivLen=%zu tagLen=%zu\n",
        entry.encryptedPassword.size(), entry.iv.size(), entry.authTag.size());

    // Step 3: GetAssertion #2 (login path — same salt, same credential)
    printf("\n[Step 3] GetAssertion #2 (decrypt) — touch your key...\n");
    auto assert2 = CWebAuthnHelper::GetAssertionHmacSecret(hwnd, rpId, makeResult.credentialId, salt);
    if (!assert2.success)
    {
        printf("FAIL: GetAssertion #2: %s\n", assert2.errorMessage.c_str());
        return 1;
    }
    printf("  OK: hmacLen=%zu\n", assert2.hmacSecretOutput.size());
    DumpHex("hmac2", assert2.hmacSecretOutput.data(), assert2.hmacSecretOutput.size());

    // Compare
    bool hmacMatch = (assert1.hmacSecretOutput == assert2.hmacSecretOutput);
    printf("\n  hmac1 == hmac2: %s\n", hmacMatch ? "YES" : "NO *** MISMATCH ***");

    if (!hmacMatch)
    {
        printf("\nFAIL: hmac-secret output is not deterministic!\n");
        printf("  This means the same (credential, salt) pair produces different keys.\n");
        return 1;
    }

    // Decrypt
    std::wstring decrypted;
    if (!CCredentialVault::DecryptPassword(
            assert2.hmacSecretOutput.data(), assert2.hmacSecretOutput.size(),
            entry, decrypted))
    {
        printf("FAIL: DecryptPassword\n");
        return 1;
    }

    // Verify
    bool pwMatch = (decrypted == testPassword);
    printf("  password match: %s\n", pwMatch ? "YES" : "NO *** MISMATCH ***");

    SecureZeroMemory(&decrypted[0], decrypted.size() * sizeof(wchar_t));

    if (pwMatch)
        printf("\n=== ALL PASSED ===\n");
    else
        printf("\n=== FAILED ===\n");

    return pwMatch ? 0 : 1;
}
