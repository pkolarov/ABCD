// test_full_flow.cpp
// End-to-end test: simulates the FULL enrollment + login flow with a real
// FIDO2 authenticator. This is the definitive test — if this passes,
// the lock screen should work.
//
// Flow:
//   1. MakeCredential (hmac-secret enabled) — touch #1
//   2. GetAssertion #1 with salt → hmac-secret → encrypt password — touch #2
//   3. Save to vault (DPAPI)
//   4. Load vault back (fresh instance)
//   5. GetAssertion #2 with same salt+credential → hmac-secret — touch #3
//   6. Decrypt password from vault
//   7. Verify password matches original
//   8. Call LsaLogonUser with decrypted password — the DEFINITIVE test
//
// Usage: test_full_flow.exe YourWindowsPassword
// Requires a FIDO2 authenticator. Will prompt for 3 touches.

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <string>
#include <vector>

#include "WebAuthnHelper.h"
#include "CredentialVault.h"
#include "FileLog.h"
#include <ctime>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "ole32.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

static void DumpHex(const char* label, const uint8_t* data, size_t len)
{
    printf("  %s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 16; i++)
        printf("%02x", data[i]);
    if (len > 16) printf("...");
    printf("\n");
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        printf("Usage: test_full_flow.exe <YourWindowsPassword>\n");
        printf("Requires a FIDO2 authenticator. Will prompt for 3 touches.\n");
        return 1;
    }

    const wchar_t* realPassword = argv[1];
    printf("=== Full Enrollment + Login Flow Test ===\n");
    printf("Password length: %zu chars\n\n", wcslen(realPassword));

    FileLog::Init();

    // Create a hidden window (WebAuthn requires a valid HWND)
    WNDCLASSW wc = {};
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"FullFlowTestWnd";
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowW(L"FullFlowTestWnd", L"Full Flow Test",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
        NULL, NULL, wc.hInstance, NULL);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    // Get current user info
    wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD compLen = ARRAYSIZE(compName);
    GetComputerNameW(compName, &compLen);

    wchar_t userName[256];
    DWORD userLen = ARRAYSIZE(userName);
    GetUserNameW(userName, &userLen);

    // Get current user SID
    HANDLE hToken;
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    DWORD tokenInfoLen = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLen);
    std::vector<BYTE> tokenInfo(tokenInfoLen);
    GetTokenInformation(hToken, TokenUser, tokenInfo.data(), tokenInfoLen, &tokenInfoLen);
    CloseHandle(hToken);
    TOKEN_USER* pUser = reinterpret_cast<TOKEN_USER*>(tokenInfo.data());
    LPWSTR sidStr = NULL;
    ConvertSidToStringSidW(pUser->User.Sid, &sidStr);

    printf("  Computer: %ls\n", compName);
    printf("  User:     %ls\n", userName);
    printf("  SID:      %ls\n", sidStr);

    std::wstring userSid(sidStr);
    LocalFree(sidStr);

    // Use temp vault path
    wchar_t tempDir[MAX_PATH];
    GetTempPathW(MAX_PATH, tempDir);
    std::wstring vaultPath = std::wstring(tempDir) + L"dds_fullflow_vault.dat";
    SetEnvironmentVariableW(L"DDS_VAULT_PATH", vaultPath.c_str());
    DeleteFileW(vaultPath.c_str());

    std::string rpId = "dds.local";
    std::vector<uint8_t> userId(userSid.begin(), userSid.end()); // use SID as userId
    std::wstring displayName = std::wstring(compName) + L"\\" + userName;

    // ================================================================
    // PHASE 1: ENROLLMENT (simulates DdsTrayAgent)
    // ================================================================
    printf("\n=== PHASE 1: ENROLLMENT ===\n");

    // Step 1: MakeCredential with hmac-secret
    printf("\n[Step 1] MakeCredential — TOUCH YOUR KEY...\n");
    auto makeResult = CWebAuthnHelper::MakeCredential(hwnd, rpId, userId, displayName, true);
    if (!makeResult.success)
    {
        printf("FAIL: MakeCredential: %s\n", makeResult.errorMessage.c_str());
        return 1;
    }
    printf("  OK: credIdLen=%zu\n", makeResult.credentialId.size());
    DumpHex("credentialId", makeResult.credentialId.data(), makeResult.credentialId.size());
    DumpHex("clientDataHash", makeResult.clientDataHash.data(), makeResult.clientDataHash.size());

    // Step 2: Generate salt + GetAssertion to get hmac-secret for encryption
    std::vector<uint8_t> salt(32);
    BCryptGenRandom(NULL, salt.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    DumpHex("salt", salt.data(), salt.size());

    printf("\n[Step 2] GetAssertion #1 (encrypt) — TOUCH YOUR KEY...\n");
    auto assert1 = CWebAuthnHelper::GetAssertionHmacSecret(hwnd, rpId, makeResult.credentialId, salt);
    if (!assert1.success)
    {
        printf("FAIL: GetAssertion #1: %s\n", assert1.errorMessage.c_str());
        return 1;
    }
    printf("  OK: hmacLen=%zu\n", assert1.hmacSecretOutput.size());
    DumpHex("hmac1", assert1.hmacSecretOutput.data(), assert1.hmacSecretOutput.size());

    // Step 3: Encrypt password
    VaultEntry entry = {};
    entry.userSid = userSid;
    entry.displayName = displayName;
    entry.credentialId = makeResult.credentialId;
    entry.rpId = rpId;
    entry.salt = salt;
    entry.enrollmentTime = (uint64_t)time(NULL);
    entry.authMethod = 1;

    if (!CCredentialVault::EncryptPassword(
            assert1.hmacSecretOutput.data(), assert1.hmacSecretOutput.size(),
            realPassword, entry))
    {
        printf("FAIL: EncryptPassword\n");
        return 1;
    }
    printf("  Encrypted: encLen=%zu ivLen=%zu tagLen=%zu\n",
        entry.encryptedPassword.size(), entry.iv.size(), entry.authTag.size());

    // Step 4: Save to vault (DPAPI)
    {
        CCredentialVault vault;
        if (!vault.EnrollUser(entry))
        {
            printf("FAIL: Vault EnrollUser/Save\n");
            return 1;
        }
        printf("  Vault saved to: %ls\n", vaultPath.c_str());
    }

    // ================================================================
    // PHASE 2: LOGIN (simulates DdsAuthBridge + CredentialProvider)
    // ================================================================
    printf("\n=== PHASE 2: LOGIN ===\n");

    // Step 5: Load vault (fresh instance, like the bridge does)
    CCredentialVault vault2;
    if (!vault2.Load())
    {
        printf("FAIL: Vault Load\n");
        return 1;
    }
    printf("  Vault loaded: %zu entries\n", vault2.GetUserCount());

    auto entries = vault2.FindByUserSid(userSid);
    if (entries.empty())
    {
        printf("FAIL: No vault entry for SID '%ls'\n", userSid.c_str());
        return 1;
    }
    const VaultEntry* pEntry = entries[0];
    printf("  Found entry: credIdLen=%zu saltLen=%zu rpId='%s'\n",
        pEntry->credentialId.size(), pEntry->salt.size(), pEntry->rpId.c_str());

    // Step 6: GetAssertion #2 with same credential + salt (simulates CP)
    printf("\n[Step 3] GetAssertion #2 (decrypt) — TOUCH YOUR KEY...\n");
    auto assert2 = CWebAuthnHelper::GetAssertionHmacSecret(
        hwnd, pEntry->rpId, pEntry->credentialId, pEntry->salt);
    if (!assert2.success)
    {
        printf("FAIL: GetAssertion #2: %s\n", assert2.errorMessage.c_str());
        return 1;
    }
    printf("  OK: hmacLen=%zu\n", assert2.hmacSecretOutput.size());
    DumpHex("hmac2", assert2.hmacSecretOutput.data(), assert2.hmacSecretOutput.size());

    // Step 7: Compare hmac outputs
    bool hmacMatch = (assert1.hmacSecretOutput == assert2.hmacSecretOutput);
    printf("\n  hmac1 == hmac2: %s\n", hmacMatch ? "YES" : "NO *** MISMATCH ***");
    if (!hmacMatch)
    {
        printf("\nFAIL: hmac-secret output differs! Password decryption will fail.\n");
        printf("  This means the WebAuthn options differ between enrollment and login.\n");
        return 1;
    }

    // Step 8: Decrypt password from vault
    std::wstring decryptedPassword;
    if (!CCredentialVault::DecryptPassword(
            assert2.hmacSecretOutput.data(), assert2.hmacSecretOutput.size(),
            *pEntry, decryptedPassword))
    {
        printf("FAIL: DecryptPassword (auth tag mismatch — wrong key)\n");
        return 1;
    }
    printf("  Decrypted: pwdLen=%zu\n", decryptedPassword.size());

    // Step 9: Verify password matches
    bool pwdMatch = (decryptedPassword == realPassword);
    printf("  password match: %s\n", pwdMatch ? "YES" : "NO *** MISMATCH ***");
    if (!pwdMatch)
    {
        printf("FAIL: decrypted password doesn't match original!\n");
        SecureZeroMemory(&decryptedPassword[0], decryptedPassword.size() * sizeof(wchar_t));
        return 1;
    }

    // ================================================================
    // PHASE 3: KERB LOGON (simulates what Windows does with the CP output)
    // ================================================================
    printf("\n=== PHASE 3: LsaLogonUser ===\n");

    HANDLE hLsa = NULL;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (!NT_SUCCESS(status))
    {
        printf("FAIL: LsaConnectUntrusted status=0x%08lX\n", status);
        SecureZeroMemory(&decryptedPassword[0], decryptedPassword.size() * sizeof(wchar_t));
        return 1;
    }

    LSA_STRING lsaPackageName;
    lsaPackageName.Buffer = (PCHAR)"Negotiate";
    lsaPackageName.Length = 9;
    lsaPackageName.MaximumLength = 10;

    ULONG authPackage = 0;
    status = LsaLookupAuthenticationPackage(hLsa, &lsaPackageName, &authPackage);
    if (!NT_SUCCESS(status))
    {
        printf("FAIL: LsaLookupAuthenticationPackage status=0x%08lX\n", status);
        LsaDeregisterLogonProcess(hLsa);
        SecureZeroMemory(&decryptedPassword[0], decryptedPassword.size() * sizeof(wchar_t));
        return 1;
    }

    // Build KERB_INTERACTIVE_UNLOCK_LOGON exactly like the CP does
    KERB_INTERACTIVE_UNLOCK_LOGON kiul = {};
    KERB_INTERACTIVE_LOGON* pkil = &kiul.Logon;
    pkil->MessageType = KerbInteractiveLogon;

    // Use UNICODE_STRING init (same as helpers.cpp)
    pkil->LogonDomainName.Length = (USHORT)(wcslen(compName) * sizeof(WCHAR));
    pkil->LogonDomainName.MaximumLength = pkil->LogonDomainName.Length;
    pkil->LogonDomainName.Buffer = compName;

    pkil->UserName.Length = (USHORT)(wcslen(userName) * sizeof(WCHAR));
    pkil->UserName.MaximumLength = pkil->UserName.Length;
    pkil->UserName.Buffer = userName;

    pkil->Password.Length = (USHORT)(decryptedPassword.size() * sizeof(WCHAR));
    pkil->Password.MaximumLength = pkil->Password.Length;
    pkil->Password.Buffer = const_cast<PWSTR>(decryptedPassword.c_str());

    // Pack (same logic as KerbInteractiveUnlockLogonPack)
    DWORD cb = sizeof(kiul) +
        pkil->LogonDomainName.Length +
        pkil->UserName.Length +
        pkil->Password.Length;

    BYTE* pPacked = (BYTE*)CoTaskMemAlloc(cb);
    KERB_INTERACTIVE_UNLOCK_LOGON* pOut =
        reinterpret_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(pPacked);
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

    printf("  domain='%ls' user='%ls' pwdLen=%zu packed=%lu bytes\n",
        compName, userName, decryptedPassword.size(), cb);

    // Secure-clear the plaintext password now that it's packed
    SecureZeroMemory(&decryptedPassword[0], decryptedPassword.size() * sizeof(wchar_t));

    // Call LsaLogonUser
    LSA_STRING originName;
    originName.Buffer = (PCHAR)"DdsFullFlowTest";
    originName.Length = 15;
    originName.MaximumLength = 16;

    TOKEN_SOURCE tokenSource;
    memcpy(tokenSource.SourceName, "DdsTest\0", 8);
    AllocateLocallyUniqueId(&tokenSource.SourceIdentifier);

    PVOID profileBuffer = NULL;
    ULONG profileLen = 0;
    LUID logonId = {};
    HANDLE hLogonToken = NULL;
    QUOTA_LIMITS quotas = {};
    NTSTATUS subStatus = 0;

    status = LsaLogonUser(
        hLsa, &originName, Interactive, authPackage,
        pPacked, cb, NULL, &tokenSource,
        &profileBuffer, &profileLen, &logonId, &hLogonToken, &quotas, &subStatus);

    SecureZeroMemory(pPacked, cb);
    CoTaskMemFree(pPacked);

    if (NT_SUCCESS(status))
    {
        printf("\n  LsaLogonUser SUCCEEDED!\n");
        if (profileBuffer) LsaFreeReturnBuffer(profileBuffer);
        if (hLogonToken) CloseHandle(hLogonToken);
    }
    else
    {
        ULONG win32err = LsaNtStatusToWinError(status);
        printf("\n  LsaLogonUser FAILED: status=0x%08lX subStatus=0x%08lX win32=%lu\n",
            status, subStatus, win32err);

        if (status == 0xC000006DL)
            printf("  -> STATUS_LOGON_FAILURE: incorrect password or username\n");
        else if (status == 0xC000006AL)
            printf("  -> STATUS_WRONG_PASSWORD\n");
        else if (status == 0xC0000064L)
            printf("  -> STATUS_NO_SUCH_USER\n");
    }

    LsaDeregisterLogonProcess(hLsa);

    // Cleanup temp vault
    DeleteFileW(vaultPath.c_str());
    SetEnvironmentVariableW(L"DDS_VAULT_PATH", NULL);

    if (NT_SUCCESS(status))
        printf("\n=== ALL PHASES PASSED — lock screen should work ===\n");
    else
        printf("\n=== FAILED — see above ===\n");

    return NT_SUCCESS(status) ? 0 : 1;
}
