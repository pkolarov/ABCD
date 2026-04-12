// EnrollmentFlow.cpp
// User enrollment: password prompt -> MakeCredential -> GetAssertion (hmac-secret)
// -> encrypt password -> vault -> POST /v1/enroll/user.

#include "EnrollmentFlow.h"
#include "WebAuthnHelper.h"
#include "CredentialVault.h"
#include "DdsNodeHttpClient.h"
#include "Configuration.h"
#include "FileLog.h"

#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>       // ConvertSidToStringSidW
#include <lmcons.h>      // UNLEN
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// Base64url encoder (no padding) — matches DdsAuthBridgeMain.cpp
// ---------------------------------------------------------------------------

static std::string Base64UrlEncode(const uint8_t* data, size_t len)
{
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((len * 4 + 2) / 3);
    for (size_t i = 0; i < len; i += 3)
    {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        out.push_back(table[(n >> 18) & 0x3F]);
        out.push_back(table[(n >> 12) & 0x3F]);
        if (i + 1 < len) out.push_back(table[(n >> 6) & 0x3F]);
        if (i + 2 < len) out.push_back(table[n & 0x3F]);
    }
    for (auto& c : out)
    {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return out;
}

// ---------------------------------------------------------------------------
// Get current user SID as a string
// ---------------------------------------------------------------------------

static bool GetCurrentUserSid(std::wstring& outSid)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return false;

    DWORD tokenInfoLen = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLen);
    std::vector<BYTE> buf(tokenInfoLen);
    if (!GetTokenInformation(hToken, TokenUser, buf.data(), tokenInfoLen, &tokenInfoLen))
    {
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);

    TOKEN_USER* pUser = reinterpret_cast<TOKEN_USER*>(buf.data());
    LPWSTR pSidStr = NULL;
    if (!ConvertSidToStringSidW(pUser->User.Sid, &pSidStr))
        return false;

    outSid = pSidStr;
    LocalFree(pSidStr);
    return true;
}

// ---------------------------------------------------------------------------
// Get current user display name
// ---------------------------------------------------------------------------

static std::wstring GetCurrentDisplayName()
{
    WCHAR name[UNLEN + 1] = {};
    DWORD len = ARRAYSIZE(name);
    if (GetUserNameW(name, &len))
        return name;
    return L"Unknown User";
}

// ---------------------------------------------------------------------------
// Simple password prompt dialog (modal)
// ---------------------------------------------------------------------------

static bool PromptForPassword(HWND hwnd, std::wstring& outPassword)
{
    // Use CredUIPromptForWindowsCredentialsW for a secure-feeling prompt.
    // Fall back to a simple InputBox-style dialog if not available.
    //
    // For simplicity we use a basic password dialog via a dynamically-
    // created template. This avoids an .rc dependency for the dialog.

    // Build a minimal in-memory dialog template
    struct PasswordDlgParam
    {
        std::wstring password;
        bool         ok;
    } param = {};
    param.ok = false;

    // We'll use a helper DLGPROC
    struct Helper
    {
        static INT_PTR CALLBACK DlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
        {
            switch (msg)
            {
            case WM_INITDIALOG:
            {
                SetWindowLongPtrW(hDlg, GWLP_USERDATA, lParam);
                SetWindowTextW(hDlg, L"DDS Enrollment — Enter Windows Password");

                // Create label
                CreateWindowW(L"STATIC", L"Enter your Windows password:",
                    WS_CHILD | WS_VISIBLE, 10, 10, 340, 20, hDlg,
                    NULL, NULL, NULL);

                // Create password edit
                HWND hEdit = CreateWindowExW(0, L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
                    10, 35, 340, 24, hDlg,
                    (HMENU)101, NULL, NULL);
                SendMessageW(hEdit, EM_SETLIMITTEXT, 256, 0);

                // OK and Cancel buttons
                CreateWindowW(L"BUTTON", L"OK",
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                    200, 70, 70, 28, hDlg, (HMENU)IDOK, NULL, NULL);
                CreateWindowW(L"BUTTON", L"Cancel",
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    280, 70, 70, 28, hDlg, (HMENU)IDCANCEL, NULL, NULL);

                SetFocus(hEdit);
                return FALSE;
            }
            case WM_COMMAND:
                if (LOWORD(wParam) == IDOK)
                {
                    auto* p = reinterpret_cast<PasswordDlgParam*>(GetWindowLongPtrW(hDlg, GWLP_USERDATA));
                    WCHAR buf[260] = {};
                    GetDlgItemTextW(hDlg, 101, buf, ARRAYSIZE(buf));
                    p->password = buf;
                    SecureZeroMemory(buf, sizeof(buf));
                    p->ok = true;
                    EndDialog(hDlg, IDOK);
                    return TRUE;
                }
                else if (LOWORD(wParam) == IDCANCEL)
                {
                    EndDialog(hDlg, IDCANCEL);
                    return TRUE;
                }
                break;
            case WM_CLOSE:
                EndDialog(hDlg, IDCANCEL);
                return TRUE;
            }
            return FALSE;
        }
    };

    // Build in-memory DLGTEMPLATE
    // This is a minimal template for CreateDialogIndirectParam
#pragma pack(push, 4)
    struct
    {
        DLGTEMPLATE tmpl;
        WORD menu;
        WORD cls;
        WORD title;
    } dlg = {};
#pragma pack(pop)

    dlg.tmpl.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | DS_MODALFRAME | DS_CENTER;
    dlg.tmpl.cx = 240;  // dialog units
    dlg.tmpl.cy = 70;

    INT_PTR ret = DialogBoxIndirectParamW(
        GetModuleHandle(NULL),
        &dlg.tmpl,
        hwnd,
        Helper::DlgProc,
        reinterpret_cast<LPARAM>(&param));

    if (ret == IDOK && param.ok && !param.password.empty())
    {
        outPassword = std::move(param.password);
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Enrollment flow
// ---------------------------------------------------------------------------

bool RunEnrollmentFlow(HWND hwnd)
{
    FileLog::Write("EnrollmentFlow: begin\n");

    // Load config
    CDdsConfiguration config;
    config.Load();

    // Get current user info
    std::wstring userSid;
    if (!GetCurrentUserSid(userSid))
    {
        MessageBoxW(hwnd, L"Failed to determine current user SID.",
                    L"Enrollment Error", MB_OK | MB_ICONERROR);
        return false;
    }
    std::wstring displayName = GetCurrentDisplayName();
    std::string rpId = config.RpId();

    FileLog::Writef("EnrollmentFlow: user='%ls' rpId='%s'\n",
                    displayName.c_str(), rpId.c_str());

    // Step 1: Prompt for Windows password
    std::wstring password;
    if (!PromptForPassword(hwnd, password))
    {
        FileLog::Write("EnrollmentFlow: user cancelled password prompt\n");
        return false;
    }

    // Step 2: MakeCredential (Touch 1)
    // Build userId from the SID string bytes
    std::vector<uint8_t> userId(
        reinterpret_cast<const uint8_t*>(userSid.c_str()),
        reinterpret_cast<const uint8_t*>(userSid.c_str()) + userSid.size() * sizeof(wchar_t));

    MessageBoxW(hwnd,
        L"Touch your security key to register it.\n\n"
        L"This is touch 1 of 2.",
        L"DDS Enrollment", MB_OK | MB_ICONINFORMATION);

    auto makeResult = CWebAuthnHelper::MakeCredential(
        hwnd, rpId, userId, displayName, true /*hmacSecret*/);

    if (!makeResult.success)
    {
        FileLog::Writef("EnrollmentFlow: MakeCredential failed: %s\n",
                        makeResult.errorMessage.c_str());
        wchar_t msg[512];
        swprintf_s(msg, L"FIDO2 key registration failed:\n%hs",
                   makeResult.errorMessage.c_str());
        MessageBoxW(hwnd, msg, L"Enrollment Error", MB_OK | MB_ICONERROR);
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        return false;
    }

    // Step 3: Generate random 32-byte salt for hmac-secret
    std::vector<uint8_t> salt(32);
    BCryptGenRandom(NULL, salt.data(), (ULONG)salt.size(),
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    // Step 4: GetAssertion with hmac-secret (Touch 2)
    MessageBoxW(hwnd,
        L"Touch your security key again to complete enrollment.\n\n"
        L"This is touch 2 of 2.",
        L"DDS Enrollment", MB_OK | MB_ICONINFORMATION);

    auto assertResult = CWebAuthnHelper::GetAssertionHmacSecret(
        hwnd, rpId, makeResult.credentialId, salt);

    if (!assertResult.success || assertResult.hmacSecretOutput.size() != 32)
    {
        FileLog::Writef("EnrollmentFlow: GetAssertion hmac failed: %s\n",
                        assertResult.errorMessage.c_str());
        MessageBoxW(hwnd,
            L"Failed to get hmac-secret from authenticator.\n"
            L"Enrollment cannot proceed.",
            L"Enrollment Error", MB_OK | MB_ICONERROR);
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        return false;
    }

    // Step 5: Encrypt password using hmac-secret output
    VaultEntry entry = {};
    entry.userSid = userSid;
    entry.displayName = displayName;
    entry.credentialId = makeResult.credentialId;
    entry.rpId = rpId;
    entry.salt = salt;
    entry.authMethod = 1; // FIDO2

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    entry.enrollmentTime = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

    if (!CCredentialVault::EncryptPassword(
            assertResult.hmacSecretOutput.data(),
            assertResult.hmacSecretOutput.size(),
            password.c_str(),
            entry))
    {
        FileLog::Write("EnrollmentFlow: password encryption failed\n");
        MessageBoxW(hwnd, L"Failed to encrypt password.",
                    L"Enrollment Error", MB_OK | MB_ICONERROR);
        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        SecureZeroMemory(assertResult.hmacSecretOutput.data(), 32);
        return false;
    }

    // Secure cleanup of sensitive material
    SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
    SecureZeroMemory(assertResult.hmacSecretOutput.data(), 32);

    // Step 6: Save to local vault
    CCredentialVault vault;
    vault.Load(); // OK if file doesn't exist yet
    if (!vault.EnrollUser(entry))
    {
        FileLog::Write("EnrollmentFlow: vault EnrollUser failed\n");
        MessageBoxW(hwnd, L"Failed to save credential to vault.",
                    L"Enrollment Error", MB_OK | MB_ICONERROR);
        return false;
    }
    if (!vault.Save())
    {
        FileLog::Write("EnrollmentFlow: vault Save failed\n");
        MessageBoxW(hwnd, L"Failed to write vault file to disk.",
                    L"Enrollment Error", MB_OK | MB_ICONERROR);
        return false;
    }

    FileLog::Write("EnrollmentFlow: vault saved OK\n");

    // Step 7: POST /v1/enroll/user to dds-node
    CDdsNodeHttpClient httpClient;
    httpClient.SetPort(config.DdsNodePort());

    std::string credIdB64 = Base64UrlEncode(
        makeResult.credentialId.data(), makeResult.credentialId.size());
    std::string attestB64 = Base64UrlEncode(
        makeResult.attestationObject.data(), makeResult.attestationObject.size());
    std::string cdhB64 = Base64UrlEncode(
        makeResult.clientDataHash.data(), makeResult.clientDataHash.size());

    // Convert displayName to UTF-8 for JSON
    char displayNameUtf8[256] = {};
    WideCharToMultiByte(CP_UTF8, 0, displayName.c_str(), -1,
                        displayNameUtf8, sizeof(displayNameUtf8), NULL, NULL);

    char userSidUtf8[160] = {};
    WideCharToMultiByte(CP_UTF8, 0, userSid.c_str(), -1,
                        userSidUtf8, sizeof(userSidUtf8), NULL, NULL);

    std::string enrollJson = "{";
    enrollJson += "\"label\":\"" + std::string(userSidUtf8) + "\",";
    enrollJson += "\"credential_id\":\"" + credIdB64 + "\",";
    enrollJson += "\"attestation_object_b64\":\"" + attestB64 + "\",";
    enrollJson += "\"client_data_hash_b64\":\"" + cdhB64 + "\",";
    enrollJson += "\"rp_id\":\"" + rpId + "\",";
    enrollJson += "\"display_name\":\"" + std::string(displayNameUtf8) + "\",";
    enrollJson += "\"authenticator_type\":\"cross-platform\"";
    enrollJson += "}";

    DdsEnrollResult enrollResult = httpClient.PostEnrollUser(enrollJson);

    if (!enrollResult.success)
    {
        FileLog::Writef("EnrollmentFlow: dds-node enroll failed: %s\n",
                        enrollResult.errorMessage.c_str());
        wchar_t msg[512];
        swprintf_s(msg,
            L"Credential saved locally, but DDS node enrollment failed:\n%hs\n\n"
            L"You can retry enrollment later. The local vault entry is preserved.",
            enrollResult.errorMessage.c_str());
        MessageBoxW(hwnd, msg, L"Enrollment Warning", MB_OK | MB_ICONWARNING);
        // Return true because the local vault was saved successfully
        return true;
    }

    FileLog::Writef("EnrollmentFlow: dds-node enroll OK urn='%s' jti='%s'\n",
                    enrollResult.urn.c_str(), enrollResult.jti.c_str());

    // Success!
    wchar_t successMsg[512];
    swprintf_s(successMsg,
        L"FIDO2 key enrolled successfully!\n\n"
        L"URN: %hs\n\n"
        L"Ask your administrator to approve this enrollment.",
        enrollResult.urn.c_str());
    MessageBoxW(hwnd, successMsg, L"Enrollment Complete", MB_OK | MB_ICONINFORMATION);

    return true;
}
