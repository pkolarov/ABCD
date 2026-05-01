// RefreshVaultFlow.cpp
// Vault refresh: GetAssertion (hmac-secret) -> re-encrypt password -> save
// vault -> clear stale-vault cooldown on the Auth Bridge.
//
// Spec: docs/windows-ad-coexistence-spec.md §6.2
//
// No new FIDO2 credential is created. The existing credential_id and salt
// from the vault entry are reused so the vault file format is unchanged.

#include "RefreshVaultFlow.h"
#include "WebAuthnHelper.h"
#include "CredentialVault.h"
#include "Configuration.h"
#include "FileLog.h"

// JoinState + IPC live under the DdsAuthBridge include path wired by vcxproj.
#include "JoinState.h"
#include "ipc_pipe_client.h"
#include "ipc_messages.h"

#include <windows.h>
#include <sddl.h>       // ConvertSidToStringSidW
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// Password prompt (title differs from EnrollmentFlow to distinguish context)
// ---------------------------------------------------------------------------

static bool PromptForCurrentPassword(HWND hwnd, std::wstring& outPassword)
{
    struct PasswordDlgParam
    {
        std::wstring password;
        bool         ok = false;
    } param;

    struct Helper
    {
        static INT_PTR CALLBACK DlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
        {
            switch (msg)
            {
            case WM_INITDIALOG:
            {
                SetWindowLongPtrW(hDlg, GWLP_USERDATA, lParam);
                SetWindowTextW(hDlg, L"DDS — Refresh Stored Password");

                CreateWindowW(L"STATIC",
                    L"Enter your current Windows password to update the stored credential:",
                    WS_CHILD | WS_VISIBLE, 10, 10, 340, 30, hDlg, NULL, NULL, NULL);

                HWND hEdit = CreateWindowExW(0, L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
                    ES_PASSWORD | ES_AUTOHSCROLL,
                    10, 45, 340, 24, hDlg, (HMENU)101, NULL, NULL);
                SendMessageW(hEdit, EM_SETLIMITTEXT, 256, 0);

                CreateWindowW(L"BUTTON", L"OK",
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                    200, 80, 70, 28, hDlg, (HMENU)IDOK, NULL, NULL);
                CreateWindowW(L"BUTTON", L"Cancel",
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP,
                    280, 80, 70, 28, hDlg, (HMENU)IDCANCEL, NULL, NULL);

                SetFocus(hEdit);
                return FALSE;
            }
            case WM_COMMAND:
                if (LOWORD(wParam) == IDOK)
                {
                    auto* p = reinterpret_cast<PasswordDlgParam*>(
                        GetWindowLongPtrW(hDlg, GWLP_USERDATA));
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
    dlg.tmpl.cx = 240;
    dlg.tmpl.cy = 80;

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
// Fire-and-forget DDS_CLEAR_STALE to the Auth Bridge pipe
// Clears the per-credential stale-vault cooldown so the next DDS sign-in
// attempt proceeds without the bridge returning STALE_VAULT_PASSWORD.
// Failure is best-effort; the bridge's cooldown naturally expires anyway.
// ---------------------------------------------------------------------------

static void SendClearStale(const std::vector<uint8_t>& credentialId)
{
    // Base64url-encode the credential ID to match the bridge's cooldown key.
    static const char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string b64;
    b64.reserve((credentialId.size() * 4 + 2) / 3);
    for (size_t i = 0; i < credentialId.size(); i += 3)
    {
        uint32_t n = static_cast<uint32_t>(credentialId[i]) << 16;
        if (i + 1 < credentialId.size()) n |= static_cast<uint32_t>(credentialId[i + 1]) << 8;
        if (i + 2 < credentialId.size()) n |= static_cast<uint32_t>(credentialId[i + 2]);
        b64.push_back(kTable[(n >> 18) & 0x3F]);
        b64.push_back(kTable[(n >> 12) & 0x3F]);
        if (i + 1 < credentialId.size()) b64.push_back(kTable[(n >> 6) & 0x3F]);
        if (i + 2 < credentialId.size()) b64.push_back(kTable[n & 0x3F]);
    }
    for (auto& c : b64)
    {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }

    IPC_REQ_DDS_CLEAR_STALE req = {};
    MultiByteToWideChar(CP_UTF8, 0, b64.c_str(), -1,
                        req.credential_id, IPC_MAX_CREDENTIAL_ID_LEN);

    CIpcPipeClient pipe;
    if (!pipe.Connect(2000))
    {
        FileLog::Write("RefreshVaultFlow: pipe connect failed; cooldown not cleared (best-effort)\n");
        return;
    }

    pipe.SendRequestNoReply(
        IPC_MSG::DDS_CLEAR_STALE,
        reinterpret_cast<const BYTE*>(&req),
        static_cast<DWORD>(sizeof(req)));

    FileLog::Write("RefreshVaultFlow: DDS_CLEAR_STALE sent\n");
}

// ---------------------------------------------------------------------------
// Get current user SID as a wide string
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
// Main flow
// ---------------------------------------------------------------------------

bool RunRefreshVaultFlow(HWND hwnd)
{
    FileLog::Write("RefreshVaultFlow: begin\n");

    // -----------------------------------------------------------------------
    // Check JoinState — spec §6.2 + behavior matrix §3
    // EntraOnly: always blocked (no vault path on Entra-only hosts).
    // Unknown: allowed only if an existing vault entry is found for the SID.
    // -----------------------------------------------------------------------
    dds::JoinState joinState = dds::GetCachedJoinState();
    FileLog::Writef("RefreshVaultFlow: JoinState=%ls\n", dds::JoinStateName(joinState));

    if (joinState == dds::JoinState::EntraOnlyJoined)
    {
        MessageBoxW(hwnd,
            L"DDS sign-in is not supported on Entra-joined machines.\n\n"
            L"Password refresh is unavailable on this host.",
            L"DDS — Refresh Not Available", MB_OK | MB_ICONINFORMATION);
        return false;
    }

    // -----------------------------------------------------------------------
    // Look up vault entry for the current SID
    // -----------------------------------------------------------------------
    std::wstring userSid;
    if (!GetCurrentUserSid(userSid))
    {
        MessageBoxW(hwnd,
            L"Failed to determine current user identity.\n\n"
            L"Cannot locate vault entry without a valid SID.",
            L"DDS — Refresh Error", MB_OK | MB_ICONERROR);
        return false;
    }
    FileLog::Writef("RefreshVaultFlow: SID=%ls\n", userSid.c_str());

    CCredentialVault vault;
    vault.Load();

    auto entries = vault.FindByUserSid(userSid);

    if (entries.empty())
    {
        if (joinState == dds::JoinState::Unknown)
        {
            // Unknown with no vault entry: block (spec §6.2)
            MessageBoxW(hwnd,
                L"DDS could not classify this machine's domain state.\n\n"
                L"Password refresh is unavailable until the DDS services can classify the host.\n"
                L"Please try again after ensuring the DDS node is running.",
                L"DDS — Refresh Not Available", MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            MessageBoxW(hwnd,
                L"No DDS credential found for the current user.\n\n"
                L"Use \"Enroll FIDO2 Key\" to enroll before refreshing.",
                L"DDS — Refresh Error", MB_OK | MB_ICONINFORMATION);
        }
        return false;
    }

    // Use the first (most recent) vault entry for this SID.
    const VaultEntry& existing = *entries[0];

    CDdsConfiguration config;
    config.Load();
    std::string rpId = config.RpId();

    // -----------------------------------------------------------------------
    // Prompt for current Windows password
    // -----------------------------------------------------------------------
    std::wstring newPassword;
    if (!PromptForCurrentPassword(hwnd, newPassword))
    {
        FileLog::Write("RefreshVaultFlow: user cancelled password prompt\n");
        return false;
    }

    // -----------------------------------------------------------------------
    // GetAssertion with hmac-secret using existing credential_id + salt
    // No MakeCredential — spec §6.2 step 3
    // -----------------------------------------------------------------------
    MessageBoxW(hwnd,
        L"Touch your security key to authenticate.",
        L"DDS — Refresh", MB_OK | MB_ICONINFORMATION);

    auto assertResult = CWebAuthnHelper::GetAssertionHmacSecret(
        hwnd, rpId, existing.credentialId, existing.salt);

    if (!assertResult.success || assertResult.hmacSecretOutput.size() != 32)
    {
        FileLog::Writef("RefreshVaultFlow: GetAssertion failed: %s\n",
                        assertResult.errorMessage.c_str());
        wchar_t msg[512];
        swprintf_s(msg,
            L"FIDO2 authentication failed:\n%hs\n\n"
            L"Password was not updated.",
            assertResult.errorMessage.c_str());
        MessageBoxW(hwnd, msg, L"DDS — Refresh Error", MB_OK | MB_ICONERROR);
        SecureZeroMemory(newPassword.data(), newPassword.size() * sizeof(wchar_t));
        return false;
    }

    // -----------------------------------------------------------------------
    // Re-encrypt new password under the hmac-secret derived key — spec §6.2 step 4
    // -----------------------------------------------------------------------
    VaultEntry updated = existing; // copy identity fields, credentialId, salt, rpId

    if (!CCredentialVault::EncryptPassword(
            assertResult.hmacSecretOutput.data(),
            assertResult.hmacSecretOutput.size(),
            newPassword.c_str(),
            updated))
    {
        FileLog::Write("RefreshVaultFlow: EncryptPassword failed\n");
        MessageBoxW(hwnd,
            L"Failed to encrypt the new password.\n\nPassword was not updated.",
            L"DDS — Refresh Error", MB_OK | MB_ICONERROR);
        SecureZeroMemory(newPassword.data(), newPassword.size() * sizeof(wchar_t));
        SecureZeroMemory(assertResult.hmacSecretOutput.data(), 32);
        return false;
    }

    SecureZeroMemory(newPassword.data(), newPassword.size() * sizeof(wchar_t));
    SecureZeroMemory(assertResult.hmacSecretOutput.data(), 32);

    // -----------------------------------------------------------------------
    // Save updated vault entry — spec §6.2 step 5
    // EnrollUser replaces any existing entry for the same SID.
    // -----------------------------------------------------------------------
    if (!vault.EnrollUser(updated))
    {
        FileLog::Write("RefreshVaultFlow: vault EnrollUser failed\n");
        MessageBoxW(hwnd,
            L"Failed to save updated credential to vault.",
            L"DDS — Refresh Error", MB_OK | MB_ICONERROR);
        return false;
    }
    if (!vault.Save())
    {
        FileLog::Write("RefreshVaultFlow: vault Save failed\n");
        MessageBoxW(hwnd,
            L"Failed to write vault file to disk.",
            L"DDS — Refresh Error", MB_OK | MB_ICONERROR);
        return false;
    }

    FileLog::Write("RefreshVaultFlow: vault saved OK\n");

    // -----------------------------------------------------------------------
    // Clear stale-vault cooldown on the Auth Bridge — spec §6.2 step 5
    // Fire-and-forget; failure does not make the refresh a failure.
    // -----------------------------------------------------------------------
    SendClearStale(updated.credentialId);

    // -----------------------------------------------------------------------
    // Success
    // -----------------------------------------------------------------------
    MessageBoxW(hwnd,
        L"Password updated successfully.\n\n"
        L"Your next DDS sign-in will use the new password.",
        L"DDS — Refresh Complete", MB_OK | MB_ICONINFORMATION);

    FileLog::Write("RefreshVaultFlow: complete\n");
    return true;
}
