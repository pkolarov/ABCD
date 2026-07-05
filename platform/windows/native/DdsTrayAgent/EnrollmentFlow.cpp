// EnrollmentFlow.cpp
// User enrollment: password prompt -> MakeCredential -> GetAssertion (hmac-secret)
// -> encrypt password -> vault -> POST /v1/enroll/user.
//
// The flow has two skins:
//   * RunEnrollmentFlow(HWND)      — legacy interactive MessageBox skin used
//                                    by DdsTrayAgent.
//   * RunEnrollmentFlowEx(opts)    — generalized: caller can preset the
//                                    password and supply a phase callback so
//                                    the UI lives outside the C++ code (used
//                                    by DdsEnrollUser.exe / the wizard).
//
// Internally both call RunEnrollmentFlowImpl().

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
// JSON string escaping (minimal — for status callback payloads)
// ---------------------------------------------------------------------------

static std::string JsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    sprintf_s(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// Emit a phase line to the callback, if set.
static void EmitPhase(const EnrollmentFlowOptions& opts, const std::string& json)
{
    if (opts.onPhase) opts.onPhase(json);
}

// ---------------------------------------------------------------------------
// Simple password prompt dialog (modal) — used only in interactive mode
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
// Core enrollment implementation
// ---------------------------------------------------------------------------

static EnrollmentFlowResult RunEnrollmentFlowImpl(const EnrollmentFlowOptions& opts)
{
    EnrollmentFlowResult result = {};
    HWND hwnd = opts.hwnd;
    const bool bare = opts.bareEnroll;

    FileLog::Writef("EnrollmentFlow: begin (interactive=%d, preset=%d, bare=%d)\n",
                    opts.interactive ? 1 : 0,
                    opts.presetPassword.empty() ? 0 : 1,
                    bare ? 1 : 0);
    EmitPhase(opts, "{\"phase\":\"start\"}");

    // Load config
    CDdsConfiguration config;
    config.Load();
    std::string rpId = config.RpId();

    // ---- Identity ----
    // Self-service: the CURRENT Windows account (label = SID, name = current
    //   user); the flow later wraps that account's password into the vault.
    // New-person (bare): a brand-new user with no account here — identity is
    //   caller-supplied (label / display name), and there is no password/vault.
    std::wstring userSid;                 // self-service only (vault key)
    std::wstring displayName;
    std::string  enrollLabel;             // enroll POST label + CTAP user.id
    std::vector<uint8_t> userId;

    if (bare)
    {
        if (opts.label.empty() || opts.displayNameOverride.empty())
        {
            result.errorPhase   = "args";
            result.errorMessage = "New-person enrollment requires a username and display name.";
            EmitPhase(opts, "{\"phase\":\"error\",\"at\":\"args\",\"message\":\""
                + JsonEscape(result.errorMessage) + "\"}");
            return result;
        }
        displayName = opts.displayNameOverride;
        char labelUtf8[128] = {};
        int lblLen = WideCharToMultiByte(CP_UTF8, 0, opts.label.c_str(), -1,
                            labelUtf8, sizeof(labelUtf8), NULL, NULL);
        if (lblLen <= 0)   // 0 => ERROR_INSUFFICIENT_BUFFER (label > 127 UTF-8 bytes) or invalid
        {
            result.errorPhase   = "args";
            result.errorMessage = "Username is too long or contains invalid characters.";
            EmitPhase(opts, "{\"phase\":\"error\",\"at\":\"args\",\"message\":\""
                + JsonEscape(result.errorMessage) + "\"}");
            return result;
        }
        enrollLabel = std::string(labelUtf8);
        userId.assign(enrollLabel.begin(), enrollLabel.end());
        FileLog::Writef("EnrollmentFlow: NEW-PERSON label='%s' name='%ls' rpId='%s'\n",
                        enrollLabel.c_str(), displayName.c_str(), rpId.c_str());
    }
    else
    {
        if (!GetCurrentUserSid(userSid))
        {
            result.errorPhase   = "user_sid";
            result.errorMessage = "Failed to determine current user SID.";
            if (opts.interactive)
                MessageBoxW(hwnd, L"Failed to determine current user SID.",
                            L"Enrollment Error", MB_OK | MB_ICONERROR);
            EmitPhase(opts, "{\"phase\":\"error\",\"at\":\"user_sid\",\"message\":\""
                + JsonEscape(result.errorMessage) + "\"}");
            return result;
        }
        displayName = GetCurrentDisplayName();
        // CTAP2 limits user.id to 64 bytes; use the narrow (ASCII) SID form.
        char sidUtf8[128] = {};
        WideCharToMultiByte(CP_UTF8, 0, userSid.c_str(), -1,
                            sidUtf8, sizeof(sidUtf8), NULL, NULL);
        enrollLabel = std::string(sidUtf8);
        userId.assign(enrollLabel.begin(), enrollLabel.end());
        FileLog::Writef("EnrollmentFlow: user='%ls' rpId='%s'\n",
                        displayName.c_str(), rpId.c_str());
    }

    // ---- Windows password (self-service only; bare has no existing account) ----
    std::wstring password;
    if (!bare)
    {
        if (!opts.presetPassword.empty())
        {
            password = opts.presetPassword;
        }
        else if (opts.interactive)
        {
            if (!PromptForPassword(hwnd, password))
            {
                FileLog::Write("EnrollmentFlow: user cancelled password prompt\n");
                result.errorPhase   = "password";
                result.errorMessage = "User cancelled.";
                EmitPhase(opts, "{\"phase\":\"cancelled\"}");
                return result;
            }
        }
        else
        {
            result.errorPhase   = "password";
            result.errorMessage = "Non-interactive mode requires presetPassword.";
            EmitPhase(opts, "{\"phase\":\"error\",\"at\":\"password\",\"message\":\""
                + JsonEscape(result.errorMessage) + "\"}");
            return result;
        }
    }

    // ---- MakeCredential (Touch 1) ----
    if (opts.interactive)
    {
        MessageBoxW(hwnd,
            L"Touch your security key to register it.\n\nThis is touch 1 of 2.",
            L"DDS Enrollment", MB_OK | MB_ICONINFORMATION);
    }
    EmitPhase(opts, "{\"phase\":\"touch1_prompt\"}");

    auto makeResult = CWebAuthnHelper::MakeCredential(
        hwnd, rpId, userId, displayName, true /*hmacSecret - must be enabled at create time*/);

    if (!makeResult.success)
    {
        FileLog::Writef("EnrollmentFlow: MakeCredential failed: %s\n",
                        makeResult.errorMessage.c_str());
        result.errorPhase   = "make_credential";
        result.errorMessage = makeResult.errorMessage;
        if (opts.interactive)
        {
            wchar_t msg[512];
            swprintf_s(msg, L"FIDO2 key registration failed:\n%hs",
                       makeResult.errorMessage.c_str());
            MessageBoxW(hwnd, msg, L"Enrollment Error", MB_OK | MB_ICONERROR);
        }
        if (!password.empty())
            SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        EmitPhase(opts, "{\"phase\":\"error\",\"at\":\"make_credential\",\"message\":\""
            + JsonEscape(makeResult.errorMessage) + "\"}");
        return result;
    }
    EmitPhase(opts, "{\"phase\":\"key_made\"}");

    // ---- Self-service only: touch-2 hmac-secret, encrypt the Windows password,
    //      save the local vault. New-person (bare) skips ALL of this — the
    //      account and its password are materialized by the first-logon claim,
    //      which creates its own vault entry keyed to the new account. ----
    if (!bare)
    {
        std::vector<uint8_t> salt(32);
        BCryptGenRandom(NULL, salt.data(), (ULONG)salt.size(),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (opts.interactive)
        {
            MessageBoxW(hwnd,
                L"Touch your security key again to complete enrollment.\n\nThis is touch 2 of 2.",
                L"DDS Enrollment", MB_OK | MB_ICONINFORMATION);
        }
        EmitPhase(opts, "{\"phase\":\"touch2_prompt\"}");

        auto assertResult = CWebAuthnHelper::GetAssertionHmacSecret(
            hwnd, rpId, makeResult.credentialId, salt);

        if (!assertResult.success || assertResult.hmacSecretOutput.size() != 32)
        {
            FileLog::Writef("EnrollmentFlow: GetAssertion hmac failed: %s\n",
                            assertResult.errorMessage.c_str());
            result.errorPhase   = "get_assertion";
            result.errorMessage = assertResult.errorMessage.empty()
                ? std::string("hmac-secret output unavailable")
                : assertResult.errorMessage;
            if (opts.interactive)
                MessageBoxW(hwnd,
                    L"Failed to get hmac-secret from authenticator.\nEnrollment cannot proceed.",
                    L"Enrollment Error", MB_OK | MB_ICONERROR);
            SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
            EmitPhase(opts, "{\"phase\":\"error\",\"at\":\"get_assertion\",\"message\":\""
                + JsonEscape(result.errorMessage) + "\"}");
            return result;
        }
        EmitPhase(opts, "{\"phase\":\"hmac_done\"}");

        VaultEntry entry = {};
        entry.userSid      = userSid;
        entry.displayName  = displayName;
        entry.credentialId = makeResult.credentialId;
        entry.rpId         = rpId;
        entry.salt         = salt;
        entry.authMethod   = 1; // FIDO2

        FILETIME ft;
        GetSystemTimeAsFileTime(&ft);
        entry.enrollmentTime = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

        if (!CCredentialVault::EncryptPassword(
                assertResult.hmacSecretOutput.data(),
                assertResult.hmacSecretOutput.size(),
                password.c_str(), entry))
        {
            FileLog::Write("EnrollmentFlow: password encryption failed\n");
            result.errorPhase   = "encrypt";
            result.errorMessage = "Failed to encrypt password with hmac-secret output.";
            if (opts.interactive)
                MessageBoxW(hwnd, L"Failed to encrypt password.",
                            L"Enrollment Error", MB_OK | MB_ICONERROR);
            SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
            SecureZeroMemory(assertResult.hmacSecretOutput.data(), 32);
            EmitPhase(opts, "{\"phase\":\"error\",\"at\":\"encrypt\",\"message\":\""
                + JsonEscape(result.errorMessage) + "\"}");
            return result;
        }

        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        SecureZeroMemory(assertResult.hmacSecretOutput.data(), 32);

        CCredentialVault vault;
        vault.Load();
        if (!vault.EnrollUser(entry) || !vault.Save())
        {
            FileLog::Write("EnrollmentFlow: vault save failed\n");
            result.errorPhase   = "vault_save";
            result.errorMessage = "Failed to write the credential vault to disk.";
            if (opts.interactive)
                MessageBoxW(hwnd, L"Failed to save credential to vault.",
                            L"Enrollment Error", MB_OK | MB_ICONERROR);
            EmitPhase(opts, "{\"phase\":\"error\",\"at\":\"vault_save\",\"message\":\""
                + JsonEscape(result.errorMessage) + "\"}");
            return result;
        }
        EmitPhase(opts, "{\"phase\":\"vault_written\"}");
        FileLog::Write("EnrollmentFlow: vault saved OK\n");

        // Local vault is in place — provisional success even if the POST fails.
        result.success = true;
    }

    // ---- POST /v1/enroll/user (both modes) ----
    CDdsNodeHttpClient httpClient;
    if (!config.ApiAddr().empty()) httpClient.SetBaseUrl(config.ApiAddr());
    else                           httpClient.SetPort(config.DdsNodePort());
    if (!config.HmacSecretPath().empty()) httpClient.LoadHmacSecret(config.HmacSecretPath());

    std::string credIdB64 = Base64UrlEncode(
        makeResult.credentialId.data(), makeResult.credentialId.size());
    std::string attestB64 = Base64UrlEncode(
        makeResult.attestationObject.data(), makeResult.attestationObject.size());
    std::string cdhB64 = Base64UrlEncode(
        makeResult.clientDataHash.data(), makeResult.clientDataHash.size());

    char displayNameUtf8[256] = {};
    WideCharToMultiByte(CP_UTF8, 0, displayName.c_str(), -1,
                        displayNameUtf8, sizeof(displayNameUtf8), NULL, NULL);

    std::string enrollJson = "{";
    enrollJson += "\"label\":\"" + JsonEscape(enrollLabel) + "\",";
    enrollJson += "\"credential_id\":\"" + credIdB64 + "\",";
    enrollJson += "\"attestation_object_b64\":\"" + attestB64 + "\",";
    enrollJson += "\"client_data_hash_b64\":\"" + cdhB64 + "\",";
    enrollJson += "\"rp_id\":\"" + rpId + "\",";
    enrollJson += "\"display_name\":\"" + JsonEscape(std::string(displayNameUtf8)) + "\",";
    enrollJson += "\"authenticator_type\":\"cross-platform\"";
    enrollJson += "}";

    DdsEnrollResult enrollResult = httpClient.PostEnrollUser(enrollJson);

    if (!enrollResult.success)
    {
        FileLog::Writef("EnrollmentFlow: dds-node enroll failed: %s\n",
                        enrollResult.errorMessage.c_str());
        result.serverPosted = false;
        result.errorPhase   = "post_enroll";
        result.errorMessage = enrollResult.errorMessage;
        if (bare)
        {
            // No local vault to fall back on — a failed POST means the
            // new-person enrollment did not happen.
            result.success = false;
            EmitPhase(opts, "{\"phase\":\"error\",\"at\":\"post_enroll\",\"message\":\""
                + JsonEscape(enrollResult.errorMessage) + "\"}");
        }
        else
        {
            if (opts.interactive)
            {
                wchar_t msg[512];
                swprintf_s(msg,
                    L"Credential saved locally, but DDS node enrollment failed:\n%hs\n\n"
                    L"You can retry enrollment later. The local vault entry is preserved.",
                    enrollResult.errorMessage.c_str());
                MessageBoxW(hwnd, msg, L"Enrollment Warning", MB_OK | MB_ICONWARNING);
            }
            EmitPhase(opts, "{\"phase\":\"enroll_failed_local_only\",\"message\":\""
                + JsonEscape(enrollResult.errorMessage) + "\"}");
            // result.success stays true — local vault is in place.
        }
        return result;
    }

    result.serverPosted = true;
    result.urn = enrollResult.urn;
    result.jti = enrollResult.jti;
    if (bare) result.success = true;   // bare: success == server posted

    FileLog::Writef("EnrollmentFlow: dds-node enroll OK urn='%s' jti='%s'\n",
                    enrollResult.urn.c_str(), enrollResult.jti.c_str());

    EmitPhase(opts, "{\"phase\":\"enroll_posted\",\"urn\":\""
        + JsonEscape(enrollResult.urn) + "\",\"jti\":\""
        + JsonEscape(enrollResult.jti) + "\"}");

    if (opts.interactive)
    {
        wchar_t successMsg[512];
        swprintf_s(successMsg,
            L"FIDO2 key enrolled successfully!\n\nURN: %hs\n\n"
            L"Ask your administrator to approve this enrollment.",
            enrollResult.urn.c_str());
        MessageBoxW(hwnd, successMsg, L"Enrollment Complete", MB_OK | MB_ICONINFORMATION);
    }

    return result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

bool RunEnrollmentFlow(HWND hwnd)
{
    EnrollmentFlowOptions opts;
    opts.hwnd        = hwnd;
    opts.interactive = true;
    auto r = RunEnrollmentFlowImpl(opts);
    // Legacy semantics: success means the local vault was saved (server
    // POST may have failed — RunEnrollmentFlowImpl already showed a warning).
    return r.success;
}

EnrollmentFlowResult RunEnrollmentFlowEx(const EnrollmentFlowOptions& opts)
{
    return RunEnrollmentFlowImpl(opts);
}
