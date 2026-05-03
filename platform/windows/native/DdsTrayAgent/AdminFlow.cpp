// AdminFlow.cpp
// Admin setup (one-time) and approval (vouch) flows.

#include "AdminFlow.h"
#include "WebAuthnHelper.h"
#include "DdsNodeHttpClient.h"
#include "Configuration.h"
#include "FileLog.h"

#include <windows.h>
#include <sddl.h>
#include <commctrl.h>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// Base64url encoder (same as EnrollmentFlow.cpp)
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
// Registry helpers for admin credential ID
// ---------------------------------------------------------------------------

static const wchar_t* REG_KEY_PATH = L"SOFTWARE\\DDS\\AuthBridge";
static const wchar_t* REG_ADMIN_CRED_ID = L"AdminCredentialId";

static bool SaveAdminCredentialIdToRegistry(const std::vector<uint8_t>& credId)
{
    HKEY hKey = NULL;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, NULL,
                        0, KEY_SET_VALUE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    std::string b64 = Base64UrlEncode(credId.data(), credId.size());
    LONG ret = RegSetValueExA(hKey, "AdminCredentialId", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(b64.c_str()), (DWORD)(b64.size() + 1));
    RegCloseKey(hKey);
    return ret == ERROR_SUCCESS;
}

// Base64url decode
static std::vector<uint8_t> Base64UrlDecode(const std::string& input)
{
    std::string b64 = input;
    for (auto& c : b64) { if (c == '-') c = '+'; else if (c == '_') c = '/'; }
    while (b64.size() % 4 != 0) b64.push_back('=');

    static const int T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> out;
    out.reserve(b64.size() * 3 / 4);
    for (size_t i = 0; i + 3 < b64.size(); i += 4)
    {
        int a = T[(unsigned char)b64[i]];
        int b = T[(unsigned char)b64[i+1]];
        int c = T[(unsigned char)b64[i+2]];
        int d = T[(unsigned char)b64[i+3]];
        if (a < 0 || b < 0) break;
        out.push_back((uint8_t)((a << 2) | (b >> 4)));
        if (c >= 0) out.push_back((uint8_t)(((b & 0xF) << 4) | (c >> 2)));
        if (d >= 0) out.push_back((uint8_t)(((c & 3) << 6) | d));
    }
    return out;
}

static bool LoadAdminCredentialIdFromRegistry(std::vector<uint8_t>& outCredId)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;

    char buf[512] = {};
    DWORD bufLen = sizeof(buf);
    DWORD type = 0;
    LONG ret = RegQueryValueExA(hKey, "AdminCredentialId", NULL, &type,
        reinterpret_cast<LPBYTE>(buf), &bufLen);
    RegCloseKey(hKey);

    if (ret != ERROR_SUCCESS || type != REG_SZ || bufLen == 0)
        return false;

    outCredId = Base64UrlDecode(std::string(buf));
    return !outCredId.empty();
}

// ---------------------------------------------------------------------------
// Admin Setup Flow
// ---------------------------------------------------------------------------

bool RunAdminSetupFlow(HWND hwnd)
{
    FileLog::Write("AdminSetup: begin\n");

    CDdsConfiguration config;
    config.Load();
    std::string rpId = config.RpId();

    // Pre-flight: ask dds-node whether admin_setup is currently
    // accepted (C-2 gate: trusted_roots empty AND .bootstrap sentinel
    // present). Refuse here so we don't burn a FIDO2 credential slot
    // on a request guaranteed to return HTTP 403. The pre-check needs
    // the same transport + HMAC plumbing as the real POST.
    {
        CDdsNodeHttpClient preCheckClient;
        if (!config.ApiAddr().empty()) {
            preCheckClient.SetBaseUrl(config.ApiAddr());
        } else {
            preCheckClient.SetPort(config.DdsNodePort());
        }
        if (!config.HmacSecretPath().empty()) {
            preCheckClient.LoadHmacSecret(config.HmacSecretPath());
        }
        auto info = preCheckClient.GetNodeInfo();
        if (!info.success) {
            FileLog::Writef("AdminSetup: pre-flight GET /v1/node/info failed: %s\n",
                            info.errorMessage.c_str());
            wchar_t msg[512];
            swprintf_s(msg, L"Cannot reach dds-node:\n%hs", info.errorMessage.c_str());
            MessageBoxW(hwnd, msg, L"DDS Admin Setup", MB_OK | MB_ICONERROR);
            return false;
        }
        if (!info.adminSetupAvailable) {
            FileLog::Write("AdminSetup: refused client-side -- admin already configured "
                           "or .bootstrap sentinel absent\n");
            MessageBoxW(hwnd,
                L"Admin Setup is not available.\n\n"
                L"Either an admin is already registered for this domain, or the "
                L"\"\\ProgramData\\DDS\\node-data\\.bootstrap\" sentinel is absent.\n\n"
                L"To add another admin, ask the existing admin to vouch for you "
                L"via Approve Enrollments. To re-bootstrap, wipe node-data and "
                L"re-run the bootstrap wizard.",
                L"DDS Admin Setup", MB_OK | MB_ICONWARNING);
            return false;
        }
    }

    // Build a userId for the admin (use "admin" as the label)
    std::string adminLabel = "admin";
    std::vector<uint8_t> userId(adminLabel.begin(), adminLabel.end());

    MessageBoxW(hwnd,
        L"Touch your security key to register it as the admin key.\n\n"
        L"This key will be used to approve user enrollments.",
        L"DDS Admin Setup", MB_OK | MB_ICONINFORMATION);

    auto makeResult = CWebAuthnHelper::MakeCredential(
        hwnd, rpId, userId, L"DDS Administrator", false /*no hmac-secret*/);

    if (!makeResult.success)
    {
        FileLog::Writef("AdminSetup: MakeCredential failed: %s\n",
                        makeResult.errorMessage.c_str());
        wchar_t msg[512];
        swprintf_s(msg, L"Admin key registration failed:\n%hs",
                   makeResult.errorMessage.c_str());
        MessageBoxW(hwnd, msg, L"Admin Setup Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // POST /v1/admin/setup
    // A-2: prefer ApiAddr over the legacy DdsNodePort path so the
    // tray agent works against bootstrap-generated node.toml that
    // ships with `api_addr = "pipe:dds-api"` only.
    CDdsNodeHttpClient httpClient;
    if (!config.ApiAddr().empty()) {
        httpClient.SetBaseUrl(config.ApiAddr());
    } else {
        httpClient.SetPort(config.DdsNodePort());
    }
    // A-3 fail-closed: load HMAC secret so response MAC verifies.
    if (!config.HmacSecretPath().empty()) {
        httpClient.LoadHmacSecret(config.HmacSecretPath());
    }

    std::string credIdB64 = Base64UrlEncode(
        makeResult.credentialId.data(), makeResult.credentialId.size());
    std::string attestB64 = Base64UrlEncode(
        makeResult.attestationObject.data(), makeResult.attestationObject.size());
    std::string cdhB64 = Base64UrlEncode(
        makeResult.clientDataHash.data(), makeResult.clientDataHash.size());

    std::string setupJson = "{";
    setupJson += "\"label\":\"admin\",";
    setupJson += "\"credential_id\":\"" + credIdB64 + "\",";
    setupJson += "\"attestation_object_b64\":\"" + attestB64 + "\",";
    setupJson += "\"client_data_hash_b64\":\"" + cdhB64 + "\",";
    setupJson += "\"rp_id\":\"" + rpId + "\",";
    setupJson += "\"display_name\":\"DDS Administrator\",";
    setupJson += "\"authenticator_type\":\"cross-platform\"";
    setupJson += "}";

    DdsAdminSetupResult setupResult = httpClient.PostAdminSetup(setupJson);

    if (!setupResult.success)
    {
        FileLog::Writef("AdminSetup: dds-node failed: %s\n",
                        setupResult.errorMessage.c_str());
        wchar_t msg[512];
        swprintf_s(msg, L"DDS node admin setup failed:\n%hs",
                   setupResult.errorMessage.c_str());
        MessageBoxW(hwnd, msg, L"Admin Setup Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // Save admin credential ID to registry for later vouch operations
    SaveAdminCredentialIdToRegistry(makeResult.credentialId);

    FileLog::Writef("AdminSetup: OK adminUrn='%s'\n", setupResult.adminUrn.c_str());

    wchar_t successMsg[512];
    swprintf_s(successMsg,
        L"Admin key registered!\n\n"
        L"Admin URN: %hs\n\n"
        L"This device is now authorized to approve user enrollments.",
        setupResult.adminUrn.c_str());
    MessageBoxW(hwnd, successMsg, L"Admin Setup Complete", MB_OK | MB_ICONINFORMATION);

    return true;
}

// ---------------------------------------------------------------------------
// User selection dialog for approval
// ---------------------------------------------------------------------------

struct ApprovalDlgParam
{
    std::vector<DdsEnrolledUser> users;
    int selectedIndex;
    bool ok;
};

static INT_PTR CALLBACK ApprovalDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_INITDIALOG:
    {
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, lParam);
        SetWindowTextW(hDlg, L"DDS Admin — Approve Enrollments");

        auto* p = reinterpret_cast<ApprovalDlgParam*>(lParam);

        // Create label
        CreateWindowW(L"STATIC", L"Select a user to approve:",
            WS_CHILD | WS_VISIBLE, 10, 10, 440, 20, hDlg,
            NULL, NULL, NULL);

        // Create listbox
        HWND hList = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_BORDER | WS_TABSTOP | LBS_NOTIFY,
            10, 35, 440, 180, hDlg,
            (HMENU)201, NULL, NULL);

        for (size_t i = 0; i < p->users.size(); i++)
        {
            const auto& u = p->users[i];
            // Format: "DisplayName (URN) [Status]"
            wchar_t item[512];
            wchar_t nameW[256] = {};
            wchar_t urnW[160] = {};
            MultiByteToWideChar(CP_UTF8, 0, u.displayName.c_str(), -1, nameW, 256);
            MultiByteToWideChar(CP_UTF8, 0, u.subjectUrn.c_str(), -1, urnW, 160);
            const wchar_t* status = u.vouched ? L"Approved" : L"Pending";
            swprintf_s(item, L"%s (%s) [%s]", nameW, urnW, status);
            SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)item);
        }

        // Buttons
        CreateWindowW(L"BUTTON", L"Approve",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
            290, 225, 75, 28, hDlg, (HMENU)IDOK, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Close",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            375, 225, 75, 28, hDlg, (HMENU)IDCANCEL, NULL, NULL);

        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK)
        {
            auto* p = reinterpret_cast<ApprovalDlgParam*>(GetWindowLongPtrW(hDlg, GWLP_USERDATA));
            HWND hList = GetDlgItem(hDlg, 201);
            int sel = (int)SendMessageW(hList, LB_GETCURSEL, 0, 0);
            if (sel == LB_ERR)
            {
                MessageBoxW(hDlg, L"Please select a user to approve.",
                            L"No Selection", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            p->selectedIndex = sel;
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

// ---------------------------------------------------------------------------
// Admin Approval (Vouch) Flow
// ---------------------------------------------------------------------------

bool RunAdminApproveFlow(HWND hwnd)
{
    FileLog::Write("AdminApprove: begin\n");

    CDdsConfiguration config;
    config.Load();
    std::string rpId = config.RpId();

    // Load admin credential ID from registry
    std::vector<uint8_t> adminCredId;
    if (!LoadAdminCredentialIdFromRegistry(adminCredId))
    {
        MessageBoxW(hwnd,
            L"No admin key found. Run Admin Setup first.",
            L"Admin Approval", MB_OK | MB_ICONWARNING);
        return false;
    }

    // Fetch enrolled users from dds-node — prefer ApiAddr (A-2).
    CDdsNodeHttpClient httpClient;
    if (!config.ApiAddr().empty()) {
        httpClient.SetBaseUrl(config.ApiAddr());
    } else {
        httpClient.SetPort(config.DdsNodePort());
    }
    // A-3 fail-closed: load HMAC secret so response MAC verifies.
    if (!config.HmacSecretPath().empty()) {
        httpClient.LoadHmacSecret(config.HmacSecretPath());
    }

    DdsEnrolledUsersResult usersResult = httpClient.GetEnrolledUsers(config.DeviceUrn());

    if (!usersResult.success)
    {
        FileLog::Writef("AdminApprove: GetEnrolledUsers failed: %s\n",
                        usersResult.errorMessage.c_str());
        wchar_t msg[512];
        swprintf_s(msg, L"Failed to fetch enrolled users:\n%hs",
                   usersResult.errorMessage.c_str());
        MessageBoxW(hwnd, msg, L"Admin Approval Error", MB_OK | MB_ICONERROR);
        return false;
    }

    if (usersResult.users.empty())
    {
        MessageBoxW(hwnd, L"No enrolled users found.",
                    L"Admin Approval", MB_OK | MB_ICONINFORMATION);
        return false;
    }

    // Show user selection dialog
    ApprovalDlgParam dlgParam;
    dlgParam.users = usersResult.users;
    dlgParam.selectedIndex = -1;
    dlgParam.ok = false;

    // Build in-memory dialog template
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
    dlg.tmpl.cx = 310;
    dlg.tmpl.cy = 170;

    INT_PTR ret = DialogBoxIndirectParamW(
        GetModuleHandle(NULL),
        &dlg.tmpl,
        hwnd,
        ApprovalDlgProc,
        reinterpret_cast<LPARAM>(&dlgParam));

    if (ret != IDOK || !dlgParam.ok || dlgParam.selectedIndex < 0)
    {
        FileLog::Write("AdminApprove: user cancelled selection\n");
        return false;
    }

    const DdsEnrolledUser& subject = dlgParam.users[dlgParam.selectedIndex];

    FileLog::Writef("AdminApprove: approving user urn='%s' credId='%s'\n",
                    subject.subjectUrn.c_str(), subject.credentialId.c_str());

    // Fetch a server-issued admin challenge before touching the authenticator.
    // The server stores the nonce and will consume it in /v1/admin/vouch to
    // enforce freshness and single-use; the assertion's clientDataJSON must
    // bind to this nonce for the hash check to pass.
    DdsChallengeResult adminChallenge = httpClient.GetAdminChallenge();
    if (!adminChallenge.success)
    {
        FileLog::Writef("AdminApprove: GetAdminChallenge failed: %s\n",
                        adminChallenge.errorMessage.c_str());
        MessageBoxW(hwnd,
            L"Failed to fetch admin challenge from DDS node.",
            L"Admin Approval Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // Admin touches authenticator for proof-of-presence
    MessageBoxW(hwnd,
        L"Touch your admin security key to approve this enrollment.",
        L"DDS Admin Approval", MB_OK | MB_ICONINFORMATION);

    auto assertResult = CWebAuthnHelper::GetAssertionProof(
        hwnd, rpId, adminCredId, adminChallenge.challengeB64url);

    if (!assertResult.success)
    {
        FileLog::Writef("AdminApprove: GetAssertion failed: %s\n",
                        assertResult.errorMessage.c_str());
        wchar_t msg[512];
        swprintf_s(msg, L"Admin assertion failed:\n%hs",
                   assertResult.errorMessage.c_str());
        MessageBoxW(hwnd, msg, L"Admin Approval Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // POST /v1/admin/vouch
    std::string credIdB64 = Base64UrlEncode(
        adminCredId.data(), adminCredId.size());
    std::string authDataB64 = Base64UrlEncode(
        assertResult.authenticatorData.data(), assertResult.authenticatorData.size());
    std::string sigB64 = Base64UrlEncode(
        assertResult.signature.data(), assertResult.signature.size());
    std::string cdhB64 = Base64UrlEncode(
        assertResult.clientDataHash.data(), assertResult.clientDataHash.size());

    // The enrolled user's subject_urn is available directly from the
    // /v1/enrolled-users response (the "subject_urn" field).

    std::string vouchJson = "{";
    vouchJson += "\"subject_urn\":\"" + subject.subjectUrn + "\",";
    vouchJson += "\"credential_id\":\"" + credIdB64 + "\",";
    vouchJson += "\"challenge_id\":\"" + adminChallenge.challengeId + "\",";
    vouchJson += "\"authenticator_data\":\"" + authDataB64 + "\",";
    vouchJson += "\"client_data_hash\":\"" + cdhB64 + "\",";
    vouchJson += "\"signature\":\"" + sigB64 + "\"";
    vouchJson += "}";

    DdsAdminVouchResult vouchResult = httpClient.PostAdminVouch(vouchJson);

    if (!vouchResult.success)
    {
        FileLog::Writef("AdminApprove: vouch failed: %s\n",
                        vouchResult.errorMessage.c_str());
        wchar_t msg[512];
        swprintf_s(msg, L"Vouch request failed:\n%hs",
                   vouchResult.errorMessage.c_str());
        MessageBoxW(hwnd, msg, L"Admin Approval Error", MB_OK | MB_ICONERROR);
        return false;
    }

    FileLog::Writef("AdminApprove: vouch OK jti='%s' subjectUrn='%s' adminUrn='%s'\n",
                    vouchResult.vouchJti.c_str(),
                    vouchResult.subjectUrn.c_str(),
                    vouchResult.adminUrn.c_str());

    wchar_t successMsg[512];
    swprintf_s(successMsg,
        L"User approved!\n\n"
        L"Subject: %hs\n"
        L"Vouched by: %hs",
        vouchResult.subjectUrn.c_str(),
        vouchResult.adminUrn.c_str());
    MessageBoxW(hwnd, successMsg, L"Approval Complete", MB_OK | MB_ICONINFORMATION);

    return true;
}
