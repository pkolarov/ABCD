// CDdsCredential — ICredentialProviderCredential for DDS.
// Forked from Crayonic CCrayonicCredential; smart card/PIV/certificate
// serialization paths stripped.  Adds GetSerializationDds() for the
// DDS Auth Bridge FIDO2 flow.

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "CDdsCredential.h"
#include "DdsBridgeClient.h"
#include "guid.h"
#include "helpers.h"
#include <string.h>
#include <strsafe.h>
#include <windows.h>

// Diagnostic log (defined in CDdsProvider.cpp)
extern void CPLog(const char* fmt, ...);

// Global DDS Bridge client shared across credential instances
static CDdsBridgeClient g_ddsBridgeClient;

// AD-10 — canonical user-facing text per
// docs/windows-ad-coexistence-spec.md §4.4. The credential provider, not
// the bridge, owns the visible string for these IPC error codes so the
// operator sees a consistent message even if a future bridge build trims,
// localises, or mistranslates the inline text. Older codes (AUTH_TIMEOUT,
// USER_CANCELLED, etc.) intentionally keep the bridge-supplied free-form
// string — they are not part of the AD coexistence taxonomy.
//
// Pinned numerically so a renumbering of IPC_ERROR forces the assertion
// pinning in test_ipc_messages.cpp to fail first, before this map drifts.
namespace {

struct DdsCanonicalErrorText
{
    UINT32                          errorCode;
    PCWSTR                          text;
    CREDENTIAL_PROVIDER_STATUS_ICON icon;
};

static const DdsCanonicalErrorText s_rgDdsCanonicalErrorText[] = {
    { 16 /* IPC_ERROR::STALE_VAULT_PASSWORD */,
      L"Your DDS stored password may be out of date. Sign in normally with "
      L"your Windows password, then refresh DDS from the system tray.",
      CPSI_WARNING },
    { 17 /* IPC_ERROR::AD_PASSWORD_CHANGE_REQUIRED */,
      L"AD requires you to set a new password. Sign in normally to change "
      L"it, then refresh DDS.",
      CPSI_WARNING },
    { 18 /* IPC_ERROR::AD_PASSWORD_EXPIRED */,
      L"AD requires you to set a new password. Sign in normally to change "
      L"it, then refresh DDS.",
      CPSI_WARNING },
    { 19 /* IPC_ERROR::PRE_ENROLLMENT_REQUIRED */,
      L"DDS sign-in is available only after enrollment on this AD-joined "
      L"machine.",
      CPSI_WARNING },
    { 20 /* IPC_ERROR::UNSUPPORTED_HOST */,
      L"DDS sign-in is not yet supported on Entra-joined machines.",
      CPSI_ERROR },
    { 21 /* IPC_ERROR::ACCOUNT_NOT_FOUND */,
      L"This DDS account no longer exists in your directory. Contact your "
      L"administrator.",
      CPSI_ERROR },
};

static const DdsCanonicalErrorText* FindDdsCanonicalErrorText(UINT32 errorCode)
{
    for (size_t i = 0; i < ARRAYSIZE(s_rgDdsCanonicalErrorText); ++i)
    {
        if (s_rgDdsCanonicalErrorText[i].errorCode == errorCode)
            return &s_rgDdsCanonicalErrorText[i];
    }
    return nullptr;
}

} // namespace

// CDdsCredential ////////////////////////////////////////////////////////////

CDdsCredential::CDdsCredential():
    _cRef(1),
    _pCredProvCredentialEvents(NULL),
    _pszSubjectUrn(nullptr),
    _pszCredentialId(nullptr)
{
    OutputDebugString(L"CDdsCredential()\n");
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));

    auto_tries = 1;
}

CDdsCredential::~CDdsCredential()
{
    OutputDebugString(L"~CDdsCredential()\n");
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }

    CoTaskMemFree(_pszSubjectUrn);
    CoTaskMemFree(_pszCredentialId);

    DllRelease();
}

// Initializes one credential with the field information passed in.
// Set the value of the SFI_USERNAME field to pwzUsername.
HRESULT CDdsCredential::Initialize(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
    const FIELD_STATE_PAIR* rgfsp,
    PCWSTR pwzUsername,
    PCWSTR pwzUsernameInfo,
    PCWSTR pwzSubjectUrn,
    PCWSTR pwzCredentialId,
    bool noUser
    )
{
    OutputDebugString(L"Initialize()\n");
    HRESULT hr = S_OK;

    _cpus = cpus;
    _noUser = noUser;

    // Copy the field descriptors for each field.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String values of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(pwzUsername, &_rgFieldStrings[SFI_USERNAME]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(pwzUsernameInfo, &_rgFieldStrings[SFI_USERNAME_INFO]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Login", &_rgFieldStrings[SFI_SUBMIT_BUTTON]);
    }
    // Store the subject URN for DDS authentication path
    if (SUCCEEDED(hr) && pwzSubjectUrn && pwzSubjectUrn[0] != L'\0')
    {
        hr = SHStrDupW(pwzSubjectUrn, &_pszSubjectUrn);
    }
    // Store the FIDO2 credential_id (base64url) for the DDS auth + AD-14
    // cooldown path. AD-14 precondition: this must be the actual
    // credential_id from tile enumeration, not the human-visible label
    // shown under the username (which is `pwzUsernameInfo`). Plumbing
    // these two strings as separate arguments is the fix for a
    // pre-existing bug where every enrolled user shared the literal
    // "DDS Passwordless Login" label as their credential_id.
    if (SUCCEEDED(hr) && pwzCredentialId && pwzCredentialId[0] != L'\0')
    {
        hr = SHStrDupW(pwzCredentialId, &_pszCredentialId);
    }

    return S_OK;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CDdsCredential::Advise(
    ICredentialProviderCredentialEvents* pcpce
    )
{
    OutputDebugString(L"Advise()\n");
    if (_pCredProvCredentialEvents != NULL)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = pcpce;
    _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

// LogonUI calls this to tell us to release the callback.
HRESULT CDdsCredential::UnAdvise()
{
    OutputDebugString(L"UnAdvise()\n");
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = NULL;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed).
HRESULT CDdsCredential::SetSelected(BOOL* pbAutoLogon)
{
    OutputDebugString(L"SetSelected()\n");
    // Auto-trigger GetSerialization when we have a valid DDS subject URN.
    // This starts the FIDO2 auth flow immediately when the user selects the tile.
    if (_pszSubjectUrn && _pszSubjectUrn[0] != L'\0' && auto_tries-- > 0)
    {
        *pbAutoLogon = TRUE;
    }
    else
    {
        *pbAutoLogon = FALSE;
    }

    return S_OK;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is.
HRESULT CDdsCredential::SetDeselected()
{
    OutputDebugString(L"SetDeselected()\n");
    HRESULT hr = S_OK;

    return hr;
}

// Gets info for a particular field of a tile.
HRESULT CDdsCredential::GetFieldState(
    DWORD dwFieldID,
    CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis
    )
{
    OutputDebugString(L"GetFieldState()\n");
    HRESULT hr;

    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)) && pcpfs && pcpfis)
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;

        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID.
HRESULT CDdsCredential::GetStringValue(
    DWORD dwFieldID,
    PWSTR* ppwsz
    )
{
    OutputDebugString(L"GetStringValue()\n");
    HRESULT hr;

    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) && ppwsz)
    {
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Gets the image to show in the user tile.
HRESULT CDdsCredential::GetBitmapValue(
    DWORD dwFieldID,
    HBITMAP* phbmp
    )
{
    OutputDebugString(L"GetBitmapValue()\n");
    HRESULT hr;
    if ((SFI_TILEIMAGE == dwFieldID) && phbmp)
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != NULL)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to.
HRESULT CDdsCredential::GetSubmitButtonValue(
    DWORD dwFieldID,
    DWORD* pdwAdjacentTo
    )
{
    OutputDebugString(L"GetSubmitButtonValue()\n");
    HRESULT hr;

    if ((SFI_SUBMIT_BUTTON == dwFieldID) && pdwAdjacentTo)
    {
        *pdwAdjacentTo = SFI_USERNAME_INFO;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets the value of a field which can accept a string as a value.
HRESULT CDdsCredential::SetStringValue(
    DWORD dwFieldID,
    PCWSTR pwz
    )
{
    OutputDebugString(L"SetStringValue()\n");
    HRESULT hr;

    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
       (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
        CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR* ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

//-------------
// The following methods are for logonUI to get the values of various UI elements and then communicate
// to the credential about what the user did in that field.  However, these methods are not implemented
// because our tile doesn't contain these types of UI elements
HRESULT CDdsCredential::GetCheckboxValue(
    DWORD dwFieldID,
    BOOL* pbChecked,
    PWSTR* ppwszLabel
    )
{
    OutputDebugString(L"GetCheckboxValue()\n");
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pbChecked);
    UNREFERENCED_PARAMETER(ppwszLabel);

    return E_NOTIMPL;
}

HRESULT CDdsCredential::GetComboBoxValueCount(
    DWORD dwFieldID,
    DWORD* pcItems,
    DWORD* pdwSelectedItem
    )
{
    OutputDebugString(L"GetComboBoxValueCount()\n");
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(pcItems);
    UNREFERENCED_PARAMETER(pdwSelectedItem);
    return E_NOTIMPL;
}

HRESULT CDdsCredential::GetComboBoxValueAt(
    DWORD dwFieldID,
    DWORD dwItem,
    PWSTR* ppwszItem
    )
{
    OutputDebugString(L"GetComboBoxValueAt()\n");
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(dwItem);
    UNREFERENCED_PARAMETER(ppwszItem);
    return E_NOTIMPL;
}

HRESULT CDdsCredential::SetCheckboxValue(
    DWORD dwFieldID,
    BOOL bChecked
    )
{
    OutputDebugString(L"SetCheckboxValue()\n");
    UNREFERENCED_PARAMETER(dwFieldID);
    UNREFERENCED_PARAMETER(bChecked);

    return E_NOTIMPL;
}

HRESULT CDdsCredential::SetComboBoxSelectedValue(
    DWORD dwFieldId,
    DWORD dwSelectedItem
    )
{
    OutputDebugString(L"SetComboBoxSelectedValue()\n");
    UNREFERENCED_PARAMETER(dwFieldId);
    UNREFERENCED_PARAMETER(dwSelectedItem);
    return E_NOTIMPL;
}

HRESULT CDdsCredential::CommandLinkClicked(DWORD dwFieldID)
{
    OutputDebugString(L"CommandLinkClicked()\n");
    UNREFERENCED_PARAMETER(dwFieldID);
    return E_NOTIMPL;
}
//------ end of methods for controls we don't have in our tile ----//


// ============================================================================
// DDS FIDO2 authentication path
// ============================================================================

HRESULT CDdsCredential::GetSerializationDds(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    OutputDebugString(L"GetSerializationDds()\n");

    if (!_pszSubjectUrn || _pszSubjectUrn[0] == L'\0')
    {
        OutputDebugString(L"GetSerializationDds: no subject URN\n");
        if (ppwszOptionalStatusText)
            SHStrDupW(L"DDS authenticator not connected", ppwszOptionalStatusText);
        if (pcpsiOptionalStatusIcon)
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // Show status while waiting for biometric
    if (ppwszOptionalStatusText)
        SHStrDupW(L"Authenticating via DDS...", ppwszOptionalStatusText);

    // Auth via DDS Bridge Service (blocks until fingerprint/timeout)
    PWSTR* pStatusText = ppwszOptionalStatusText;
    auto progressCb = [pStatusText](UINT32 /*state*/, PCWSTR msg)
    {
        OutputDebugString(L"DDS auth progress: ");
        if (msg) OutputDebugString(msg);
        OutputDebugString(L"\n");
        if (pStatusText && msg)
        {
            CoTaskMemFree(*pStatusText);
            SHStrDupW(msg, pStatusText);
        }
    };

    DdsBridgeAuthResult authResult = g_ddsBridgeClient.AuthenticateDds(
        _pszSubjectUrn,
        _pszCredentialId ? _pszCredentialId : L"",
        L"dds.local",      // rpId
        20000,             // 20 second timeout — keep short to avoid freezing LogonUI
        progressCb
    );

    if (!authResult.success)
    {
        OutputDebugString(L"GetSerializationDds: auth failed — ");
        OutputDebugString(authResult.errorMessage.c_str());
        OutputDebugString(L"\n");
        // Don't auto-trigger again on next tile select — let user click Submit manually
        auto_tries = 0;

        // AD-10 — map AD-coexistence IPC error codes to the canonical §4.4
        // status text and icon owned by the credential provider. Codes
        // outside the taxonomy fall back to the bridge-supplied message
        // and the generic CPSI_ERROR icon (existing behaviour).
        const DdsCanonicalErrorText* canonical =
            FindDdsCanonicalErrorText(authResult.errorCode);
        PCWSTR statusText = canonical ? canonical->text
                                      : authResult.errorMessage.c_str();
        CREDENTIAL_PROVIDER_STATUS_ICON statusIcon =
            canonical ? canonical->icon : CPSI_ERROR;

        if (ppwszOptionalStatusText)
        {
            CoTaskMemFree(*ppwszOptionalStatusText);
            SHStrDupW(
                (statusText && statusText[0] != L'\0')
                    ? statusText
                    : L"DDS sign-in failed",
                ppwszOptionalStatusText);
        }
        if (pcpsiOptionalStatusIcon)
            *pcpsiOptionalStatusIcon = statusIcon;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // Got credentials — serialize as KERB_INTERACTIVE_LOGON (password logon)
    OutputDebugString(L"GetSerializationDds: auth OK, packing KERB credential\n");
    {
        char domA[64]{}, userA[64]{};
        WideCharToMultiByte(CP_UTF8, 0, authResult.domain.c_str(), -1, domA, sizeof(domA), NULL, NULL);
        WideCharToMultiByte(CP_UTF8, 0, authResult.username.c_str(), -1, userA, sizeof(userA), NULL, NULL);
        CPLog("GetSerializationDds: domain='%s' user='%s' pwdLen=%zu cpus=%d",
            domA, userA, authResult.password.size(), (int)_cpus);
        // Log first/last wchar code points to verify encoding (not the actual password)
        if (!authResult.password.empty())
            CPLog("GetSerializationDds: pwd[0]=0x%04X pwd[last]=0x%04X",
                (unsigned)authResult.password[0],
                (unsigned)authResult.password[authResult.password.size()-1]);
    }

    PWSTR pwzProtectedPassword = nullptr;
    HRESULT hr = ProtectIfNecessaryAndCopyPassword(
        authResult.password.c_str(), _cpus, &pwzProtectedPassword);

    // Securely clear the plaintext password from DdsBridgeAuthResult immediately
    if (!authResult.password.empty())
    {
        SecureZeroMemory(&authResult.password[0],
                         authResult.password.size() * sizeof(wchar_t));
        authResult.password.clear();
    }

    if (SUCCEEDED(hr))
    {
        wchar_t szDomain[256]{}, szUser[256]{};
        wcsncpy_s(szDomain,  authResult.domain.c_str(),   _TRUNCATE);
        wcsncpy_s(szUser,    authResult.username.c_str(), _TRUNCATE);

        KERB_INTERACTIVE_UNLOCK_LOGON kiul{};
        hr = KerbInteractiveUnlockLogonInit(
            szDomain,
            szUser,
            pwzProtectedPassword,
            _cpus,
            &kiul);

        if (SUCCEEDED(hr))
        {
            hr = KerbInteractiveUnlockLogonPack(kiul,
                &pcpcs->rgbSerialization, &pcpcs->cbSerialization);

            if (SUCCEEDED(hr))
            {
                ULONG ulAuthPackage = 0;
                hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                if (SUCCEEDED(hr))
                {
                    pcpcs->ulAuthenticationPackage = ulAuthPackage;
                    pcpcs->clsidCredentialProvider = CLSID_CDdsProvider;
                    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

                    if (ppwszOptionalStatusText)
                    {
                        CoTaskMemFree(*ppwszOptionalStatusText);
                        SHStrDupW(L"Authenticating...", ppwszOptionalStatusText);
                    }
                }
            }
        }
        // L-14 (security review): zero before free. In CPUS_CREDUI and
        // already-encrypted paths pwzProtectedPassword holds plaintext;
        // in the CredProtect path it holds ciphertext, but zeroing is
        // cheap defense-in-depth.
        if (pwzProtectedPassword)
        {
            SecureZeroMemory(pwzProtectedPassword,
                             wcslen(pwzProtectedPassword) * sizeof(wchar_t));
            CoTaskMemFree(pwzProtectedPassword);
        }
    }

    return hr;
}


// ============================================================================
// Legacy Crayonic Bridge FIDO2 path (kept for BLE badge fallback)
// ============================================================================

HRESULT CDdsCredential::GetSerializationBridge(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    UNREFERENCED_PARAMETER(pcpsiOptionalStatusIcon);

    OutputDebugString(L"GetSerializationBridge()\n");

    if (!_pszSubjectUrn || _pszSubjectUrn[0] == L'\0')
    {
        OutputDebugString(L"GetSerializationBridge: no subject URN\n");
        if (ppwszOptionalStatusText)
            SHStrDupW(L"DDS authenticator not connected", ppwszOptionalStatusText);
        if (pcpsiOptionalStatusIcon)
            *pcpsiOptionalStatusIcon = CPSI_WARNING;
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // Show status while waiting for biometric
    if (ppwszOptionalStatusText)
        SHStrDupW(L"Touch the fingerprint sensor on your authenticator...",
                  ppwszOptionalStatusText);

    // Auth via Bridge Service (blocks until fingerprint/timeout)
    PWSTR* pStatusText = ppwszOptionalStatusText;
    auto progressCb = [pStatusText](UINT32 /*state*/, PCWSTR msg)
    {
        OutputDebugString(L"Bridge auth progress: ");
        if (msg) OutputDebugString(msg);
        OutputDebugString(L"\n");
        if (pStatusText && msg)
        {
            CoTaskMemFree(*pStatusText);
            SHStrDupW(msg, pStatusText);
        }
    };

    DdsBridgeAuthResult authResult = g_ddsBridgeClient.AuthenticateFido(
        _pszSubjectUrn,
        L"dds.local.login",   // rpId — matches enrollment
        60000,                 // 60 second timeout
        progressCb
    );

    if (!authResult.success)
    {
        OutputDebugString(L"GetSerializationBridge: auth failed — ");
        OutputDebugString(authResult.errorMessage.c_str());
        OutputDebugString(L"\n");
        if (ppwszOptionalStatusText)
        {
            CoTaskMemFree(*ppwszOptionalStatusText);
            SHStrDupW(authResult.errorMessage.c_str(), ppwszOptionalStatusText);
        }
        if (pcpsiOptionalStatusIcon)
            *pcpsiOptionalStatusIcon = CPSI_ERROR;
        // Return S_OK (not E_FAIL): LogonUI silently discards the status
        // text when GetSerialization returns a failure HRESULT. We want
        // the user to see why the login failed, so we report success to
        // the COM caller and convey "no credential" via pcpgsr instead.
        *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
        return S_OK;
    }

    // Got credentials — serialize as KERB_INTERACTIVE_LOGON (password logon)
    OutputDebugString(L"GetSerializationBridge: auth OK, packing KERB credential\n");

    PWSTR pwzProtectedPassword = nullptr;
    HRESULT hr = ProtectIfNecessaryAndCopyPassword(
        authResult.password.c_str(), _cpus, &pwzProtectedPassword);

    // Securely clear the plaintext password from DdsBridgeAuthResult immediately
    if (!authResult.password.empty())
    {
        SecureZeroMemory(&authResult.password[0],
                         authResult.password.size() * sizeof(wchar_t));
        authResult.password.clear();
    }

    if (SUCCEEDED(hr))
    {
        wchar_t szDomain[256]{}, szUser[256]{};
        wcsncpy_s(szDomain,  authResult.domain.c_str(),   _TRUNCATE);
        wcsncpy_s(szUser,    authResult.username.c_str(), _TRUNCATE);

        KERB_INTERACTIVE_UNLOCK_LOGON kiul{};
        hr = KerbInteractiveUnlockLogonInit(
            szDomain,
            szUser,
            pwzProtectedPassword,
            _cpus,
            &kiul);

        if (SUCCEEDED(hr))
        {
            hr = KerbInteractiveUnlockLogonPack(kiul,
                &pcpcs->rgbSerialization, &pcpcs->cbSerialization);

            if (SUCCEEDED(hr))
            {
                ULONG ulAuthPackage = 0;
                hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
                if (SUCCEEDED(hr))
                {
                    pcpcs->ulAuthenticationPackage = ulAuthPackage;
                    pcpcs->clsidCredentialProvider = CLSID_CDdsProvider;
                    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;

                    if (ppwszOptionalStatusText)
                    {
                        CoTaskMemFree(*ppwszOptionalStatusText);
                        SHStrDupW(L"Authenticating...", ppwszOptionalStatusText);
                    }
                }
            }
        }
        // L-14 (security review): zero before free — see GetSerializationDds.
        if (pwzProtectedPassword)
        {
            SecureZeroMemory(pwzProtectedPassword,
                             wcslen(pwzProtectedPassword) * sizeof(wchar_t));
            CoTaskMemFree(pwzProtectedPassword);
        }
    }

    return hr;
}

// ============================================================================
// GetSerialization — dispatch to DDS auth path
// ============================================================================

HRESULT CDdsCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
)
{
    OutputDebugString(L"GetSerialization()\n");
    CPLog("GetSerialization: called, dispatching to GetSerializationDds");

    return GetSerializationDds(pcpgsr, pcpcs, ppwszOptionalStatusText, pcpsiOptionalStatusIcon);
}

struct REPORT_RESULT_STATUS_INFO
{
    NTSTATUS ntsStatus;
    NTSTATUS ntsSubstatus;
    PWSTR     pwzMessage;
    CREDENTIAL_PROVIDER_STATUS_ICON cpsi;
};

// AD-14 — STATUS_PASSWORD_MUST_CHANGE / STATUS_PASSWORD_EXPIRED are not in
// the ntstatus.h shipped with most SDKs as plain identifiers, so use the
// numeric constants directly (the spec also pins them in §4.4).
#ifndef STATUS_PASSWORD_MUST_CHANGE
#define STATUS_PASSWORD_MUST_CHANGE ((NTSTATUS)0xC0000224L)
#endif
#ifndef STATUS_PASSWORD_EXPIRED
#define STATUS_PASSWORD_EXPIRED     ((NTSTATUS)0xC0000071L)
#endif

static const REPORT_RESULT_STATUS_INFO s_rgLogonStatusInfo[] =
{
    // AD-14 — stale-vault / AD password recovery text. Distinguishing the
    // three NTSTATUSes matters because the default Windows UX collapses
    // them, leaving the operator unsure whether the issue is in DDS or AD.
    { STATUS_LOGON_FAILURE, STATUS_SUCCESS,
      const_cast<PWSTR>(
          L"Your DDS stored password may be out of date. Sign in normally "
          L"with your Windows password, then refresh DDS from the system tray."),
      CPSI_WARNING, },
    { STATUS_PASSWORD_MUST_CHANGE, STATUS_SUCCESS,
      const_cast<PWSTR>(
          L"AD requires you to set a new password. Sign in normally to change "
          L"it, then refresh DDS."),
      CPSI_WARNING, },
    { STATUS_PASSWORD_EXPIRED, STATUS_SUCCESS,
      const_cast<PWSTR>(
          L"AD requires you to set a new password. Sign in normally to change "
          L"it, then refresh DDS."),
      CPSI_WARNING, },
    { STATUS_ACCOUNT_RESTRICTION, STATUS_ACCOUNT_DISABLED,
      const_cast<PWSTR>(L"The account is disabled."), CPSI_WARNING },
};

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.
HRESULT CDdsCredential::ReportResult(
    NTSTATUS ntsStatus,
    NTSTATUS ntsSubstatus,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon
    )
{
    OutputDebugString(L"ReportResult()\n");

    wchar_t buffer[512];

    swprintf_s(buffer, 512, L"ntsStatus: 0x%X\n", ntsStatus);
    OutputDebugString(buffer);

    swprintf_s(buffer, 512, L"ntsSubstatus: 0x%X\n", ntsSubstatus);
    OutputDebugString(buffer);

    if (ppwszOptionalStatusText != nullptr && *ppwszOptionalStatusText != nullptr) {
        swprintf_s(buffer, 512, L"OptionalStatusText: %ls\n", *ppwszOptionalStatusText);
        OutputDebugString(buffer);
    }

    *ppwszOptionalStatusText = NULL;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    // AD-14 — report stale-password NTSTATUSes back to the Auth Bridge so
    // it can install a 15-min cooldown for this credential. Fire-and-forget;
    // we never block the logon flow on the report. The credential_id is the
    // one bound to this CDdsCredential instance — it's the credential we
    // just serialized via GetSerializationDds.
    if (_pszCredentialId != nullptr && _pszCredentialId[0] != L'\0' &&
        (ntsStatus == STATUS_LOGON_FAILURE ||
         ntsStatus == STATUS_PASSWORD_MUST_CHANGE ||
         ntsStatus == STATUS_PASSWORD_EXPIRED))
    {
        g_ddsBridgeClient.ReportLogonResult(_pszCredentialId,
            static_cast<INT32>(ntsStatus));
    }

    DWORD dwStatusInfo = (DWORD)-1;

    // Look for a match on status and substatus.
    for (DWORD i = 0; i < ARRAYSIZE(s_rgLogonStatusInfo); i++)
    {
        if (s_rgLogonStatusInfo[i].ntsStatus == ntsStatus && s_rgLogonStatusInfo[i].ntsSubstatus == ntsSubstatus)
        {
            dwStatusInfo = i;
            break;
        }
    }

    if ((DWORD)-1 != dwStatusInfo)
    {
        if (SUCCEEDED(SHStrDupW(s_rgLogonStatusInfo[dwStatusInfo].pwzMessage, ppwszOptionalStatusText)))
        {
            *pcpsiOptionalStatusIcon = s_rgLogonStatusInfo[dwStatusInfo].cpsi;
        }
    }

    // If we failed the logon, try to erase the password field.
    if (!SUCCEEDED(HRESULT_FROM_NT(ntsStatus)))
    {
        if (_pCredProvCredentialEvents)
        {
            // No password field in DDS tile — nothing to clear.
        }
    }

    // Since NULL is a valid value for *ppwszOptionalStatusText and *pcpsiOptionalStatusIcon
    // this function can't fail.
    return S_OK;
}
