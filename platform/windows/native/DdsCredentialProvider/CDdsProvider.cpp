// CDdsProvider — ICredentialProvider implementation for DDS.
// Forked from Crayonic CCrayonicProvider; smart card/PIV/certificate paths stripped.
// Enumerates user tiles from DDS Auth Bridge (via named-pipe IPC).

#include <credentialprovider.h>
#include "CDdsProvider.h"
#include "CDdsCredential.h"
#include "DdsBridgeClient.h"
#include "guid.h"

#include <windows.h>
#include <process.h>
#include <functional>
#include <stdio.h>
#include <shlobj.h>
#include <sddl.h>
#include <aclapi.h>

#pragma comment(lib, "advapi32.lib")

// ---- Diagnostic log ----
//
// AUDIT-2026-06-11 #14: the diagnostic log previously lived at
// C:\Temp\dds_cp.log with no DACL — world-readable, so any user could read CP
// diagnostics (which until #12 also leaked password-derived data). Write to
// %ProgramData%\DDS\logs\dds_cp.log instead, with an explicit protected DACL
// granting FullControl only to LocalSystem and BUILTIN\Administrators. This
// mirrors the FileLog::ApplyRestrictedDacl idiom in DdsAuthBridge/FileLog.cpp.
namespace
{
    // Resolve %ProgramData%\DDS\logs\dds_cp.log into g_cpLogPath once, creating
    // the directory with a protected DACL. Returns the path, or "" on failure.
    const wchar_t* CPLogPath()
    {
        static wchar_t g_cpLogPath[MAX_PATH] = L"";
        static bool    g_resolved = false;
        if (g_resolved)
            return g_cpLogPath;
        g_resolved = true;

        wchar_t programData[MAX_PATH] = {0};
        if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, 0, programData) != S_OK)
            wcscpy_s(programData, L"C:\\ProgramData");

        wchar_t dir[MAX_PATH];
        swprintf_s(dir, L"%s\\DDS\\logs", programData);

        // Ensure the parent (%ProgramData%\DDS) and the logs dir exist.
        wchar_t parent[MAX_PATH];
        swprintf_s(parent, L"%s\\DDS", programData);
        CreateDirectoryW(parent, NULL);
        CreateDirectoryW(dir, NULL);

        // SY -> LocalSystem, BA -> BUILTIN\Administrators; PAI = protected +
        // non-inherited; OICI propagates to files created inside.
        const wchar_t* sddl = L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
        PSECURITY_DESCRIPTOR pSD = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SDDL_REVISION_1, &pSD, nullptr))
        {
            BOOL daclPresent = FALSE, daclDefaulted = FALSE;
            PACL pDacl = nullptr;
            if (GetSecurityDescriptorDacl(pSD, &daclPresent, &pDacl, &daclDefaulted) &&
                daclPresent)
            {
                SetNamedSecurityInfoW(dir, SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, pDacl, nullptr);
            }
            LocalFree(pSD);
        }

        swprintf_s(g_cpLogPath, L"%s\\dds_cp.log", dir);
        return g_cpLogPath;
    }
}

void CPLog(const char* fmt, ...)
{
    const wchar_t* path = CPLogPath();
    if (path[0] == L'\0') return;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"a") != 0 || !f) return;
    SYSTEMTIME st{}; GetLocalTime(&st);
    fprintf(f, "[%02d:%02d:%02d.%03d PID=%lu] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            GetCurrentProcessId());
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fputc('\n', f);
    fclose(f);
}
#include <string>

#include "version.h"
#define VERSION "Version " DDS_CREDENTIAL_PROVIDER_VERSION

// ============================================================================
// DDS user entry — simplified replacement for SmartcardCredentialStruct
// ============================================================================
#define MAX_DDS_STRING_LENGTH 256
// MAX_DDS_USERS lives in CDdsProvider.h so MAX_CREDENTIALS can be derived from
// it — see the tile-capacity comment there.

struct DdsUserEntry {
    wchar_t subjectUrn[MAX_DDS_STRING_LENGTH];
    wchar_t displayName[MAX_DDS_STRING_LENGTH];
    wchar_t credentialId[MAX_DDS_STRING_LENGTH];
};

struct DdsUserStorage {
    DdsUserEntry users[MAX_DDS_USERS];
    int count;
};

static DdsUserStorage g_ddsUsers = { 0 };

// ============================================================================
// Bridge Service integration
// ============================================================================
static CDdsBridgeClient g_provider_bridge;

static bool TryLoadDdsUsers()
{
    std::vector<DdsBridgeUser> users = g_provider_bridge.ListDdsUsers(L"");
    CPLog("TryLoadDdsUsers: g_provider_bridge.ListDdsUsers() returned %zu users",
          users.size());
    if (users.empty()) {
        CPLog("TryLoadDdsUsers: FAILED — empty list (pipe down or no enrolled users?)");
        return false;
    }

    memset(&g_ddsUsers, 0, sizeof(g_ddsUsers));
    int count = 0;
    for (auto& u : users)
    {
        if (count >= MAX_DDS_USERS) break;
        DdsUserEntry& entry = g_ddsUsers.users[count];
        wcscpy_s(entry.subjectUrn,   u.subjectUrn.c_str());
        wcscpy_s(entry.displayName,  u.displayName.c_str());
        wcscpy_s(entry.credentialId, u.credentialId.c_str());
        count++;
    }
    g_ddsUsers.count = count;

    // Log the first subject URN (truncated) for diagnostics
    wchar_t urnHead[80]{};
    wcsncpy_s(urnHead, g_ddsUsers.users[0].subjectUrn, 79);
    char urnA[80]{};
    WideCharToMultiByte(CP_UTF8, 0, urnHead, -1, urnA, sizeof(urnA), nullptr, nullptr);
    CPLog("TryLoadDdsUsers: OK — loaded %d user(s), first urn='%s'", count, urnA);
    return true;
}

// ============================================================================
// Bridge Service status poll thread — polls bridge for device connect/disconnect
// ============================================================================

static HANDLE g_BridgePollThread         = NULL;
static volatile bool g_BridgePollActive  = false;
static volatile bool g_BridgePollKill    = false;
static bool g_DeviceConnectedLast        = false;
// Abort event: signalled by CleanupBridgePoll to wake the poll thread quickly.
static HANDLE g_BridgePollAbortEvent     = NULL;

unsigned __stdcall BridgePollThreadFunction(void* param)
{
    UNREFERENCED_PARAMETER(param);

    while (!g_BridgePollKill)
    {
        // Poll interval: 100 ms when no device is connected (react fast to
        // connect for auto-logon UX), 500 ms while connected (heartbeat).
        DWORD pollWaitMs = g_DeviceConnectedLast ? 500 : 100;

        // ---- Wait pollWaitMs, but wake immediately on abort ----
        if (g_BridgePollAbortEvent)
        {
            DWORD w = WaitForSingleObject(g_BridgePollAbortEvent, pollWaitMs);
            if (w == WAIT_OBJECT_0) break;   // abort signalled
        }
        else
        {
            Sleep(pollWaitMs);
        }

        if (g_BridgePollKill) break;
        if (!g_BridgePollActive) continue;

        // ---- Poll FIDO HID device presence directly ----
        // The original Crayonic-forked code asked the bridge for
        // deviceConnected, but the bridge hardcodes that to FALSE
        // (no BLE device manager in the DDS fork). For the USB FIDO2
        // path we look at HID device presence ourselves — we already
        // run inside LogonUI with SetupAPI access. This is what wakes
        // the "key just got plugged in → auto-logon" nudge.
        bool connected = (CDdsBridgeClient::AnyFidoHidDevicePresent() == TRUE);

        if (connected != g_DeviceConnectedLast)
        {
            g_DeviceConnectedLast = connected;
            if (connected)
            {
                CPLog("BridgePoll: FIDO HID device connected — calling TryLoadDdsUsers");
                bool ok = TryLoadDdsUsers();
                for (int attempt = 1; !ok && attempt <= 3 && !g_BridgePollKill; ++attempt)
                {
                    Sleep(250);
                    CPLog("BridgePoll: TryLoadDdsUsers retry %d/3", attempt);
                    ok = TryLoadDdsUsers();
                }
                CPLog("BridgePoll: TryLoadDdsUsers final result=%d  g_ddsUsers.count=%d",
                      (int)ok, g_ddsUsers.count);
            }
            else
            {
                CPLog("BridgePoll: FIDO HID device disconnected — clearing g_ddsUsers");
                memset(&g_ddsUsers, 0, sizeof(g_ddsUsers));
            }

            if (!g_BridgePollKill && onDdsStatusChangeCallback)
                onDdsStatusChangeCallback();
        }
    }
    return 0;
}

void InitializeBridgePoll()
{
    g_BridgePollActive     = false;
    g_BridgePollKill       = false;
    g_DeviceConnectedLast  = false;
    g_BridgePollAbortEvent = CreateEventW(NULL,  // default security
                                          TRUE,  // manual-reset
                                          FALSE, // initially non-signalled
                                          NULL); // unnamed
    g_BridgePollThread = (HANDLE)_beginthreadex(
        NULL, 0, BridgePollThreadFunction, NULL, 0, NULL);
}

void CleanupBridgePoll()
{
    CPLog("CleanupBridgePoll: start");

    // Step 1: Null the callback FIRST so the poll thread cannot invoke it
    // after we start tearing down.
    onDdsStatusChangeCallback = nullptr;

    // Step 2: Tell the thread to stop
    g_BridgePollActive = false;
    g_BridgePollKill   = true;

    // Signal the abort event so the thread wakes immediately.
    if (g_BridgePollAbortEvent)
        SetEvent(g_BridgePollAbortEvent);

    // Step 3: Wait for the thread to exit
    if (g_BridgePollThread)
    {
        DWORD waited = WaitForSingleObject(g_BridgePollThread, 3000);
        CPLog("CleanupBridgePoll: thread wait result=%lu", waited);
        CloseHandle(g_BridgePollThread);
        g_BridgePollThread = NULL;
    }

    // Step 4: Close the abort event
    if (g_BridgePollAbortEvent)
    {
        CloseHandle(g_BridgePollAbortEvent);
        g_BridgePollAbortEvent = NULL;
    }

    CPLog("CleanupBridgePoll: done");
}

// CDdsProvider ////////////////////////////////////////////////////////////////

CDdsProvider::CDdsProvider():
    _cRef(1),
    _pkiulSetSerialization(NULL),
    _dwNumCreds(0),
    _bAutoSubmitSetSerializationCred(false),
    _dwSetSerializationCred(CREDENTIAL_PROVIDER_NO_DEFAULT),
    _bNeedsReEnumeration(0),
    _bPendingAutoLogon(0)
{
    _pcpe = NULL;
    OutputDebugString(L"CDdsProvider()\n");
    DllAddRef();

    ZeroMemory(_rgpCredentials, sizeof(_rgpCredentials));

    onDdsStatusChangeCallback = std::bind(&CDdsProvider::OnConnectStatusChanged, this);

    InitializeBridgePoll();
}

CDdsProvider::~CDdsProvider()
{
    OutputDebugString(L"~CDdsProvider()\n");

    // L-2 (pre-prod review 2026-07-24): scrub and free the
    // SetSerialization blob. `_CleanupSetSerialization` has always
    // existed but was never called from anywhere, so the
    // KERB_INTERACTIVE_UNLOCK_LOGON handed to us by LogonUI — which
    // carries the user's cleartext password on the RDP/NLA path — was
    // left un-zeroed in the LogonUI (SYSTEM) process heap for the
    // lifetime of the process. Recovering it still requires existing
    // SYSTEM-level memory access, which is why this is low severity, but
    // there is no reason to leave it lying there.
    _CleanupSetSerialization();

    for (size_t i = 0; i < _dwNumCreds; i++)
    {
        if (_rgpCredentials[i] != NULL)
        {
            _rgpCredentials[i]->Release();
        }
    }

    // Stop the poll thread (nulls onDdsStatusChangeCallback, signals abort event)
    // before releasing _pcpe so the thread cannot call CredentialsChanged()
    // on a freed interface.
    CleanupBridgePoll();

    // Release the LogonUI event callback interface if Advise() was called
    // but UnAdvise() was never called.
    if (_pcpe != NULL)
    {
        _pcpe->Release();
        _pcpe = NULL;
    }

    DllRelease();
}

// Called from the BridgePollThread when device connect/disconnect is detected.
// IMPORTANT: this runs on the background thread.  _rgpCredentials/_dwNumCreds
// must NEVER be touched here — LogonUI's main thread may be reading them
// concurrently (e.g. inside GetCredentialAt).
//
// Pattern: set a dirty flag, then call CredentialsChanged() so that LogonUI
// re-calls GetCredentialCount / GetCredentialAt on ITS OWN thread, at which
// point _EnumerateCredentials() runs safely on the main thread.
void CDdsProvider::OnConnectStatusChanged()
{
    // Mark credentials as stale (main thread will re-enumerate in GetCredentialCount).
    InterlockedExchange(&_bNeedsReEnumeration, 1L);

    // If the transition was device-CONNECTED and at least one user was
    // loaded, arm one-shot auto-logon.
    if (g_DeviceConnectedLast && g_ddsUsers.count > 0)
    {
        InterlockedExchange(&_bPendingAutoLogon, 1L);
        CPLog("OnConnectStatusChanged: device connected + %d user(s) — arming auto-logon",
              g_ddsUsers.count);
    }
    else
    {
        CPLog("OnConnectStatusChanged: dirty flag set, notifying LogonUI (no auto-logon)");
    }

    if (_pcpe != NULL)
    {
        _pcpe->CredentialsChanged(_upAdviseContext);
    }
}

// L-2 (pre-prod review 2026-07-24): scrub-then-free the
// SetSerialization blob. Nulls the member itself so the function is
// idempotent — it is now called from two places (the replace site in
// SetSerialization and the destructor) and a double call must not
// double-free.
void CDdsProvider::_CleanupSetSerialization()
{
    OutputDebugString(L"_CleanupSetSerialization()\n");
    if (_pkiulSetSerialization)
    {
        KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;
        SecureZeroMemory(_pkiulSetSerialization,
                         sizeof(*_pkiulSetSerialization) +
                         pkil->LogonDomainName.MaximumLength +
                         pkil->UserName.MaximumLength +
                         pkil->Password.MaximumLength);
        HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);
        _pkiulSetSerialization = NULL;
    }
}

// ---------------------------------------------------------------------------
// Safety check: if the registry value
//   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\
//     Credential Providers\{a7f3b2c1-9d4e-4f8a-b6c5-2e1d0a3f7b9c}
//     Disabled = 1   (DWORD)
// is set, the CP returns E_NOTIMPL for all scenarios and LogonUI hides it.
// This lets an admin remotely disable the CP without unregistering it.
static bool IsDdsCPDisabled()
{
    static const WCHAR kKey[] =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\"
        L"Credential Providers\\{a7f3b2c1-9d4e-4f8a-b6c5-2e1d0a3f7b9c}";
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return false;
    DWORD disabled = 0, size = sizeof(disabled), type = 0;
    RegQueryValueExW(hKey, L"Disabled", NULL, &type, (LPBYTE)&disabled, &size);
    RegCloseKey(hKey);
    return (type == REG_DWORD && disabled != 0);
}

// SetUsageScenario is the provider's cue that it's going to be asked for tiles
// in a subsequent call.
HRESULT CDdsProvider::SetUsageScenario(
    CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    DWORD dwFlags
    )
{
    OutputDebugString(L"SetUsageScenario()\n");
    UNREFERENCED_PARAMETER(dwFlags);
    HRESULT hr;

    CPLog("SetUsageScenario cpus=%u dwFlags=%lu", (unsigned)cpus, (unsigned long)dwFlags);

    // Emergency kill-switch via registry
    if (IsDdsCPDisabled())
    {
        CPLog("SetUsageScenario: CP disabled via registry — returning E_NOTIMPL");
        return E_NOTIMPL;
    }

    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        _cpus = cpus;
        hr = this->_EnumerateCredentials();
        // AUDIT-2026-06-12 R1 follow-up: _dwNumCreds is DWORD — %zu reads a
        // 64-bit size_t for a 32-bit vararg on x64 (UB, desyncs later args).
        CPLog("SetUsageScenario: _EnumerateCredentials returned hr=0x%08X _dwNumCreds=%lu",
              (unsigned)hr, (unsigned long)_dwNumCreds);
        g_BridgePollActive = true;
        break;

    case CPUS_CREDUI:
    case CPUS_CHANGE_PASSWORD:
        hr = E_NOTIMPL;
        break;

    default:
        hr = E_INVALIDARG;
        break;
    }

    return hr;
}

// SetSerialization takes the kind of buffer that you would normally return to
// LogonUI for an authentication attempt.
STDMETHODIMP CDdsProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs
    )
{
    OutputDebugString(L"SetSerialization()\n");
    HRESULT hr = E_INVALIDARG;

    if ((CLSID_CDdsProvider == pcpcs->clsidCredentialProvider))
    {
        ULONG ulAuthPackage;
        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);

        if (SUCCEEDED(hr))
        {
            if ((ulAuthPackage == pcpcs->ulAuthenticationPackage) &&
                (0 < pcpcs->cbSerialization && pcpcs->rgbSerialization))
            {
                KERB_INTERACTIVE_UNLOCK_LOGON* pkil = (KERB_INTERACTIVE_UNLOCK_LOGON*) pcpcs->rgbSerialization;
                if (KerbInteractiveLogon == pkil->Logon.MessageType)
                {
                    BYTE* rgbSerialization;
                    rgbSerialization = (BYTE*)HeapAlloc(GetProcessHeap(), 0, pcpcs->cbSerialization);
                    hr = rgbSerialization ? S_OK : E_OUTOFMEMORY;

                    if (SUCCEEDED(hr))
                    {
                        CopyMemory(rgbSerialization, pcpcs->rgbSerialization, pcpcs->cbSerialization);
                        KerbInteractiveUnlockLogonUnpackInPlace((KERB_INTERACTIVE_UNLOCK_LOGON*)rgbSerialization, pcpcs->cbSerialization);

                        if (_pkiulSetSerialization)
                        {
                            // L-2 (pre-prod review 2026-07-24): the
                            // previous blob holds the cleartext password
                            // from the caller's KERB_INTERACTIVE_LOGON.
                            // A bare HeapFree returns those pages to the
                            // heap with the password still in them —
                            // scrub first. `_CleanupSetSerialization`
                            // does the SecureZeroMemory + HeapFree pair
                            // and nulls the member.
                            _CleanupSetSerialization();

                            if (_dwSetSerializationCred != CREDENTIAL_PROVIDER_NO_DEFAULT && _dwSetSerializationCred == _dwNumCreds - 1)
                            {
                                _rgpCredentials[_dwSetSerializationCred]->Release();
                                _rgpCredentials[_dwSetSerializationCred] = NULL;
                                _dwNumCreds--;
                                _dwSetSerializationCred = CREDENTIAL_PROVIDER_NO_DEFAULT;
                            }
                        }
                        _pkiulSetSerialization = (KERB_INTERACTIVE_UNLOCK_LOGON*)rgbSerialization;
                        hr = S_OK;
                    }
                }
            }
        }
        else
        {
            hr = E_INVALIDARG;
        }
    }
    return hr;
}

// Called by LogonUI to give you a callback.
HRESULT CDdsProvider::Advise(
    ICredentialProviderEvents* pcpe,
    UINT_PTR upAdviseContext
    )
{
    OutputDebugString(L"Advise()\n");
    CPLog("Advise() called pcpe=%p", (void*)pcpe);
    if (_pcpe != NULL)
    {
        _pcpe->Release();
    }
    _pcpe = pcpe;
    _pcpe->AddRef();
    _upAdviseContext = upAdviseContext;

    return S_OK;
}

// Called by LogonUI when the ICredentialProviderEvents callback is no longer valid.
HRESULT CDdsProvider::UnAdvise()
{
    OutputDebugString(L"Unadvise()\n");
    CPLog("UnAdvise() called");
    if (_pcpe != NULL)
    {
        _pcpe->Release();
        _pcpe = NULL;
    }

    g_BridgePollActive = false;

    return S_OK;
}

// Called by LogonUI to determine the number of fields in your tiles.
HRESULT CDdsProvider::GetFieldDescriptorCount(
    DWORD* pdwCount
    )
{
    OutputDebugString(L"GetFieldDescriptorCount()\n");
    // Show all fields (including submit button) when DDS users are loaded,
    // even if no physical BLE device is connected.
    *pdwCount = (g_DeviceConnectedLast || g_ddsUsers.count > 0)
                    ? SFI_NUM_FIELDS : SFI_NUM_FIELDS_NO_USER;

    return S_OK;
}

// Gets the field descriptor for a particular field.
HRESULT CDdsProvider::GetFieldDescriptorAt(
    DWORD dwIndex,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd
    )
{
    OutputDebugString(L"GetFieldDescriptorAt()\n");
    HRESULT hr;

    if ((dwIndex < SFI_NUM_FIELDS) && ppcpfd)
    {
        hr = FieldDescriptorCoAllocCopy(s_rgCredProvFieldDescriptors[dwIndex], ppcpfd);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwCount to the number of tiles that we wish to show at this time.
HRESULT CDdsProvider::GetCredentialCount(
    DWORD* pdwCount,
    DWORD* pdwDefault,
    BOOL* pbAutoLogonWithDefault
    )
{
    OutputDebugString(L"GetCredentialCount()\n");
    HRESULT hr = S_OK;

    // Re-enumerate if the background poll thread flagged a device change.
    if (InterlockedExchange(&_bNeedsReEnumeration, 0L) != 0L)
    {
        CPLog("GetCredentialCount: dirty flag — re-enumerating credentials (main thread)");
        _EnumerateCredentials();
    }

    if (_pkiulSetSerialization && _dwSetSerializationCred == CREDENTIAL_PROVIDER_NO_DEFAULT)
    {
        _EnumerateSetSerialization();
    }

    *pdwCount = (_dwNumCreds > 0) ? (DWORD)_dwNumCreds : 0;
    CPLog("GetCredentialCount: pdwCount=%lu _dwNumCreds=%lu ddsUserCount=%d",
          (unsigned long)*pdwCount, (unsigned long)_dwNumCreds, g_ddsUsers.count);
    if (*pdwCount > 0)
    {
        // Default tile: the SetSerialization tile when one is pending
        // (RDP / NLA hand-off), else the sole DDS tile, else NO default.
        // A forced default of 0 made the device-connect auto-logon below
        // serialize tile 0 (the first enrolled user) even when the user
        // had selected a different user's tile, hijacking multi-user
        // logons — the selected tile's ceremony was cancelled and the
        // first user's ceremony ran against the inserted key.
        if (_dwSetSerializationCred != CREDENTIAL_PROVIDER_NO_DEFAULT)
        {
            *pdwDefault = _dwSetSerializationCred;
        }
        else if (_dwNumCreds == 1)
        {
            *pdwDefault = 0;
        }
        else
        {
            *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
        }

        // ---- One-shot auto-logon on device connect ----
        // Only fire when the default tile is unambiguous (exactly one
        // DDS *user* tile, no pending SetSerialization). With several
        // enrolled users the tile choice belongs to the human; their
        // click still auto-starts that tile's ceremony via SetSelected.
        // HasSubjectUrn() excludes the "connect authenticator"
        // placeholder that _EnumerateCredentials creates when every
        // enrolled user was admin-filtered — auto-firing it would greet
        // a just-inserted key with "authenticator not connected".
        LONG armed = InterlockedExchange(&_bPendingAutoLogon, 0L);
        bool soleDdsTile = (g_ddsUsers.count > 0) && (_dwNumCreds == 1) &&
                           (_dwSetSerializationCred == CREDENTIAL_PROVIDER_NO_DEFAULT) &&
                           (_rgpCredentials[0] != NULL) &&
                           _rgpCredentials[0]->HasSubjectUrn();
        *pbAutoLogonWithDefault = (armed && soleDdsTile) ? TRUE : FALSE;
        if (armed && !soleDdsTile)
            CPLog("GetCredentialCount: auto-logon suppressed — %lu tiles, user picks",
                  (unsigned long)_dwNumCreds);
        if (*pbAutoLogonWithDefault)
            CPLog("GetCredentialCount: AUTO-LOGON armed — LogonUI will call GetSerialization immediately");
    }
    else
    {
        *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
        *pbAutoLogonWithDefault = FALSE;
        hr = S_OK;
    }

    return hr;
}

// Returns the credential at the index specified by dwIndex.
HRESULT CDdsProvider::GetCredentialAt(
    DWORD dwIndex,
    ICredentialProviderCredential** ppcpc
    )
{
    OutputDebugString(L"GetCredentialAt()\n");
    HRESULT hr;

    if ((dwIndex < _dwNumCreds) && ppcpc)
    {
        hr = _rgpCredentials[dwIndex]->QueryInterface(IID_ICredentialProviderCredential, reinterpret_cast<void**>(ppcpc));
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Creates a Credential with the SFI_USERNAME field's value set to pwzUsername.
// AD-14 precondition: pwzCredentialId is the FIDO2 credential_id
// (base64url) for this enrollment, sourced from the DDS user list. It is
// distinct from pwUsernameInfo (which is the human-visible label shown
// under the username). The credential provider DLL needs the real
// credential_id to (a) drive `DDS_START_AUTH` against the right vault
// entry and (b) report stale-vault NTSTATUSes to the bridge cooldown
// keyed on a per-credential identifier — without this, every enrolled
// user would share one cooldown bucket.
HRESULT CDdsProvider::_EnumerateOneCredential(
    DWORD dwCredentialIndex,
    PCWSTR pwzUsername,
    PCWSTR pwUsernameInfo,
    PCWSTR pwzSubjectUrn,
    PCWSTR pwzCredentialId
    )
{
    OutputDebugString(L"_EnumerateOneCredential()\n");
    HRESULT hr;

    // AUDIT-2026-06-11 #7 / AUDIT-2026-06-12 R1 follow-up: hard bound the
    // write cursor to the array capacity. The _rgpCredentials array has
    // exactly MAX_CREDENTIALS slots; writing past it is an out-of-bounds
    // pointer write in SYSTEM-context LogonUI. The slot is appended densely
    // at _dwNumCreds (dwCredentialIndex is a log label only — see below), so
    // the cursor is the value that must stay in bounds. Callers cap their
    // loops, but enforce it here too so no path can overflow the array.
    if (_dwNumCreds >= MAX_CREDENTIALS)
    {
        return E_INVALIDARG;
    }

    CDdsCredential* ppc = new CDdsCredential();

    if (ppc)
    {
        {
            char urnA[96]{};
            WideCharToMultiByte(CP_UTF8, 0,
                pwzSubjectUrn ? pwzSubjectUrn : L"(null)", -1,
                urnA, sizeof(urnA), nullptr, nullptr);
            CPLog("_EnumerateOneCredential[%lu]: subjectUrn='%s'",
                  (unsigned long)dwCredentialIndex, urnA);
        }
        hr = ppc->Initialize(
            _cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs,
            pwzUsername, pwUsernameInfo,
            pwzSubjectUrn,         // DDS subject URN
            pwzCredentialId,       // FIDO2 credential_id (base64url)
            !g_DeviceConnectedLast // noUser flag
        );

        if (SUCCEEDED(hr))
        {
            // AUDIT-2026-06-12 R1 follow-up: append densely at _dwNumCreds
            // instead of trusting dwCredentialIndex. The caller's loop
            // advances its index even when Initialize fails, so indexed
            // writes could leave holes: a slot skipped on failure keeps
            // whatever pointer the release loop left behind while
            // _dwNumCreds counts later successes past it — and
            // GetCredentialAt(hole) would QueryInterface a freed pointer in
            // SYSTEM-context LogonUI. Dense appends make holes structurally
            // impossible: slots [0, _dwNumCreds) are always live.
            _rgpCredentials[_dwNumCreds] = ppc;
            _dwNumCreds++;
        }
        else
        {
            ppc->Release();
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

// Sets up all the credentials for this provider.
HRESULT CDdsProvider::_EnumerateCredentials()
{
    OutputDebugString(L"_EnumerateCredentials()\n");
    CPLog("_EnumerateCredentials: start ddsUserCount=%d numCreds=%lu",
          g_ddsUsers.count, (unsigned long)_dwNumCreds);

    for (size_t i = 0; i < _dwNumCreds; i++)
    {
        if (_rgpCredentials[i] != NULL)
        {
            _rgpCredentials[i]->Release();
            // AUDIT-2026-06-12 R1 follow-up: NULL the slot after Release. A
            // freed pointer left behind here is what turned a later mid-loop
            // Initialize failure into a use-after-free hole (see the
            // dense-append rationale in _EnumerateOneCredential).
            _rgpCredentials[i] = NULL;
        }
    }
    _dwNumCreds = 0;
    // AUDIT-2026-06-12 R1 follow-up: the loop above destroyed the
    // SetSerialization tile along with every other tile, so the index that
    // labeled it must not survive re-enumeration. A stale index (a) blocks
    // GetCredentialCount's `_dwSetSerializationCred == NO_DEFAULT` check from
    // re-creating the tile for a still-pending _pkiulSetSerialization blob,
    // and (b) lets a second SetSerialization call Release a legitimate user
    // tile that now occupies the stale slot.
    _dwSetSerializationCred = CREDENTIAL_PROVIDER_NO_DEFAULT;

    // If g_ddsUsers is empty, attempt an inline load from the bridge.
    if (g_ddsUsers.count == 0)
    {
        const DWORD kLoadTimeoutMs = 1500;
        DWORD t0 = GetTickCount();
        std::vector<DdsBridgeUser> users = g_provider_bridge.ListDdsUsersTimeout(L"", kLoadTimeoutMs);
        DWORD dt = GetTickCount() - t0;
        CPLog("_EnumerateCredentials: ListDdsUsersTimeout(%lu) took %lu ms, got %zu users",
              kLoadTimeoutMs, dt, users.size());

        if (!users.empty())
        {
            memset(&g_ddsUsers, 0, sizeof(g_ddsUsers));
            int count = 0;
            for (auto& u : users)
            {
                if (count >= MAX_DDS_USERS) break;
                DdsUserEntry& entry = g_ddsUsers.users[count];
                wcscpy_s(entry.subjectUrn,   u.subjectUrn.c_str());
                wcscpy_s(entry.displayName,  u.displayName.c_str());
                wcscpy_s(entry.credentialId, u.credentialId.c_str());
                count++;
            }
            g_ddsUsers.count = count;
            char urnA[80]{};
            WideCharToMultiByte(CP_UTF8, 0,
                g_ddsUsers.users[0].subjectUrn, -1,
                urnA, sizeof(urnA), nullptr, nullptr);
            CPLog("_EnumerateCredentials: inline load OK — %d user(s), first urn='%s'",
                  count, urnA);
        }
        else
        {
            CPLog("_EnumerateCredentials: inline load returned empty — "
                  "will fall back to placeholder tile");
        }
    }

    HRESULT hr = 0;
    if (g_ddsUsers.count > 0) {
        DWORD credIdx = 0;
        for (int i = 0; i < g_ddsUsers.count; i++) {
            // AUDIT-2026-06-11 #7 / AUDIT-2026-06-12 R1 follow-up:
            // never write past _rgpCredentials. MAX_CREDENTIALS is now derived
            // from MAX_DDS_USERS (+1 for the SetSerialization tile), so a full
            // user cache always fits and this guard no longer silently drops
            // enrolled users the way the old 3-slot array did — it stays as the
            // structural backstop. The bound is _dwNumCreds (the dense append
            // cursor _EnumerateOneCredential actually writes at), not credIdx —
            // the two diverge when an Initialize fails, and credIdx is only a
            // log label.
            if (_dwNumCreds >= MAX_CREDENTIALS)
                break;
            // Skip admin accounts — they don't log into Windows
            std::wstring urn(g_ddsUsers.users[i].subjectUrn);
            if (urn.find(L"urn:vouchsafe:admin.") == 0)
                continue;
            hr = _EnumerateOneCredential(credIdx++,
                g_ddsUsers.users[i].displayName,
                L"DDS Passwordless Login",
                g_ddsUsers.users[i].subjectUrn,
                g_ddsUsers.users[i].credentialId
            );
        }
        // If all users were filtered out (only admins), show placeholder
        if (credIdx == 0)
            hr = _EnumerateOneCredential(0, L"Connect DDS authenticator", L"No enrolled users", L"", L"");
    }
    else
    {
        const char* narrowTimestamp = VERSION;
        size_t len = strlen(narrowTimestamp) + 1;

        size_t wideTimestampSize = 0;
        mbstowcs_s(&wideTimestampSize, nullptr, 0, narrowTimestamp, 0);

        wchar_t* wideTimestamp = new wchar_t[wideTimestampSize];

        mbstowcs_s(nullptr, wideTimestamp, wideTimestampSize, narrowTimestamp, len);

        hr = _EnumerateOneCredential(0, L"Connect DDS authenticator", wideTimestamp, L"", L"");
    }
    return hr;
}

// Boilerplate code to create our provider.
HRESULT CDdsProvider_CreateInstance(REFIID riid, void** ppv)
{
    OutputDebugString(L"CDdsProvider_CreateInstance()\n");
    HRESULT hr;

    CDdsProvider* pProvider = new CDdsProvider();

    if (pProvider)
    {
        hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}

// This enumerates a tile for the info in _pkiulSetSerialization.
HRESULT CDdsProvider::_EnumerateSetSerialization()
{
    OutputDebugString(L"_EnumerateSetSerialization()\n");

    // AUDIT-2026-06-12 R1: hard bound the append to the array capacity. The
    // _rgpCredentials array has exactly MAX_CREDENTIALS slots, and
    // GetCredentialCount runs _EnumerateCredentials() (which can legitimately
    // fill all MAX_CREDENTIALS of them) before calling this function in the
    // same pass — so with a full tile set plus a pending SetSerialization
    // blob, the unguarded append would write _rgpCredentials[MAX_CREDENTIALS],
    // an out-of-bounds pointer write in SYSTEM-context LogonUI, and the
    // bumped _dwNumCreds would drive the destructor's Release() over a wild
    // pointer. Enforce the bound before any allocation so the refusal path
    // cannot leak a CDdsCredential.
    if (_dwNumCreds >= MAX_CREDENTIALS)
    {
        CPLog("_EnumerateSetSerialization: credential array full "
              "(_dwNumCreds=%lu, max=%d) — refusing SetSerialization tile",
              (unsigned long)_dwNumCreds, MAX_CREDENTIALS);
        return E_INVALIDARG;
    }

    KERB_INTERACTIVE_LOGON* pkil = &_pkiulSetSerialization->Logon;

    // SAFETY: auto-submit with SetSerialization data could push an empty /
    // stale credential to LSA and contribute to account lockout.
    _bAutoSubmitSetSerializationCred = false;

    WCHAR wszUsername[MAX_PATH] = {0};

    HRESULT hr = StringCbCopyNW(wszUsername, sizeof(wszUsername), pkil->UserName.Buffer, pkil->UserName.Length);

    if (SUCCEEDED(hr))
    {
        if (SUCCEEDED(hr))
        {
            CDdsCredential* pCred = new CDdsCredential();

            if (pCred)
            {
                hr = pCred->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, L"", L"", L"", L"");

                if (SUCCEEDED(hr))
                {
                    _rgpCredentials[_dwNumCreds] = pCred;
                    _dwSetSerializationCred = _dwNumCreds;
                    _dwNumCreds++;
                }
                else
                {
                    // AUDIT-2026-06-12 R1 follow-up: the slot was never
                    // written, so the allocation must be released here —
                    // mirrors _EnumerateOneCredential's failure path.
                    pCred->Release();
                }
            }
            else
            {
                hr = E_OUTOFMEMORY;
            }
        }
    }

    return hr;
}
