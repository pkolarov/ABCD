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

// ---- Diagnostic log to C:\Temp\dds_cp.log ----
static void CPLog(const char* fmt, ...)
{
    CreateDirectoryA("C:\\Temp", nullptr); // ensure dir exists
    FILE* f = nullptr;
    fopen_s(&f, "C:\\Temp\\dds_cp.log", "a");
    if (!f) return;
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
#define MAX_DDS_USERS 5

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

        // ---- Poll bridge status ----
        IPC_RESP_STATUS status{};
        bool connected = (g_provider_bridge.GetStatusShort(200, &status) &&
                          status.deviceConnected);

        if (connected != g_DeviceConnectedLast)
        {
            g_DeviceConnectedLast = connected;
            if (connected)
            {
                CPLog("BridgePoll: device connected — calling TryLoadDdsUsers");
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
                CPLog("BridgePoll: device disconnected — clearing g_ddsUsers");
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
        CPLog("SetUsageScenario: _EnumerateCredentials returned hr=0x%08X _dwNumCreds=%zu",
              (unsigned)hr, _dwNumCreds);
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
                            HeapFree(GetProcessHeap(), 0, _pkiulSetSerialization);

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
    *pdwCount = (g_DeviceConnectedLast) ? SFI_NUM_FIELDS : SFI_NUM_FIELDS_NO_USER;

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
    CPLog("GetCredentialCount: pdwCount=%lu _dwNumCreds=%zu ddsUserCount=%d",
          (unsigned long)*pdwCount, _dwNumCreds, g_ddsUsers.count);
    if (*pdwCount > 0)
    {
        if (_dwSetSerializationCred != CREDENTIAL_PROVIDER_NO_DEFAULT)
        {
            *pdwDefault = 0;
        }
        else
        {
            *pdwDefault = 0;
        }
        // ---- One-shot auto-logon on device connect ----
        LONG armed = InterlockedExchange(&_bPendingAutoLogon, 0L);
        bool haveDdsUser = (g_ddsUsers.count > 0);
        *pbAutoLogonWithDefault = (armed && haveDdsUser) ? TRUE : FALSE;
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
HRESULT CDdsProvider::_EnumerateOneCredential(
    DWORD dwCredentialIndex,
    PCWSTR pwzUsername,
    PCWSTR pwUsernameInfo,
    PCWSTR pwzSubjectUrn
    )
{
    OutputDebugString(L"_EnumerateOneCredential()\n");
    HRESULT hr;

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
            !g_DeviceConnectedLast // noUser flag
        );

        if (SUCCEEDED(hr))
        {
            _rgpCredentials[dwCredentialIndex] = ppc;
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
    CPLog("_EnumerateCredentials: start ddsUserCount=%d numCreds=%zu", g_ddsUsers.count, _dwNumCreds);

    for (size_t i = 0; i < _dwNumCreds; i++)
    {
        if (_rgpCredentials[i] != NULL)
        {
            _rgpCredentials[i]->Release();
        }
    }
    _dwNumCreds = 0;

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
        for (int i = 0; i < g_ddsUsers.count; i++) {
            hr = _EnumerateOneCredential(i,
                g_ddsUsers.users[i].displayName,
                g_ddsUsers.users[i].credentialId,
                g_ddsUsers.users[i].subjectUrn
            );
        }
    }
    else
    {
        const char* narrowTimestamp = VERSION;
        size_t len = strlen(narrowTimestamp) + 1;

        size_t wideTimestampSize = 0;
        mbstowcs_s(&wideTimestampSize, nullptr, 0, narrowTimestamp, 0);

        wchar_t* wideTimestamp = new wchar_t[wideTimestampSize];

        mbstowcs_s(nullptr, wideTimestamp, wideTimestampSize, narrowTimestamp, len);

        hr = _EnumerateOneCredential(0, L"Connect DDS authenticator", wideTimestamp, L"");
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
                hr = pCred->Initialize(_cpus, s_rgCredProvFieldDescriptors, s_rgFieldStatePairs, L"", L"", L"");

                if (SUCCEEDED(hr))
                {
                    _rgpCredentials[_dwNumCreds] = pCred;
                    _dwSetSerializationCred = _dwNumCreds;
                    _dwNumCreds++;
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
