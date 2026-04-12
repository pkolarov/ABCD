// DDS Credential Provider — COM DLL entry points.
// Forked from Crayonic CP; updated CLSID for DDS.

#include <windows.h>
#include <unknwn.h>
#include <stdio.h>
#include "Dll.h"
#include "helpers.h"

static LONG g_cRef = 0;
HINSTANCE g_hinst = NULL;

extern HRESULT CDdsProvider_CreateInstance(REFIID riid, void** ppv);
EXTERN_C GUID CLSID_CDdsProvider;

class CClassFactory : public IClassFactory
{
public:
    CClassFactory() : _cRef(1) {}

    IFACEMETHODIMP QueryInterface(REFIID riid, __deref_out void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CClassFactory, IClassFactory),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }
    IFACEMETHODIMP_(ULONG) AddRef()  { return InterlockedIncrement(&_cRef); }
    IFACEMETHODIMP_(ULONG) Release()
    {
        LONG cRef = InterlockedDecrement(&_cRef);
        if (!cRef) delete this;
        return cRef;
    }
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, __deref_out void **ppv)
    {
        if (!pUnkOuter) return CDdsProvider_CreateInstance(riid, ppv);
        *ppv = NULL; return CLASS_E_NOAGGREGATION;
    }
    IFACEMETHODIMP LockServer(BOOL bLock)
    {
        if (bLock) DllAddRef(); else DllRelease();
        return S_OK;
    }
private:
    ~CClassFactory() {}
    long _cRef;
};

HRESULT CClassFactory_CreateInstance(REFCLSID rclsid, REFIID riid, __deref_out void **ppv)
{
    *ppv = NULL;
    if (CLSID_CDdsProvider == rclsid)
    {
        CClassFactory* pcf = new CClassFactory();
        if (!pcf) return E_OUTOFMEMORY;
        HRESULT hr = pcf->QueryInterface(riid, ppv);
        pcf->Release();
        return hr;
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

void DllAddRef()  { InterlockedIncrement(&g_cRef); }
void DllRelease() { InterlockedDecrement(&g_cRef); }

STDAPI DllCanUnloadNow()
{
    return (g_cRef > 0) ? S_FALSE : S_OK;
}

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    {
        CreateDirectoryA("C:\\Temp", nullptr);
        FILE* f = nullptr; fopen_s(&f, "C:\\Temp\\dds_cp.log", "a");
        if (f) {
            SYSTEMTIME st{}; GetLocalTime(&st);
            fprintf(f, "[%02d:%02d:%02d.%03d PID=%lu] DllGetClassObject called\n",
                    st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentProcessId());
            fclose(f);
        }
    }
    HRESULT hr = CClassFactory_CreateInstance(rclsid, riid, ppv);
    {
        FILE* f2 = nullptr; fopen_s(&f2, "C:\\Temp\\dds_cp.log", "a");
        if (f2) {
            SYSTEMTIME st2{}; GetLocalTime(&st2);
            fprintf(f2, "[%02d:%02d:%02d.%03d PID=%lu] DllGetClassObject returning hr=0x%08X ppv=%p\n",
                    st2.wHour, st2.wMinute, st2.wSecond, st2.wMilliseconds, GetCurrentProcessId(),
                    (unsigned)hr, *ppv);
            fclose(f2);
        }
    }
    return hr;
}

STDAPI_(BOOL) DllMain(HINSTANCE hinstDll, DWORD dwReason, void*)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        {
            CreateDirectoryA("C:\\Temp", nullptr);
            FILE* flog = nullptr; fopen_s(&flog, "C:\\Temp\\dds_cp.log", "a");
            if (flog) {
                SYSTEMTIME st{}; GetLocalTime(&st);
                fprintf(flog, "[%02d:%02d:%02d.%03d PID=%lu] DllMain DLL_PROCESS_ATTACH\n",
                        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, GetCurrentProcessId());
                fclose(flog);
            }
        }
        DisableThreadLibraryCalls(hinstDll);
        g_hinst = hinstDll;
        SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                 LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

// ============================================================================
// DllRegisterServer / DllUnregisterServer
// ============================================================================

static HRESULT RegSetSz(HKEY hKey, PCWSTR pszName, PCWSTR pszValue)
{
    DWORD cb = (DWORD)((wcslen(pszValue) + 1) * sizeof(wchar_t));
    return HRESULT_FROM_WIN32(RegSetValueExW(hKey, pszName, 0, REG_SZ,
                                              (const BYTE*)pszValue, cb));
}

STDAPI DllRegisterServer()
{
    wchar_t dllPath[MAX_PATH]{};
    if (!GetModuleFileNameW(g_hinst, dllPath, MAX_PATH))
        return HRESULT_FROM_WIN32(GetLastError());

    wchar_t* pName = wcsrchr(dllPath, L'\\');
    const wchar_t* dllFilename = pName ? pName + 1 : dllPath;

    const wchar_t kClsid[] = L"{a7f3b2c1-9d4e-4f8a-b6c5-2e1d0a3f7b9c}";

    wchar_t expandPath[MAX_PATH]{};
    swprintf_s(expandPath, L"%%SystemRoot%%\\System32\\%s", dllFilename);

    wchar_t clsidKey[160]{};
    swprintf_s(clsidKey, L"SOFTWARE\\Classes\\CLSID\\%s", kClsid);
    HKEY hClsid = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, clsidKey, 0, nullptr, 0,
                         KEY_WRITE, nullptr, &hClsid, nullptr) != ERROR_SUCCESS)
        return E_FAIL;
    RegSetSz(hClsid, nullptr, L"DDS Credential Provider");

    HKEY hInproc = nullptr;
    if (RegCreateKeyExW(hClsid, L"InprocServer32", 0, nullptr, 0,
                         KEY_WRITE, nullptr, &hInproc, nullptr) == ERROR_SUCCESS)
    {
        DWORD cb = (DWORD)((wcslen(expandPath) + 1) * sizeof(wchar_t));
        RegSetValueExW(hInproc, nullptr, 0, REG_EXPAND_SZ, (const BYTE*)expandPath, cb);
        RegSetSz(hInproc, L"ThreadingModel", L"Apartment");
        RegCloseKey(hInproc);
    }
    RegCloseKey(hClsid);

    wchar_t cpKey[256]{};
    swprintf_s(cpKey,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication"
        L"\\Credential Providers\\%s", kClsid);
    HKEY hCp = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, cpKey, 0, nullptr, 0,
                         KEY_WRITE, nullptr, &hCp, nullptr) == ERROR_SUCCESS)
    {
        RegSetSz(hCp, nullptr, L"DdsCredentialProvider");
        RegCloseKey(hCp);
    }

    return S_OK;
}

STDAPI DllUnregisterServer()
{
    const wchar_t kClsid[] = L"{a7f3b2c1-9d4e-4f8a-b6c5-2e1d0a3f7b9c}";

    wchar_t inprocKey[256]{}, clsidKey[160]{}, cpKey[256]{};
    swprintf_s(inprocKey, L"SOFTWARE\\Classes\\CLSID\\%s\\InprocServer32", kClsid);
    swprintf_s(clsidKey,  L"SOFTWARE\\Classes\\CLSID\\%s", kClsid);
    swprintf_s(cpKey,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication"
        L"\\Credential Providers\\%s", kClsid);

    RegDeleteKeyW(HKEY_LOCAL_MACHINE, inprocKey);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, clsidKey);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, cpKey);
    return S_OK;
}
