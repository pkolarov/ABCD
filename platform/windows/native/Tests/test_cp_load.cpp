// test_cp_load.cpp — Test harness that simulates what LogonUI does
// with our credential provider, without needing the lock screen.
//
// Build: cl /EHsc /std:c++17 /DUNICODE /D_UNICODE test_cp_load.cpp ole32.lib
// Run:   test_cp_load.exe

#include <windows.h>
#include <credentialprovider.h>
#include <stdio.h>

// {a7f3b2c1-9d4e-4f8a-b6c5-2e1d0a3f7b9c}
static const CLSID CLSID_CDdsProvider = {
    0xa7f3b2c1, 0x9d4e, 0x4f8a,
    { 0xb6, 0xc5, 0x2e, 0x1d, 0x0a, 0x3f, 0x7b, 0x9c }
};

int wmain()
{
    printf("=== DDS Credential Provider Test Harness ===\n\n");

    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        printf("CoInitializeEx failed: 0x%08X\n", (unsigned)hr);
        return 1;
    }

    printf("[1] CoCreateInstance(CLSID_CDdsProvider, IID_ICredentialProvider)...\n");
    ICredentialProvider* pProvider = nullptr;
    hr = CoCreateInstance(CLSID_CDdsProvider, NULL, CLSCTX_INPROC_SERVER,
                          IID_ICredentialProvider, (void**)&pProvider);
    printf("    hr = 0x%08X, pProvider = %p\n", (unsigned)hr, pProvider);
    if (FAILED(hr)) {
        printf("    FAILED — cannot create provider\n");
        CoUninitialize();
        return 1;
    }

    printf("\n[2] SetUsageScenario(CPUS_LOGON, 0)...\n");
    hr = pProvider->SetUsageScenario(CPUS_LOGON, 0);
    printf("    hr = 0x%08X\n", (unsigned)hr);
    if (FAILED(hr)) {
        printf("    FAILED — SetUsageScenario error\n");
        pProvider->Release();
        CoUninitialize();
        return 1;
    }

    printf("\n[3] GetCredentialCount()...\n");
    DWORD dwCount = 0;
    DWORD dwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    BOOL bAutoLogon = FALSE;
    hr = pProvider->GetCredentialCount(&dwCount, &dwDefault, &bAutoLogon);
    printf("    hr = 0x%08X, count = %lu, default = %lu, autoLogon = %d\n",
           (unsigned)hr, dwCount, dwDefault, bAutoLogon);

    for (DWORD i = 0; i < dwCount; i++) {
        printf("\n[4.%lu] GetCredentialAt(%lu)...\n", i, i);
        ICredentialProviderCredential* pCred = nullptr;
        hr = pProvider->GetCredentialAt(i, &pCred);
        printf("    hr = 0x%08X, pCred = %p\n", (unsigned)hr, pCred);
        if (SUCCEEDED(hr) && pCred) {
            // Try GetStringValue for SFI_USERNAME (field 1)
            LPWSTR pszVal = nullptr;
            hr = pCred->GetStringValue(1, &pszVal);
            if (SUCCEEDED(hr) && pszVal) {
                printf("    Username field: %ls\n", pszVal);
                CoTaskMemFree(pszVal);
            }
            // Try GetStringValue for SFI_USERNAME_INFO (field 2)
            pszVal = nullptr;
            hr = pCred->GetStringValue(2, &pszVal);
            if (SUCCEEDED(hr) && pszVal) {
                printf("    Info field: %ls\n", pszVal);
                CoTaskMemFree(pszVal);
            }
            pCred->Release();
        }
    }

    printf("\n=== Test complete ===\n");
    pProvider->Release();
    CoUninitialize();

    // Show log
    printf("\n=== dds_cp.log contents ===\n");
    FILE* f = nullptr;
    fopen_s(&f, "C:\\Temp\\dds_cp.log", "r");
    if (f) {
        char buf[512];
        while (fgets(buf, sizeof(buf), f)) fputs(buf, stdout);
        fclose(f);
    } else {
        printf("(no log file)\n");
    }

    return 0;
}
