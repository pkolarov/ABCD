// Configuration.cpp
// Registry-based configuration reader for DDS Auth Bridge.
//

#include "Configuration.h"

CDdsConfiguration::CDdsConfiguration()
    : m_dwDdsNodePort(5551)
    , m_rpId("dds.local")
    , m_bFilterBuiltInProviders(FALSE)
    , m_bAllowPasswordFallback(TRUE)
{
}

void CDdsConfiguration::Load()
{
    HKEY hKey = NULL;
    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS)
    {
        // Key doesn't exist -- use defaults
        OutputDebugStringW(L"DdsAuthBridge: Configuration: Using default settings (registry key not found)");
        return;
    }

    m_dwDdsNodePort         = ReadDword(hKey, L"DdsNodePort", 5551);
    m_bFilterBuiltInProviders = ReadDword(hKey, L"FilterBuiltInProviders", 0) != 0;
    m_bAllowPasswordFallback = ReadDword(hKey, L"AllowPasswordFallback", 1) != 0;

    m_deviceUrn = ReadStringNarrow(hKey, L"DeviceUrn", "");
    m_rpId      = ReadStringNarrow(hKey, L"RpId", "dds.local");
    // A-2 (security review): optional full URL for the dds-node API,
    // including the `pipe:<name>` form added in H-7 step-2b. Empty =
    // legacy port-only behaviour.
    m_apiAddr   = ReadStringNarrow(hKey, L"ApiAddr", "");
    // H-6 step-2: path to the per-install HMAC secret file.
    m_hmacSecretPath = ReadStringWide(hKey, L"HmacSecretPath", L"");

    RegCloseKey(hKey);
}

DWORD CDdsConfiguration::GetDword(_In_ PCWSTR pszValueName, _In_ DWORD dwDefault) const
{
    HKEY hKey = NULL;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, KEY_READ, &hKey);
    if (r != ERROR_SUCCESS) return dwDefault;
    DWORD v = ReadDword(hKey, pszValueName, dwDefault);
    RegCloseKey(hKey);
    return v;
}

DWORD CDdsConfiguration::ReadDword(_In_ HKEY hKey, _In_ PCWSTR pszValueName, _In_ DWORD dwDefault) const
{
    DWORD dwValue = 0;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwType = 0;

    LONG result = RegQueryValueExW(hKey, pszValueName, NULL, &dwType,
        reinterpret_cast<LPBYTE>(&dwValue), &dwSize);

    if (result == ERROR_SUCCESS && dwType == REG_DWORD)
    {
        return dwValue;
    }

    return dwDefault;
}

std::string CDdsConfiguration::ReadStringNarrow(_In_ HKEY hKey, _In_ PCWSTR pszValueName, _In_ const char* pszDefault) const
{
    wchar_t buf[512] = {0};
    DWORD type = 0, cbData = sizeof(buf) - sizeof(wchar_t);
    if (RegQueryValueExW(hKey, pszValueName, NULL, &type,
                         (LPBYTE)buf, &cbData) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ))
    {
        // Convert wide to narrow UTF-8
        char narrow[512] = {0};
        WideCharToMultiByte(CP_UTF8, 0, buf, -1, narrow, sizeof(narrow), nullptr, nullptr);
        if (narrow[0] != '\0')
            return std::string(narrow);
    }
    return std::string(pszDefault);
}

std::wstring CDdsConfiguration::ReadStringWide(_In_ HKEY hKey, _In_ PCWSTR pszValueName, _In_ const wchar_t* pszDefault) const
{
    wchar_t buf[1024] = {0};
    DWORD type = 0, cbData = sizeof(buf) - sizeof(wchar_t);
    if (RegQueryValueExW(hKey, pszValueName, NULL, &type,
                         (LPBYTE)buf, &cbData) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ))
    {
        if (buf[0] != L'\0')
            return std::wstring(buf);
    }
    return std::wstring(pszDefault);
}
