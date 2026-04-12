// Configuration.h
// Registry-based configuration reader for the DDS Auth Bridge Service.
//

#pragma once

#include <windows.h>
#include <cstdint>
#include <string>

class CDdsConfiguration
{
public:
    CDdsConfiguration();

    // Load settings from the registry. Uses defaults for missing values.
    void Load();

    // --- DDS Node Settings ---
    DWORD DdsNodePort() const { return m_dwDdsNodePort; }
    const std::string& DeviceUrn() const { return m_deviceUrn; }
    const std::string& RpId() const { return m_rpId; }

    // --- Credential Provider Filter Settings ---
    BOOL  FilterBuiltInProviders() const { return m_bFilterBuiltInProviders; }

    // --- Auth Method Settings ---
    BOOL  AllowPasswordFallback() const { return m_bAllowPasswordFallback; }

    // --- Generic registry reader ---
    DWORD GetDword(_In_ PCWSTR pszValueName, _In_ DWORD dwDefault) const;

private:
    static constexpr const wchar_t* REG_KEY_PATH = L"SOFTWARE\\DDS\\AuthBridge";

    DWORD ReadDword(_In_ HKEY hKey, _In_ PCWSTR pszValueName, _In_ DWORD dwDefault) const;
    std::string ReadStringNarrow(_In_ HKEY hKey, _In_ PCWSTR pszValueName, _In_ const char* pszDefault) const;

    // DDS Node connection
    DWORD       m_dwDdsNodePort;    // default 5551
    std::string m_deviceUrn;        // device URN for this machine
    std::string m_rpId;             // FIDO2 relying party ID (default "dds.local")

    // CP filter
    BOOL  m_bFilterBuiltInProviders;

    // Auth methods
    BOOL  m_bAllowPasswordFallback;
};
