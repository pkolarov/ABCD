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
    // **A-2 (security review)**: full base URL for the dds-node API.
    // Empty string = fall back to `http://127.0.0.1:<DdsNodePort>` for
    // backwards compatibility. Otherwise this is passed to
    // `CDdsNodeHttpClient::SetBaseUrl` and may carry a `pipe:<name>`
    // form to select the named-pipe transport surfaced by H-7 step-2b.
    // The MSI writes a default value matching the Rust node.toml so
    // operators don't have to hand-edit the registry to use the
    // hardened transport.
    const std::string& ApiAddr() const { return m_apiAddr; }
    // **H-6 step-2 (security review)**: per-install shared secret for
    // response-body MAC verification. Provisioned by the MSI at install
    // time, read by both dds-node (via `node_hmac_secret_path` in
    // network.api_auth) and this service. Empty string = MAC
    // verification disabled (transitional; deployments SHOULD set it).
    const std::wstring& HmacSecretPath() const { return m_hmacSecretPath; }

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
    std::wstring ReadStringWide(_In_ HKEY hKey, _In_ PCWSTR pszValueName, _In_ const wchar_t* pszDefault) const;

    // DDS Node connection
    DWORD       m_dwDdsNodePort;    // default 5551 (legacy; ApiAddr takes precedence)
    std::string m_apiAddr;          // A-2: full API URL; empty = fall back to port
    std::string m_deviceUrn;        // device URN for this machine
    std::string m_rpId;             // FIDO2 relying party ID (default "dds.local")

    // CP filter
    BOOL  m_bFilterBuiltInProviders;

    // Auth methods
    BOOL  m_bAllowPasswordFallback;

    // H-6 step-2: response-MAC secret file path.
    std::wstring m_hmacSecretPath;
};
