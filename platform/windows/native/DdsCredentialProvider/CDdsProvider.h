// CDdsProvider — ICredentialProvider implementation for DDS.
// Forked from Crayonic CCrayonicProvider; smart card/PIV/BLE paths stripped.
// Enumerates user tiles from DDS Auth Bridge (via named-pipe IPC).

#pragma once

#include <credentialprovider.h>
#include <windows.h>
#include <strsafe.h>
#include <functional>

#include "CDdsCredential.h"
#include <helpers.h>

#define MAX_CREDENTIALS 3
#define MAX_DWORD   0xffffffff

std::function<void(void)> onDdsStatusChangeCallback;

class CDdsProvider : public ICredentialProvider
{
  public:
    // IUnknown
    STDMETHOD_(ULONG, AddRef)()
    {
        return ++_cRef;
    }

    STDMETHOD_(ULONG, Release)()
    {
        LONG cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    STDMETHOD (QueryInterface)(REFIID riid, void** ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CDdsProvider, ICredentialProvider),
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

  public:
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);

    IFACEMETHODIMP Advise(__in ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP GetFieldDescriptorCount(__out DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, __deref_out CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);

    IFACEMETHODIMP GetCredentialCount(__out DWORD* pdwCount,
                                      __out DWORD* pdwDefault,
                                      __out BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex,
                                   __out ICredentialProviderCredential** ppcpc);

    friend HRESULT CDdsProvider_CreateInstance(REFIID riid, __deref_out void** ppv);

    void OnConnectStatusChanged(void);

  protected:
    CDdsProvider();
    __override ~CDdsProvider();

  private:
    HRESULT _EnumerateOneCredential(__in DWORD dwCredentialIndex,
                                    __in PCWSTR pwzUsername,
                                    __in PCWSTR pwUsernameInfo,
                                    __in PCWSTR pwzSubjectUrn);
    HRESULT _EnumerateSetSerialization();
    HRESULT _EnumerateCredentials();
    void _ReleaseEnumeratedCredentials();
    void _CleanupSetSerialization();

  private:
    LONG                                    _cRef;
    CDdsCredential*                         _rgpCredentials[MAX_CREDENTIALS];
    DWORD                                   _dwNumCreds;
    KERB_INTERACTIVE_UNLOCK_LOGON*          _pkiulSetSerialization;
    DWORD                                   _dwSetSerializationCred;
    bool                                    _bAutoSubmitSetSerializationCred;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;
    ICredentialProviderEvents*              _pcpe;
    UINT_PTR                                _upAdviseContext;
    volatile LONG                           _bNeedsReEnumeration;
    volatile LONG                           _bPendingAutoLogon;
};
