// CDdsCredential — ICredentialProviderCredential for DDS.
// Forked from Crayonic CCrayonicCredential.
// Smart card/PIV/certificate serialization paths stripped.
// Adds GetSerializationDds() for the DDS Auth Bridge FIDO2 flow.

#pragma once

#include <helpers.h>
#include "common.h"
#include "dll.h"
#include "resource.h"

class CDdsCredential : public ICredentialProviderCredential
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
            QITABENT(CDdsCredential, ICredentialProviderCredential),
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }

  public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                 CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);

    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                    PWSTR* ppwszOptionalStatusText,
                                    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus,
                                NTSTATUS ntsSubstatus,
                                PWSTR* ppwszOptionalStatusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

  public:
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                       const FIELD_STATE_PAIR* rgfsp,
                       PCWSTR pwzUsername,
                       PCWSTR pwzUsernameInfo,
                       PCWSTR pwzSubjectUrn,
                       bool noUser = false);

    // DDS Auth Bridge FIDO2 authentication path.
    IFACEMETHODIMP GetSerializationDds(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // Legacy Crayonic Bridge path (kept for BLE badge fallback).
    IFACEMETHODIMP GetSerializationBridge(
        CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
        PWSTR* ppwszOptionalStatusText,
        CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    CDdsCredential();
    virtual ~CDdsCredential();

  private:
    LONG                                  _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO    _cpus;
    bool                                  _noUser;

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR  _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];
    FIELD_STATE_PAIR                      _rgFieldStatePairs[SFI_NUM_FIELDS];
    PWSTR                                 _rgFieldStrings[SFI_NUM_FIELDS];
    ICredentialProviderCredentialEvents*   _pCredProvCredentialEvents;

    LONG auto_tries;

    LPWSTR _pszSubjectUrn;    // DDS Vouchsafe URN for this user
    LPWSTR _pszCredentialId;  // FIDO2 credential ID (base64url) for this user
};
