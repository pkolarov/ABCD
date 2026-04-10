# DDS Windows Credential Provider (.NET stub — SUPERSEDED)

> **This .NET stub has been superseded by the native C++ Credential
> Provider at [`platform/windows/native/DdsCredentialProvider/`](../native/DdsCredentialProvider/).**
> The native implementation is forked from the [Crayonic Credential
> Provider](../../docs/crayonic-cp-integration-plan.md) and provides
> production-quality COM integration with the Windows logon screen,
> FIDO2 authentication via the DDS Auth Bridge service, and proper
> LSA hand-off via `KERB_INTERACTIVE_UNLOCK_LOGON`.
>
> This file is kept for reference and for the `DdsLocalClient` HTTP
> client class which may still be useful for .NET-based integration
> tests or the `DdsPolicyAgent`.

---

*Original description:*

A `net8.0` class library that bridges Windows logon to a locally
running `dds-node` over its HTTP API (`http://127.0.0.1:5551/v1/*`).

This is the **Phase 2 minimum viable surface**. It is intentionally a
stub of the Windows Credential Provider COM contract — enough to
demonstrate the integration shape and to be unit-testable on a dev
machine, but not enough to actually appear on the Windows logon screen.

## What it does

- `DdsLocalClient` — `HttpClient` wrapper that POSTs to
  `/v1/session` with a passkey-derived subject URN and parses the
  `SessionDocument` response (`session_id`, `token_b64`, `expires_at`).
- `DdsLocalClient.SubjectUrnForCredential(credentialId)` — derives a
  Vouchsafe-shaped URN (`urn:vouchsafe:passkey.<base32-sha256>`) from
  a FIDO2 credential id.
- `ICredentialProvider` — managed analogue of the unmanaged COM
  interface from `credentialprovider.h`. Lets us call `Authenticate`
  in unit tests without the COM runtime.
- `DdsCredentialProvider` — `[ComVisible]` class tagged with the
  stable CLSID `8C0DBE9A-5E27-4DDA-9A4B-3B5C8A6E2A11` and
  `ClassInterfaceType.None`, ready to be picked up by an installer
  that knows how to register it.

## What is stubbed (and why)

| Piece | Status | Why |
|---|---|---|
| Native COM `ICredentialProvider` import | not done | Requires `[ComImport]` of Microsoft's interface tree (`ICredentialProviderCredential`, `ICredentialProviderTile`, `ICredentialProviderEvents`, ...). Several days of binding work. |
| `comhost.dll` packaging | not done | `EnableComHosting=true` is set in the csproj, but we don't ship the native shim or `.comhost.dll` per build. |
| LSA / Authentication Package handoff | not done | Real logon needs `KerbInteractiveLogon` or a custom AP DLL signed for Windows. |
| Installer | not done | A future MSI/WiX project would write the registry keys below. |
| Tests | not done on macOS | The csproj is syntactically valid C#, but `dotnet build` is not run from the dev host (macOS). CI on a Windows runner can build it. |

## Registering on Windows (when the stubs are filled in)

A real installer would write two sets of registry keys:

```
HKLM\SOFTWARE\Classes\CLSID\{8C0DBE9A-5E27-4DDA-9A4B-3B5C8A6E2A11}
    @ = "DDS Credential Provider"
    InprocServer32\
        @ = "C:\Program Files\DDS\DdsCredentialProvider.comhost.dll"
        ThreadingModel = "Apartment"

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\
    Credential Providers\{8C0DBE9A-5E27-4DDA-9A4B-3B5C8A6E2A11}
    @ = "DDS Credential Provider"
```

After registration, run:

```
regsvr32 /n /i:user "C:\Program Files\DDS\DdsCredentialProvider.comhost.dll"
```

and reboot. Windows LogonUI enumerates the `Authentication\Credential
Providers` key and instantiates each CLSID via `CoCreateInstance`.

## Local development

Build on a Windows host with the .NET 8 SDK:

```
dotnet build platform/windows/DdsCredentialProvider/DdsCredentialProvider.csproj
```

The library targets `net8.0` and depends only on
`System.Net.Http.Json` from NuGet. It must run on the same machine as
`dds-node` so it can reach `127.0.0.1:5551`.

## Threat model note

Because the credential provider uses an unauthenticated `127.0.0.1`
HTTP channel, dds-node must reject any request that does not originate
from the local machine. Phase 1's HTTP server already binds to
loopback only; we should additionally consider a per-install bearer
token in `dds-node` config before this provider ships to production.
