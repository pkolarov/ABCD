// RefreshVaultFlow.h
// Vault refresh flow (AD-13): re-wrap stored Windows password after a
// password change, without creating a new FIDO2 credential.
//
// Spec: docs/windows-ad-coexistence-spec.md §6.2

#pragma once

#include <windows.h>

// Run the vault refresh flow for the currently-logged-in user.
// Displays UI prompts and calls the Windows WebAuthn API.
// Must be called from the UI thread (or a thread with a message pump)
// so that the WebAuthn dialogs can appear.
//
// hwnd: Owner window for dialogs and WebAuthn prompts.
//
// Returns true on success (vault updated, cooldown cleared).
// Returns false on user cancel, no existing enrollment, or error.
// A MessageBox is shown to the user before returning in every error case.
bool RunRefreshVaultFlow(HWND hwnd);
