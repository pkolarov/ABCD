// EnrollmentFlow.h
// User enrollment logic: FIDO2 MakeCredential -> GetAssertion for hmac-secret
// -> encrypt Windows password -> save to vault -> POST /v1/enroll/user.

#pragma once

#include <windows.h>
#include <string>

// Run the full user enrollment flow. Displays UI prompts and calls the
// Windows WebAuthn API. Must be called from the UI thread (or a thread
// with a message pump) so that the WebAuthn dialogs can appear.
//
// hwnd:   Owner window for dialogs and WebAuthn prompts.
//
// Returns true on success, false on user cancel or error (a MessageBox
// is shown to the user before returning in the error case).
bool RunEnrollmentFlow(HWND hwnd);
