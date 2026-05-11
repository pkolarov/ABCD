// EnrollmentFlow.h
// User enrollment logic: FIDO2 MakeCredential -> GetAssertion for hmac-secret
// -> encrypt Windows password -> save to vault -> POST /v1/enroll/user.
//
// Two entry points:
//   * RunEnrollmentFlow(HWND)              — legacy interactive flow used by
//                                            DdsTrayAgent (modal dialogs).
//   * RunEnrollmentFlowEx(opts)            — generalized flow with optional
//                                            preset password and a phase
//                                            callback for NDJSON status —
//                                            used by DdsEnrollUser.exe to
//                                            drive the wizard from PowerShell.

#pragma once

#include <windows.h>
#include <functional>
#include <string>

// Result of RunEnrollmentFlowEx. `success` is true once the local vault
// entry has been saved AND the server enroll POST succeeded. If the vault
// was saved but the server call failed, `success` is true and `serverPosted`
// is false (the user can sign in locally; admin approval can wait).
struct EnrollmentFlowResult
{
    bool        success      = false;
    bool        serverPosted = false;   // POST /v1/enroll/user succeeded
    std::string urn;                    // Enrolled user URN (server response)
    std::string jti;                    // Enrollment JTI (server response)
    std::string errorPhase;             // Phase that failed: "password" |
                                        //   "make_credential" | "get_assertion" |
                                        //   "encrypt" | "vault_save" | "post_enroll"
    std::string errorMessage;           // Human-readable error
};

// Phases emitted to onPhase as JSON one-liners (NDJSON). Stable strings.
//   {"phase":"start"}
//   {"phase":"touch1_prompt"}
//   {"phase":"key_made"}
//   {"phase":"touch2_prompt"}
//   {"phase":"hmac_done"}
//   {"phase":"vault_written"}
//   {"phase":"enroll_posted","urn":"...","jti":"..."}
//   {"phase":"enroll_failed_local_only","message":"..."}      // POST failed; local OK
//   {"phase":"error","at":"<phase>","message":"..."}
//   {"phase":"cancelled"}                                     // user cancelled
struct EnrollmentFlowOptions
{
    HWND hwnd = NULL;                                  // Owner window for the
                                                       // Windows WebAuthn UI.
                                                       // HWND_DESKTOP is OK
                                                       // for a CLI process.
    bool interactive = true;                           // If true, show the
                                                       // legacy MessageBoxes
                                                       // and password prompt.
                                                       // If false, the caller
                                                       // is responsible for UI
                                                       // and MUST set
                                                       // presetPassword.
    std::wstring presetPassword;                       // If non-empty, skip
                                                       // the password prompt
                                                       // and use this value.
    std::function<void(const std::string&)> onPhase;   // Called once per
                                                       // phase boundary with
                                                       // a JSON line (no
                                                       // trailing newline).
};

// Legacy interactive entry point (used by DdsTrayAgent). Shows MessageBox
// dialogs for status and PromptForPassword for the password. Must be called
// from a UI thread.
//
// Returns true on success (vault written; server POST may have failed —
// matches the legacy semantics).
bool RunEnrollmentFlow(HWND hwnd);

// Generalized entry point. Honors `interactive` and `presetPassword`.
// `onPhase` is optional (may be null). Returns a structured result.
EnrollmentFlowResult RunEnrollmentFlowEx(const EnrollmentFlowOptions& opts);
