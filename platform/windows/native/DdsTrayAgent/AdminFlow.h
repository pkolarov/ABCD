// AdminFlow.h
// Admin setup and user approval flows.
//
// Admin Setup:  MakeCredential (register admin FIDO2 key) -> POST /v1/admin/setup
// Admin Vouch:  List pending users -> GetAssertion (proof of presence) -> POST /v1/admin/vouch

#pragma once

#include <windows.h>

// Run the one-time admin setup flow.
// Registers an admin FIDO2 key and creates an admin identity in dds-node.
// Returns true on success.
bool RunAdminSetupFlow(HWND hwnd);

// Run the admin approval (vouch) flow.
// Shows a list of enrolled users, admin selects one to approve,
// then provides FIDO2 proof-of-presence to sign the vouch.
// Returns true if at least one user was approved.
bool RunAdminApproveFlow(HWND hwnd);
