// ctap_selftest.h
// Offline hmac-secret PARITY self-test for the raw-CTAP2 fallback (Stage 2 gate).
//
// The pre-first-logon fix performs FIDO2 getAssertion via raw CTAP2 in the
// bridge instead of webauthn.dll. That only works if the raw path derives the
// SAME 32-byte hmac-secret output that webauthn.dll produced at enrollment —
// otherwise the AES-GCM-sealed vault password won't decrypt. This routine proves
// (or disproves) that parity against the real enrolled credential + key, with no
// dependency on the logon path.
//
// Run interactively from an elevated prompt with the security key inserted:
//     DdsAuthBridge.exe --ctap-selftest
//
// For each vault entry it does a raw CTAP2 getAssertion (up=true, no UV, same
// stored salt), decrypts the hmac-secret output, and checks whether the vault
// entry's password decrypts. A green result means Stage 2 is viable.

#pragma once

// Never prints or returns the decrypted password (nor its length).
//
// Exit-code contract:
//   0  PARITY CONFIRMED — at least one credential decrypted its vault entry, no failures
//   1  MIXED           — some credentials passed, some hard-failed
//   2  NO VAULT        — vault missing/unreadable or empty
//   3  INCONCLUSIVE    — no enrolled credential was present on the inserted key
//   4  PARITY FAILED   — credentials exercised but none decrypted (real mismatch)
//   5  NEEDS UV TOKEN  — the key forces UV; parity not disproven, Stage 2 needs pinUvAuthToken
int RunCtapHmacParitySelfTest();
