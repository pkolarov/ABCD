//! Windows DPAPI machine-scope seal/unseal for the node-passphrase blob.
//!
//! The passphrase is a random 32-byte value hex-encoded as a 64-character
//! ASCII string. It is sealed at provisioning time with
//! `CryptProtectData(CRYPTPROTECT_LOCAL_MACHINE)` and written to a `.dpapi`
//! file. At service start, `win_service.rs` reads and unseals it, then sets
//! `DDS_NODE_PASSPHRASE` before the node runtime starts.
//!
//! `CRYPTPROTECT_LOCAL_MACHINE` makes the ciphertext bound to this specific
//! Windows machine (any process running as SYSTEM or Administrators can
//! decrypt). On hosts with a TPM, DPAPI's machine master key is transparently
//! TPM-backed by the OS (Silent-Backup / TPM-Bind); on hosts without a TPM it
//! degrades to software protection that is still off-host-unbindable.

#![cfg(windows)]

use std::ptr;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE,
};
use zeroize::Zeroizing;

/// Seal `plaintext` with DPAPI machine scope. Returns the opaque ciphertext
/// blob. Caller writes this to `%ProgramData%\DDS\node-passphrase.dpapi`.
pub fn seal(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok: BOOL = unsafe {
        CryptProtectData(
            &mut input as *mut _,
            ptr::null(),      // description — optional
            ptr::null_mut(),  // optional entropy
            ptr::null_mut(),  // reserved
            ptr::null_mut(),  // prompt struct
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output as *mut _,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("CryptProtectData failed: 0x{err:08x}"));
    }
    let blob =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe { LocalFree(output.pbData as *mut _) };
    Ok(blob)
}

/// Unseal a DPAPI blob produced by [`seal`].
///
/// Returns the plaintext wrapped in [`Zeroizing`] so it is wiped on drop.
/// Returns an error if the blob was sealed on a different machine or if DPAPI
/// is unavailable.
pub fn unseal(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok: BOOL = unsafe {
        CryptUnprotectData(
            &mut input as *mut _,
            ptr::null_mut(),  // description out — not needed
            ptr::null_mut(),  // optional entropy
            ptr::null_mut(),  // reserved
            ptr::null_mut(),  // prompt struct
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output as *mut _,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        return Err(format!("CryptUnprotectData failed: 0x{err:08x}"));
    }
    let plaintext =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe { LocalFree(output.pbData as *mut _) };
    Ok(Zeroizing::new(plaintext))
}
