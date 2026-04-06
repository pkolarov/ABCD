//! Token parsing, validation, and signature verification.
//!
//! Handles Vouchsafe token types:
//! - Attestation (`vch:attest`) — identity declarations, policy assignments
//! - Vouch (`vch:vouch`) — group membership, delegation
//! - Revocation (`vch:revoke`) — membership removal
//! - Burn (`vch:burn`) — permanent identity retirement
