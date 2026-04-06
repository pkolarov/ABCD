//! # dds-core
//!
//! Core library for the Decentralized Directory Service (DDS).
//!
//! This crate is `no_std`-compatible (with `alloc`) and contains:
//! - Identity management (Vouchsafe ID generation, key handling)
//! - Token parsing, validation, and signature verification
//! - CRDT types for directory state (LWW-Register, 2P-Set, Causal DAG)
//! - Policy evaluation engine
//! - Trust graph traversal and chain validation

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod crdt;
pub mod identity;
pub mod policy;
pub mod token;
pub mod trust;
