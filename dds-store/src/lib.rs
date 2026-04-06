//! # dds-store
//!
//! Storage layer for the Decentralized Directory Service.
//!
//! Provides a trait-based storage abstraction with implementations:
//! - [`RedbBackend`] — Persistent storage via redb (ACID, pure Rust)
//! - [`MemoryBackend`] — In-memory storage for tests and embedded devices

pub mod memory_backend;
pub mod redb_backend;
pub mod traits;
