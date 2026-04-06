//! Delta-sync protocol for efficient state convergence.
//!
//! When two nodes connect or reconnect:
//! 1. Exchange MMR root hashes
//! 2. If different, exchange operation ID sets
//! 3. Transfer missing operations
//! 4. Validate and CRDT-merge each received operation
