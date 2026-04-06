//! 2P-Set with remove-wins semantics.
//!
//! Used for group membership. Members can be added and removed.
//! Concurrent add + remove resolves to **removed** (principle of least privilege).
