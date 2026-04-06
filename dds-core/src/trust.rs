//! Trust graph traversal and chain validation.
//!
//! Walks the Vouchsafe vouch chain from a principal back to a trusted root,
//! validating signatures and checking for revocations at each step.
//! Maximum chain depth is configurable (default: 5).
