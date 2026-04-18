//! Last-Writer-Wins Register.
//!
//! Used for mutable directory entry attributes (display name, email, etc.).
//! Conflicts resolved by timestamp ordering. Ties broken by value ordering.
//!
//! **L-11 (security review)**: `timestamp` is a plain `u64`
//! (typically seconds-since-epoch supplied by the caller) — the merge
//! rule is strictly "larger timestamp wins, ties broken by value
//! ordering". This means convergence is driven by wall-clock
//! ordering, NOT causal (happens-before) ordering. Call sites that
//! need causal-correct convergence under clock skew must either
//!
//!   (a) supply a monotonic or hybrid-logical-clock timestamp, or
//!   (b) use a different CRDT (e.g. a CausalDag backed by
//!       `dds_core::crdt::causal_dag`).
//!
//! Current in-repo audit: LwwRegister is only referenced by
//! `dds-loadtest/src/harness.rs` (chaos/soak fixtures) and
//! `dds-core/benches/crdt_merge.rs`. No production directory
//! operation depends on it, so the wall-clock semantics are safe
//! today. If you add a new production caller, re-audit this
//! limitation before relying on convergence.

use core::cmp::Ordering;
use core::fmt;
use serde::{Deserialize, Serialize};

/// A Last-Writer-Wins register that resolves conflicts by timestamp.
/// If timestamps are equal, the lexicographically greater value wins
/// for deterministic convergence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LwwRegister<T: Clone + Ord> {
    value: T,
    timestamp: u64,
}

impl<T: Clone + Ord> LwwRegister<T> {
    /// Create a new register with an initial value and timestamp.
    pub fn new(value: T, timestamp: u64) -> Self {
        Self { value, timestamp }
    }

    /// Get the current value.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Get the timestamp of the current value.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Update the register with a new value and timestamp.
    /// Returns `true` if the value was updated.
    pub fn set(&mut self, value: T, timestamp: u64) -> bool {
        if self.should_update(&value, timestamp) {
            self.value = value;
            self.timestamp = timestamp;
            true
        } else {
            false
        }
    }

    /// Merge another register into this one (CRDT merge).
    /// The register with the higher timestamp wins.
    /// On timestamp tie, the greater value wins.
    pub fn merge(&mut self, other: &Self) -> bool {
        self.set(other.value.clone(), other.timestamp)
    }

    fn should_update(&self, new_value: &T, new_timestamp: u64) -> bool {
        match new_timestamp.cmp(&self.timestamp) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => new_value > &self.value,
        }
    }
}

impl<T: Clone + Ord + PartialEq> PartialEq for LwwRegister<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value && self.timestamp == other.timestamp
    }
}

impl<T: Clone + Ord + Eq> Eq for LwwRegister<T> {}

impl<T: Clone + Ord + fmt::Display> fmt::Display for LwwRegister<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.value, self.timestamp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn test_new_and_value() {
        let reg = LwwRegister::new(String::from("alice"), 100);
        assert_eq!(reg.value(), "alice");
        assert_eq!(reg.timestamp(), 100);
    }

    #[test]
    fn test_set_newer_timestamp() {
        let mut reg = LwwRegister::new(String::from("alice"), 100);
        assert!(reg.set(String::from("bob"), 200));
        assert_eq!(reg.value(), "bob");
        assert_eq!(reg.timestamp(), 200);
    }

    #[test]
    fn test_set_older_timestamp_rejected() {
        let mut reg = LwwRegister::new(String::from("alice"), 200);
        assert!(!reg.set(String::from("bob"), 100));
        assert_eq!(reg.value(), "alice");
    }

    #[test]
    fn test_set_same_timestamp_greater_value_wins() {
        let mut reg = LwwRegister::new(String::from("alice"), 100);
        assert!(reg.set(String::from("bob"), 100)); // "bob" > "alice"
        assert_eq!(reg.value(), "bob");
    }

    #[test]
    fn test_set_same_timestamp_lesser_value_rejected() {
        let mut reg = LwwRegister::new(String::from("bob"), 100);
        assert!(!reg.set(String::from("alice"), 100)); // "alice" < "bob"
        assert_eq!(reg.value(), "bob");
    }

    #[test]
    fn test_merge_newer_wins() {
        let mut r1 = LwwRegister::new(String::from("old"), 100);
        let r2 = LwwRegister::new(String::from("new"), 200);
        assert!(r1.merge(&r2));
        assert_eq!(r1.value(), "new");
    }

    #[test]
    fn test_merge_older_rejected() {
        let mut r1 = LwwRegister::new(String::from("new"), 200);
        let r2 = LwwRegister::new(String::from("old"), 100);
        assert!(!r1.merge(&r2));
        assert_eq!(r1.value(), "new");
    }

    #[test]
    fn test_merge_commutative() {
        let a = LwwRegister::new(String::from("a"), 100);
        let b = LwwRegister::new(String::from("b"), 200);

        let mut r1 = a.clone();
        r1.merge(&b);

        let mut r2 = b.clone();
        r2.merge(&a);

        assert_eq!(r1.value(), r2.value());
    }

    #[test]
    fn test_merge_idempotent() {
        let mut r1 = LwwRegister::new(String::from("a"), 100);
        let r2 = LwwRegister::new(String::from("b"), 200);
        r1.merge(&r2);
        let v1 = r1.value().clone();
        r1.merge(&r2);
        assert_eq!(r1.value(), &v1);
    }

    #[test]
    fn test_equality() {
        let r1 = LwwRegister::new(42u64, 100);
        let r2 = LwwRegister::new(42u64, 100);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_display() {
        let reg = LwwRegister::new(String::from("alice"), 100);
        assert_eq!(format!("{}", reg), "alice@100");
    }
}
