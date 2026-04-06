//! 2P-Set with remove-wins semantics.
//!
//! Used for group membership. Members can be added and removed.
//! Concurrent add + remove resolves to **removed** (principle of least privilege).
//!
//! Once an element is in the remove set, it cannot be re-added via a simple `add`.
//! Use `force_add` to re-add a previously removed element (requires admin action
//! with a new vouch token).

use alloc::collections::BTreeSet;
use core::fmt;
use serde::{Deserialize, Serialize};

/// A two-phase set with remove-wins conflict resolution.
///
/// - Elements can be added and removed.
/// - An element present in both the add-set and remove-set is considered **absent**
///   (remove-wins for security).
/// - Once removed, an element can only be re-added via `force_add` (which clears
///   it from the remove set — representing a new admin vouch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoPSet<T: Ord + Clone> {
    add_set: BTreeSet<T>,
    remove_set: BTreeSet<T>,
}

impl<T: Ord + Clone> TwoPSet<T> {
    /// Create an empty 2P-Set.
    pub fn new() -> Self {
        Self {
            add_set: BTreeSet::new(),
            remove_set: BTreeSet::new(),
        }
    }

    /// Add an element. Returns `false` if the element is in the remove set
    /// (already removed — use `force_add` to override).
    pub fn add(&mut self, element: T) -> bool {
        if self.remove_set.contains(&element) {
            return false;
        }
        self.add_set.insert(element)
    }

    /// Remove an element. Returns `true` if the element was present.
    pub fn remove(&mut self, element: T) -> bool {
        self.remove_set.insert(element)
    }

    /// Force-add an element, clearing it from the remove set first.
    /// This represents a new admin vouch overriding a prior revocation.
    /// Returns `true` if the element is now a member (always true after force_add).
    pub fn force_add(&mut self, element: T) -> bool {
        self.remove_set.remove(&element);
        self.add_set.insert(element.clone());
        self.contains(&element)
    }

    /// Check if an element is a member (in add-set AND NOT in remove-set).
    pub fn contains(&self, element: &T) -> bool {
        self.add_set.contains(element) && !self.remove_set.contains(element)
    }

    /// Return an iterator over all active members.
    pub fn members(&self) -> impl Iterator<Item = &T> {
        self.add_set
            .iter()
            .filter(|e| !self.remove_set.contains(*e))
    }

    /// Return the number of active members.
    pub fn len(&self) -> usize {
        self.members().count()
    }

    /// Check if there are no active members.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Merge another 2P-Set into this one (CRDT merge).
    /// - add_set = union of both add_sets
    /// - remove_set = union of both remove_sets
    /// Remove-wins: anything in the merged remove_set is excluded.
    pub fn merge(&mut self, other: &Self) {
        for e in &other.add_set {
            self.add_set.insert(e.clone());
        }
        for e in &other.remove_set {
            self.remove_set.insert(e.clone());
        }
    }

    /// Get the raw add set (for testing/diagnostics).
    pub fn add_set(&self) -> &BTreeSet<T> {
        &self.add_set
    }

    /// Get the raw remove set (for testing/diagnostics).
    pub fn remove_set(&self) -> &BTreeSet<T> {
        &self.remove_set
    }
}

impl<T: Ord + Clone> Default for TwoPSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Ord + Clone + PartialEq> PartialEq for TwoPSet<T> {
    fn eq(&self, other: &Self) -> bool {
        self.add_set == other.add_set && self.remove_set == other.remove_set
    }
}

impl<T: Ord + Clone + Eq> Eq for TwoPSet<T> {}

impl<T: Ord + Clone + fmt::Debug> fmt::Display for TwoPSet<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let members: alloc::vec::Vec<_> = self.members().collect();
        write!(f, "{:?}", members)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    #[test]
    fn test_new_empty() {
        let set: TwoPSet<String> = TwoPSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_add_and_contains() {
        let mut set = TwoPSet::new();
        assert!(set.add(String::from("alice")));
        assert!(set.contains(&String::from("alice")));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_add_duplicate() {
        let mut set = TwoPSet::new();
        assert!(set.add(String::from("alice")));
        assert!(!set.add(String::from("alice"))); // already present
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut set = TwoPSet::new();
        set.add(String::from("alice"));
        set.remove(String::from("alice"));
        assert!(!set.contains(&String::from("alice")));
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_remove_wins_over_add() {
        let mut set = TwoPSet::new();
        set.add(String::from("alice"));
        set.remove(String::from("alice"));
        // Trying to re-add after removal fails (remove-wins)
        assert!(!set.add(String::from("alice")));
        assert!(!set.contains(&String::from("alice")));
    }

    #[test]
    fn test_force_add_after_removal() {
        let mut set = TwoPSet::new();
        set.add(String::from("alice"));
        set.remove(String::from("alice"));
        assert!(!set.contains(&String::from("alice")));
        // force_add overrides the removal
        assert!(set.force_add(String::from("alice")));
        assert!(set.contains(&String::from("alice")));
    }

    #[test]
    fn test_members_iterator() {
        let mut set = TwoPSet::new();
        set.add(String::from("alice"));
        set.add(String::from("bob"));
        set.add(String::from("charlie"));
        set.remove(String::from("bob"));
        let members: alloc::vec::Vec<_> = set.members().cloned().collect();
        assert_eq!(members, vec![String::from("alice"), String::from("charlie")]);
    }

    #[test]
    fn test_merge_adds() {
        let mut s1 = TwoPSet::new();
        s1.add(String::from("alice"));

        let mut s2 = TwoPSet::new();
        s2.add(String::from("bob"));

        s1.merge(&s2);
        assert!(s1.contains(&String::from("alice")));
        assert!(s1.contains(&String::from("bob")));
    }

    #[test]
    fn test_merge_remove_wins() {
        // Scenario: one admin adds alice, another concurrently removes alice
        let mut s1 = TwoPSet::new();
        s1.add(String::from("alice"));

        let mut s2 = TwoPSet::new();
        s2.add(String::from("alice"));
        s2.remove(String::from("alice"));

        s1.merge(&s2);
        // Remove wins — alice is NOT a member
        assert!(!s1.contains(&String::from("alice")));
    }

    #[test]
    fn test_merge_commutative() {
        let mut s1 = TwoPSet::new();
        s1.add(String::from("alice"));
        s1.remove(String::from("charlie"));

        let mut s2 = TwoPSet::new();
        s2.add(String::from("bob"));
        s2.add(String::from("charlie"));

        let mut r1 = s1.clone();
        r1.merge(&s2);

        let mut r2 = s2.clone();
        r2.merge(&s1);

        // Both should converge to the same state
        let m1: alloc::vec::Vec<_> = r1.members().cloned().collect();
        let m2: alloc::vec::Vec<_> = r2.members().cloned().collect();
        assert_eq!(m1, m2);
    }

    #[test]
    fn test_merge_idempotent() {
        let mut s1 = TwoPSet::new();
        s1.add(String::from("alice"));

        let s2 = s1.clone();
        s1.merge(&s2);
        s1.merge(&s2);
        assert_eq!(s1.len(), 1);
    }

    #[test]
    fn test_default() {
        let set: TwoPSet<String> = TwoPSet::default();
        assert!(set.is_empty());
    }

    #[test]
    fn test_equality() {
        let mut s1 = TwoPSet::new();
        s1.add(String::from("alice"));
        let mut s2 = TwoPSet::new();
        s2.add(String::from("alice"));
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_display() {
        let mut set = TwoPSet::new();
        set.add(String::from("alice"));
        let display = format!("{}", set);
        assert!(display.contains("alice"));
    }
}
