//! Causal DAG for operation ordering.
//!
//! Each directory mutation links to its causal predecessors, forming a DAG.
//! Enables efficient delta-sync and deterministic conflict resolution.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

/// A single operation in the causal DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    /// Unique operation ID.
    pub id: String,
    /// Author identity URN.
    pub author: String,
    /// IDs of predecessor operations (causal dependencies).
    pub deps: Vec<String>,
    /// The operation payload (opaque bytes — interpreted by higher layers).
    pub data: Vec<u8>,
    /// Timestamp (for ordering hints, not for conflict resolution).
    pub timestamp: u64,
}

/// A causal DAG that tracks operations and their dependencies.
///
/// Operations form a directed acyclic graph where each operation
/// references its causal predecessors. This enables:
/// - Causal ordering of operations
/// - Efficient delta-sync (exchange only missing operations)
/// - Detection of concurrent operations (for CRDT conflict resolution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalDag {
    /// All operations by ID.
    ops: BTreeMap<String, Operation>,
    /// Set of "head" operation IDs (ops with no successors yet).
    heads: BTreeSet<String>,
}

impl CausalDag {
    /// Create an empty DAG.
    pub fn new() -> Self {
        Self {
            ops: BTreeMap::new(),
            heads: BTreeSet::new(),
        }
    }

    /// Insert an operation. Returns `Ok(true)` if newly inserted,
    /// `Ok(false)` if duplicate, or `Err` if a dependency is missing.
    pub fn insert(&mut self, op: Operation) -> Result<bool, DagError> {
        if self.ops.contains_key(&op.id) {
            return Ok(false); // idempotent
        }

        // Validate: all deps must exist in the DAG (or deps is empty for root ops)
        for dep in &op.deps {
            if !self.ops.contains_key(dep) {
                return Err(DagError::MissingDependency(dep.clone()));
            }
        }

        // Remove deps from heads (they now have a successor)
        for dep in &op.deps {
            self.heads.remove(dep);
        }

        // This new op becomes a head
        let id = op.id.clone();
        self.ops.insert(id.clone(), op);
        self.heads.insert(id);

        Ok(true)
    }

    /// Get an operation by ID.
    pub fn get(&self, id: &str) -> Option<&Operation> {
        self.ops.get(id)
    }

    /// Check if the DAG contains an operation.
    pub fn contains(&self, id: &str) -> bool {
        self.ops.contains_key(id)
    }

    /// Get the current head operation IDs.
    pub fn heads(&self) -> &BTreeSet<String> {
        &self.heads
    }

    /// Total number of operations.
    pub fn len(&self) -> usize {
        self.ops.len()
    }

    /// Check if the DAG is empty.
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Get all operation IDs (for sync negotiation).
    pub fn operation_ids(&self) -> BTreeSet<String> {
        self.ops.keys().cloned().collect()
    }

    /// Determine which operations from `other` are missing in `self`.
    pub fn missing_from(&self, other: &CausalDag) -> Vec<String> {
        other
            .ops
            .keys()
            .filter(|id| !self.ops.contains_key(*id))
            .cloned()
            .collect()
    }

    /// Check if two operations are concurrent (neither depends on the other).
    pub fn are_concurrent(&self, id_a: &str, id_b: &str) -> bool {
        !self.is_ancestor(id_a, id_b) && !self.is_ancestor(id_b, id_a)
    }

    /// Check if `ancestor` is an ancestor of `descendant` in the DAG.
    pub fn is_ancestor(&self, ancestor: &str, descendant: &str) -> bool {
        if ancestor == descendant {
            return true;
        }

        let Some(desc_op) = self.ops.get(descendant) else {
            return false;
        };

        // BFS backwards through deps
        let mut queue: Vec<&str> = desc_op.deps.iter().map(|s| s.as_str()).collect();
        let mut visited = BTreeSet::new();

        while let Some(current) = queue.pop() {
            if current == ancestor {
                return true;
            }
            if !visited.insert(current) {
                continue;
            }
            if let Some(op) = self.ops.get(current) {
                for dep in &op.deps {
                    queue.push(dep.as_str());
                }
            }
        }

        false
    }

    /// Merge another DAG into this one. Operations are inserted in
    /// topological order to satisfy dependency constraints.
    /// Returns the number of new operations merged.
    pub fn merge(&mut self, other: &CausalDag) -> Result<usize, DagError> {
        let missing = self.missing_from(other);
        if missing.is_empty() {
            return Ok(0);
        }

        // Collect missing ops and sort topologically
        let mut to_insert: Vec<&Operation> =
            missing.iter().filter_map(|id| other.ops.get(id)).collect();

        // Simple topological sort: insert ops whose deps are all satisfied
        let mut count = 0;
        let mut progress = true;
        while progress && !to_insert.is_empty() {
            progress = false;
            let mut remaining = Vec::new();
            for op in to_insert {
                if op.deps.iter().all(|d| self.ops.contains_key(d)) {
                    self.insert(op.clone())?;
                    count += 1;
                    progress = true;
                } else {
                    remaining.push(op);
                }
            }
            to_insert = remaining;
        }

        if !to_insert.is_empty() {
            return Err(DagError::MissingDependency(to_insert[0].deps[0].clone()));
        }

        Ok(count)
    }
}

impl Default for CausalDag {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CausalDag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CausalDag({} ops, {} heads)",
            self.ops.len(),
            self.heads.len()
        )
    }
}

/// Errors from DAG operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagError {
    /// A required dependency operation is not in the DAG.
    MissingDependency(String),
}

impl fmt::Display for DagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DagError::MissingDependency(id) => write!(f, "missing dependency: {}", id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn op(id: &str, deps: Vec<&str>) -> Operation {
        Operation {
            id: String::from(id),
            author: String::from("test-author"),
            deps: deps.into_iter().map(String::from).collect(),
            data: vec![],
            timestamp: 0,
        }
    }

    #[test]
    fn test_empty_dag() {
        let dag = CausalDag::new();
        assert!(dag.is_empty());
        assert_eq!(dag.len(), 0);
        assert!(dag.heads().is_empty());
    }

    #[test]
    fn test_insert_root() {
        let mut dag = CausalDag::new();
        assert!(dag.insert(op("a", vec![])).unwrap());
        assert_eq!(dag.len(), 1);
        assert!(dag.heads().contains("a"));
    }

    #[test]
    fn test_insert_duplicate_idempotent() {
        let mut dag = CausalDag::new();
        dag.insert(op("a", vec![])).unwrap();
        assert!(!dag.insert(op("a", vec![])).unwrap());
        assert_eq!(dag.len(), 1);
    }

    #[test]
    fn test_insert_with_dep() {
        let mut dag = CausalDag::new();
        dag.insert(op("a", vec![])).unwrap();
        dag.insert(op("b", vec!["a"])).unwrap();
        // "a" is no longer a head, "b" is
        assert!(!dag.heads().contains("a"));
        assert!(dag.heads().contains("b"));
    }

    #[test]
    fn test_insert_missing_dep() {
        let mut dag = CausalDag::new();
        let result = dag.insert(op("b", vec!["a"]));
        assert_eq!(result, Err(DagError::MissingDependency(String::from("a"))));
    }

    #[test]
    fn test_concurrent_ops() {
        let mut dag = CausalDag::new();
        dag.insert(op("root", vec![])).unwrap();
        dag.insert(op("a", vec!["root"])).unwrap();
        dag.insert(op("b", vec!["root"])).unwrap();
        // a and b are concurrent
        assert!(dag.are_concurrent("a", "b"));
        // both are heads
        assert!(dag.heads().contains("a"));
        assert!(dag.heads().contains("b"));
    }

    #[test]
    fn test_is_ancestor() {
        let mut dag = CausalDag::new();
        dag.insert(op("a", vec![])).unwrap();
        dag.insert(op("b", vec!["a"])).unwrap();
        dag.insert(op("c", vec!["b"])).unwrap();
        assert!(dag.is_ancestor("a", "c"));
        assert!(dag.is_ancestor("b", "c"));
        assert!(!dag.is_ancestor("c", "a"));
    }

    #[test]
    fn test_is_ancestor_self() {
        let mut dag = CausalDag::new();
        dag.insert(op("a", vec![])).unwrap();
        assert!(dag.is_ancestor("a", "a"));
    }

    #[test]
    fn test_missing_from() {
        let mut d1 = CausalDag::new();
        d1.insert(op("a", vec![])).unwrap();

        let mut d2 = CausalDag::new();
        d2.insert(op("a", vec![])).unwrap();
        d2.insert(op("b", vec!["a"])).unwrap();

        let missing = d1.missing_from(&d2);
        assert_eq!(missing, vec![String::from("b")]);
    }

    #[test]
    fn test_merge() {
        let mut d1 = CausalDag::new();
        d1.insert(op("a", vec![])).unwrap();

        let mut d2 = CausalDag::new();
        d2.insert(op("a", vec![])).unwrap();
        d2.insert(op("b", vec!["a"])).unwrap();
        d2.insert(op("c", vec!["b"])).unwrap();

        let count = d1.merge(&d2).unwrap();
        assert_eq!(count, 2);
        assert!(d1.contains("b"));
        assert!(d1.contains("c"));
        assert!(d1.heads().contains("c"));
    }

    #[test]
    fn test_merge_commutative() {
        let mut d1 = CausalDag::new();
        d1.insert(op("root", vec![])).unwrap();
        d1.insert(op("a", vec!["root"])).unwrap();

        let mut d2 = CausalDag::new();
        d2.insert(op("root", vec![])).unwrap();
        d2.insert(op("b", vec!["root"])).unwrap();

        let mut r1 = d1.clone();
        r1.merge(&d2).unwrap();

        let mut r2 = d2.clone();
        r2.merge(&d1).unwrap();

        assert_eq!(r1.operation_ids(), r2.operation_ids());
        assert_eq!(r1.heads(), r2.heads());
    }

    #[test]
    fn test_merge_idempotent() {
        let mut d1 = CausalDag::new();
        d1.insert(op("a", vec![])).unwrap();
        d1.insert(op("b", vec!["a"])).unwrap();

        let d2 = d1.clone();
        let count = d1.merge(&d2).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_operation_ids() {
        let mut dag = CausalDag::new();
        dag.insert(op("a", vec![])).unwrap();
        dag.insert(op("b", vec!["a"])).unwrap();
        let ids = dag.operation_ids();
        assert!(ids.contains("a"));
        assert!(ids.contains("b"));
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn test_display() {
        let mut dag = CausalDag::new();
        dag.insert(op("a", vec![])).unwrap();
        dag.insert(op("b", vec!["a"])).unwrap();
        let s = format!("{}", dag);
        assert!(s.contains("2 ops"));
        assert!(s.contains("1 heads"));
    }

    #[test]
    fn test_default() {
        let dag: CausalDag = CausalDag::default();
        assert!(dag.is_empty());
    }

    #[test]
    fn test_diamond_merge() {
        // root → a, root → b, then c depends on both a and b
        let mut dag = CausalDag::new();
        dag.insert(op("root", vec![])).unwrap();
        dag.insert(op("a", vec!["root"])).unwrap();
        dag.insert(op("b", vec!["root"])).unwrap();
        dag.insert(op("c", vec!["a", "b"])).unwrap();

        assert_eq!(dag.heads().len(), 1);
        assert!(dag.heads().contains("c"));
        assert!(dag.is_ancestor("root", "c"));
        assert!(dag.is_ancestor("a", "c"));
        assert!(dag.is_ancestor("b", "c"));
    }

    #[test]
    fn test_dag_error_display() {
        let e = DagError::MissingDependency(String::from("xyz"));
        assert_eq!(format!("{}", e), "missing dependency: xyz");
    }
}
