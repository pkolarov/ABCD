//! Causal DAG for operation ordering.
//!
//! Each directory mutation links to its causal predecessors, forming a DAG.
//! Enables efficient delta-sync and deterministic conflict resolution.
