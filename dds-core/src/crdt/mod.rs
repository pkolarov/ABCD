//! CRDT types for directory state.
//!
//! - [`LwwRegister`] — Last-Writer-Wins register for mutable attributes
//! - [`TwoPSet`] — 2P-Set with remove-wins for group membership
//! - [`CausalDag`] — DAG-based operation ordering

pub mod causal_dag;
pub mod lww_register;
pub mod twop_set;
