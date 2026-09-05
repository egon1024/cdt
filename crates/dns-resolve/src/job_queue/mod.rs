//! Job-queue coordinator for `delve trace` and session branch queries.
//!
//! Primary traces call [`run_policy`] (via [`crate::trace::run`]). Session branch
//! work uses [`run_branch_job`] for a single alternate-server hop or
//! [`run_expand_cut_branch`] to query every nameserver at a zone cut. Branch
//! subtrees continue single-path through delegation; only the first hop carries
//! [`crate::NodeOrigin::Branch`] with the supplied [`crate::BranchIntent`].

mod branch;
mod coordinator;
mod emitter;
mod pool;
mod queue;
mod result_store;
mod types;
mod worker;

pub use branch::{BranchJobRequest, run_branch_job, run_expand_cut_branch};
pub use coordinator::TerminalSiblingExpansion;
pub(crate) use coordinator::{run_ns_resolution_batch, run_policy, run_terminal_sibling_expansion};
