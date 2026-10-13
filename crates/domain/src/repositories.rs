//! Transient local status facts. These are not synchronized repository catalog
//! rows, provider identity evidence, mutation authorization, or remote freshness.
use serde::{Deserialize, Serialize};

pub mod catalog;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeadKind {
    Branch,
    Unborn,
    Detached,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Changes {
    pub staged: u32,
    pub unstaged: u32,
    pub untracked: u32,
    pub conflicted: u32,
    pub submodule_changes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BranchComparison {
    NotApplicable,
    Unavailable,
    Available { ahead: u32, behind: u32 },
    Partial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartialReason {
    HistoryBudget,
    RenameBudget,
    SnapshotChanged,
}

/// Serialization serves bounded local worker IPC. No State/EntityKind mapping
/// exists: host paths, git directories, provider credentials and identities are
/// deliberately absent. Native composition owns the checkout input separately.
#[derive(Clone, Serialize, Deserialize)]
pub struct LocalGitStatus {
    pub head_kind: HeadKind,
    pub branch: Option<String>,
    pub upstream: Option<String>,
    pub comparison: BranchComparison,
    pub changes: Changes,
    pub partial_reasons: Vec<PartialReason>,
}
