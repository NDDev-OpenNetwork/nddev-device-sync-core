//! The existing NativeAgent::repository_status consumer uses this reader port.
//! Adapters own OS checkout handles, cancellation, budgets and worker lifetime.
use nddev_device_sync_domain::{modules::ModuleError, repositories::*};
use std::future::Future;

pub trait ReadGitStatus: Send + Sync {
    type Checkout: ?Sized + Sync;
    type Cancellation: Send;
    fn read_git_status(
        &self,
        checkout: &Self::Checkout,
        cancellation: Self::Cancellation,
    ) -> impl Future<Output = Result<LocalGitStatus, ModuleError>> + Send;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalGitClassification {
    Conflicted,
    Unborn,
    Detached,
    Dirty,
    DivergedCached,
    AheadCached,
    BehindCached,
    NoUpstream,
    CleanCached,
}

/// None means the read cannot establish one complete local classification.
/// Every cached classification leaves remote freshness unknown.
pub fn classify_local_status(status: &LocalGitStatus) -> Option<LocalGitClassification> {
    use LocalGitClassification::*;
    if !status.partial_reasons.is_empty() || status.comparison == BranchComparison::Partial {
        return None;
    }
    if status.changes.conflicted > 0 {
        return Some(Conflicted);
    }
    match status.head_kind {
        HeadKind::Unborn => return Some(Unborn),
        HeadKind::Detached => return Some(Detached),
        HeadKind::Branch => {}
    }
    if status.changes != Changes::default() {
        return Some(Dirty);
    }
    if status.upstream.is_none() {
        return Some(NoUpstream);
    }
    match status.comparison {
        BranchComparison::Available { ahead, behind } => Some(match (ahead, behind) {
            (0, 0) => CleanCached,
            (_, 0) => AheadCached,
            (0, _) => BehindCached,
            _ => DivergedCached,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn clean() -> LocalGitStatus {
        LocalGitStatus {
            head_kind: HeadKind::Branch,
            branch: Some("main".into()),
            upstream: Some("origin/main".into()),
            comparison: BranchComparison::Available {
                ahead: 0,
                behind: 0,
            },
            changes: Changes::default(),
            partial_reasons: vec![],
        }
    }
    #[test]
    fn missing_or_partial_evidence_cannot_be_classified_as_clean() {
        let mut status = clean();
        assert_eq!(
            classify_local_status(&status),
            Some(LocalGitClassification::CleanCached)
        );
        status.comparison = BranchComparison::Unavailable;
        assert_eq!(classify_local_status(&status), None);
        status = clean();
        for reason in [
            PartialReason::HistoryBudget,
            PartialReason::RenameBudget,
            PartialReason::SnapshotChanged,
        ] {
            status.partial_reasons = vec![reason];
            assert_eq!(classify_local_status(&status), None);
        }
    }
    #[test]
    fn dirty_and_conflicted_work_retains_its_local_classification() {
        let mut status = clean();
        status.changes.untracked = 1;
        assert_eq!(
            classify_local_status(&status),
            Some(LocalGitClassification::Dirty)
        );
        status.changes.conflicted = 1;
        assert_eq!(
            classify_local_status(&status),
            Some(LocalGitClassification::Conflicted)
        );
    }
}
