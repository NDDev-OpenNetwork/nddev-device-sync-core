//! Identified extensions of the existing Server SyncStore and Vault ReplicaPort.
//! They add no auth platform, scheduler, payload store or default-success shim.
use super::*;
use nddev_device_sync_domain::sync::history::{HistoryVersion, VersionedOperation};
/// Server implements this using the same owner/auth/nonce lock and original row
/// storage as SyncStore. Retained exact replay precedes new-basis/cap checks.
pub trait HistoryStore: SyncStore {
    fn append_versioned(
        &self,
        authorization: &AuthenticatedSession,
        signed: SignedRequest,
        operation: VersionedOperation,
        original_body: Vec<u8>,
        now: u64,
    ) -> impl Future<Output = Result<StoredResult, HistoryFailure>> + Send;
    fn history_page(
        &self,
        authorization: &AuthenticatedSession,
        signed: SignedRequest,
        after: u64,
        limit: usize,
        now: u64,
    ) -> impl Future<Output = Result<HistoryPage, HistoryFailure>> + Send;
    /// Original full request/result bytes, at most100 rows/60KiB encoded. A
    /// token names frozen membership, never a mutable latest-entity query.
    fn base_page(
        &self,
        authorization: &AuthenticatedSession,
        signed: SignedRequest,
        token: BaseRead,
        now: u64,
    ) -> impl Future<Output = Result<BasePage, HistoryFailure>> + Send;
}
/// Original row status is needed by V3 without changing the deployed V2 Entry.
pub struct RetainedEntry {
    pub original: Entry,
    pub original_status: u16,
}
pub struct HistoryPage {
    pub history: HistoryVersion,
    pub contents: Page<RetainedEntry>,
}
pub enum HistoryFailure {
    Standard(SyncError),
    Expired(ExpiredHistory),
}
impl From<SyncError> for HistoryFailure {
    fn from(error: SyncError) -> Self {
        Self::Standard(error)
    }
}
pub struct BaseRead {
    pub base: u64,
    pub after_member: u64,
    pub limit: usize,
}
pub struct BasePage {
    pub base: u64,
    pub total_members: usize,
    pub entries: Vec<RetainedEntry>,
    pub next_member: u64,
    pub has_more: bool,
}
/// Wire failure maps to an explicit Unknown/BasisExpired value, never a new
/// Operation or UUID. An adapter still owns the current HTTP error projection.
pub struct ExpiredHistory {
    pub reason: ExpiredReason,
    pub history: HistoryVersion,
}
pub enum ExpiredReason {
    Basis,
    Cursor,
    Checkpoint,
    LegacyMissing,
}
/// Opaque durable stage in the existing storage owner. Guard contains no new
/// Core authority; the adapter retains/checks its actual scope/key/LocalUseFence.
pub struct ActiveStage<S, G> {
    pub stage: S,
    pub guard: G,
    pub base: nddev_device_sync_domain::sync::history::BaseProgress,
    pub through: u64,
    pub tail_at_head: bool,
    /// Current safe install threshold/version metadata from the same storage snapshot.
    /// Not an auth grant; actual install rechecks its original guarded transaction.
    pub install_version: nddev_device_sync_domain::sync::history::InstallVersion,
}
pub enum StageResume<S, G> {
    Absent,
    Active(ActiveStage<S, G>),
    Stale(S),
}
pub trait CheckpointPort: crate::replica::ReplicaPort {
    type Stage;
    type Guard: Eq;
    type BaseContents;
    fn checkpoint_resume(
        &self,
    ) -> impl Future<Output = Result<StageResume<Self::Stage, Self::Guard>, Self::Error>>;
    fn checkpoint_begin(
        &self,
        base: u64,
        total: usize,
    ) -> impl Future<Output = Result<ActiveStage<Self::Stage, Self::Guard>, Self::Error>>;
    fn checkpoint_page(
        &self,
        token: BaseRead,
    ) -> impl Future<
        Output = Result<
            crate::replica::ReadOutcome<VerifiedBasePage<Self::BaseContents>>,
            Self::Error,
        >,
    >;
    fn stage_page(
        &self,
        stage: &Self::Stage,
        page: VerifiedBasePage<Self::BaseContents>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
    fn checkpoint_delta(
        &self,
        stage: &Self::Stage,
        page: crate::replica::VerifiedPage<Self::Page>,
    ) -> impl Future<Output = Result<(), Self::Error>>;
    fn checkpoint_discard(
        &self,
        stage: Self::Stage,
    ) -> impl Future<Output = Result<(), Self::Error>>;
    fn install_checkpoint(
        &self,
        expected: &Self::Guard,
        stage: Self::Stage,
    ) -> impl Future<Output = Result<(), Self::Error>>;
}
pub struct VerifiedBasePage<P> {
    pub contents: P,
    pub base: u64,
    pub expected_members: usize,
    pub sequences: Vec<u64>,
    pub next_member: u64,
    pub has_more: bool,
}
