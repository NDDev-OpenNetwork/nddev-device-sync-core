//! One bounded replica/recovery policy for native and browser callers.
//! Adapters own protected authorization, crypto, verified wire and atomic I/O.
use crate::sync::history::{ActiveStage, BaseRead, CheckpointPort, StageResume, VerifiedBasePage};
use nddev_device_sync_domain::sync::{history::*, *};
use std::{future::Future, time::Duration};
pub mod writer;
pub use writer::*;
pub const MAX_UPLOADS: usize = 16;
pub const MAX_PULL_PAGES: usize = 16;
pub const BATCH_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadMode {
    Legacy,
    Versioned,
}
pub struct Capabilities {
    pub reader_versions: [u8; 2],
    pub writer: WriterMode,
    pub retention: bool,
}
pub enum Negotiation {
    LegacyUnsupported,
    Capabilities(Capabilities),
}
pub struct PreparedContext {
    pub key_id: String,
    pub observed_basis: Option<u64>,
}
pub enum Preparation {
    Ready(PreparedContext),
    ReadBudgetExhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownReason {
    BasisExpired,
    LegacyMissing,
}
pub enum AppendOutcome<R> {
    Receipt(R),
    Unknown(UnknownReason),
}
pub enum ReadOutcome<P> {
    Page(P),
    Expired(HistoryVersion),
    LegacyExpired,
}

/// Core constructs exactly once. Discovery and all recovery reads borrow it;
/// adapters cannot construct a replacement or reset counters.
pub struct BatchBudget {
    reads: usize,
    uploads: usize,
}
impl BatchBudget {
    fn new() -> Self {
        Self {
            reads: MAX_PULL_PAGES,
            uploads: MAX_UPLOADS,
        }
    }
    pub fn take_read(&mut self) -> bool {
        if self.reads == 0 {
            false
        } else {
            self.reads -= 1;
            true
        }
    }
    pub fn reads_remaining(&self) -> usize {
        self.reads
    }
    fn take_upload(&mut self) -> bool {
        if self.uploads == 0 {
            false
        } else {
            self.uploads -= 1;
            true
        }
    }
}
pub struct VerifiedPage<P> {
    pub contents: P,
    pub next_after: u64,
    pub entries: usize,
    pub has_more: bool,
    pub history: Option<HistoryVersion>,
}
impl<P> VerifiedPage<P> {
    fn validate_after(&self, cursor: u64, mode: ReadMode) -> Result<(), SyncError> {
        if self.entries > MAX_PAGE_ITEMS
            || self.has_more && self.entries == 0
            || self.next_after > MAX_REVISION
            || cursor.checked_add(self.entries as u64) != Some(self.next_after)
        {
            return Err(SyncError::Invalid);
        }
        match (mode, self.history) {
            (ReadMode::Legacy, None) => Ok(()),
            (ReadMode::Versioned, Some(history)) => {
                history.validate()?;
                if cursor < history.floor
                    || self.next_after > history.head
                    || (!self.has_more && self.next_after != history.head)
                    || self.has_more && self.next_after >= history.head
                {
                    return Err(SyncError::Invalid);
                }
                Ok(())
            }
            _ => Err(SyncError::Invalid),
        }
    }
}
pub struct Progress {
    pub uploaded: usize,
    pub received: usize,
    pub cursor: u64,
    pub inbox_at_head: bool,
    pub caught_up: bool,
    pub capacity_probe: Option<CapacityProbeOutcome>,
}
/// Actual result of the one-original check, after durable local handling.
/// Unknown preserves the original and excludes it from later claims; it does
/// not assert whether that original ever committed on the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityProbeOutcome {
    Receipt,
    Unknown,
    NoEligibleWork,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReconcileMode {
    Full,
    Inbox,
    CapacityProbe,
}
pub trait ReplicaPort {
    type Error: From<SyncError>;
    type Pending;
    type Receipt;
    type Page;
    fn negotiate(&self) -> impl Future<Output = Result<Negotiation, Self::Error>>;
    fn writer_facts(&self) -> impl Future<Output = Result<WriterFacts, Self::Error>>;
    /// Current protected auth/key/fence checked by the adapter. Take one read
    /// BEFORE every History/Base key-discovery request. No new batch deadline.
    fn prepare_context(
        &self,
        mode: ReadMode,
        budget: &mut BatchBudget,
    ) -> impl Future<Output = Result<Preparation, Self::Error>>;
    fn confirm_writer(
        &self,
        expected: &WriterFacts,
        confirmed: ConfirmedWriter,
    ) -> impl Future<Output = Result<(), Self::Error>>;
    fn claim(&self) -> impl Future<Output = Result<Vec<Self::Pending>, Self::Error>>;
    /// Must claim at most one root, without marking other work dispatched.
    fn claim_one(&self) -> impl Future<Output = Result<Option<Self::Pending>, Self::Error>>;
    fn append_outcome(
        &self,
        pending: &Self::Pending,
    ) -> impl Future<Output = Result<AppendOutcome<Self::Receipt>, Self::Error>>;
    /// Exact dispatched original check; metadata only, never settlement/rewrite.
    fn remember_unknown(
        &self,
        pending: &Self::Pending,
        reason: UnknownReason,
    ) -> impl Future<Output = Result<(), Self::Error>>;
    fn acknowledge(
        &self,
        pending: Self::Pending,
        receipt: Self::Receipt,
    ) -> impl Future<Output = Result<(), Self::Error>>;
    fn cursor(&self) -> impl Future<Output = Result<u64, Self::Error>>;
    fn history_outcome(
        &self,
        mode: ReadMode,
        after: u64,
        limit: usize,
    ) -> impl Future<Output = Result<ReadOutcome<VerifiedPage<Self::Page>>, Self::Error>>;
    fn ingest(&self, page: Self::Page) -> impl Future<Output = Result<(), Self::Error>>;
    fn caught_up(&self, cursor: u64) -> impl Future<Output = Result<bool, Self::Error>>;
}
fn negotiated(value: Negotiation) -> Result<(ReadMode, Option<WriterMode>), SyncError> {
    match value {
        Negotiation::LegacyUnsupported => Ok((ReadMode::Legacy, None)),
        Negotiation::Capabilities(c) => {
            if !matches!(c.reader_versions, [2, 3] | [3, 2])
                || c.retention != (c.writer == WriterMode::V3)
            {
                return Err(SyncError::Invalid);
            }
            Ok((ReadMode::Versioned, Some(c.writer)))
        }
    }
}
fn validate_stage<S, G>(stage: &ActiveStage<S, G>) -> Result<(), SyncError> {
    let b = stage.base;
    if b.base > MAX_REVISION
        || b.total > MAX_OPERATIONS as usize
        || b.received > b.total
        || b.after_member > b.base
        || stage.through < b.base
        || stage.through > MAX_REVISION
        || stage.install_version.cursor > MAX_REVISION
        || stage.install_version.known_committed_seq > MAX_REVISION
        || (!b.complete() && (stage.through != b.base || stage.tail_at_head))
    {
        return Err(SyncError::Invalid);
    }
    Ok(())
}
/// Reconcile all paths with one budget/deadline owned by the caller. A resumed
/// stage wins before claim and remains opaque/durable across partial batches.
pub async fn reconcile_history<P: CheckpointPort>(
    port: &P,
    inbox_only: bool,
) -> Result<Progress, P::Error> {
    reconcile_mode(
        port,
        if inbox_only {
            ReconcileMode::Inbox
        } else {
            ReconcileMode::Full
        },
    )
    .await
}
pub async fn probe_capacity<P: CheckpointPort>(port: &P) -> Result<Progress, P::Error> {
    reconcile_mode(port, ReconcileMode::CapacityProbe).await
}
async fn reconcile_mode<P: CheckpointPort>(
    port: &P,
    mode_request: ReconcileMode,
) -> Result<Progress, P::Error> {
    let mut budget = BatchBudget::new();
    let mut progress = Progress {
        uploaded: 0,
        received: 0,
        cursor: port.cursor().await?,
        inbox_at_head: false,
        caught_up: false,
        capacity_probe: None,
    };
    let (mode, writer) = negotiated(port.negotiate().await?)?;
    let facts = port.writer_facts().await?;
    if facts
        .confirmed
        .as_ref()
        .is_some_and(|c| c.mode == WriterMode::V3 && writer != Some(WriterMode::V3))
    {
        return Err(SyncError::Invalid.into());
    }
    let prepared = match port.prepare_context(mode, &mut budget).await? {
        Preparation::Ready(v) => v,
        Preparation::ReadBudgetExhausted => return Ok(progress),
    };
    if prepared.key_id.is_empty() {
        return Err(SyncError::KeyRegistration.into());
    }
    if facts
        .confirmed
        .as_ref()
        .is_some_and(|c| c.key_id != prepared.key_id)
    {
        return Err(SyncError::KeyConflict.into());
    }
    if let Some(writer) = writer {
        if let Some(basis) = prepared.observed_basis {
            let next = confirm_writer_facts(&facts, writer, &prepared.key_id, basis)?;
            if facts.confirmed.as_ref() != Some(&next) {
                port.confirm_writer(&facts, next).await?;
            }
        } else if !facts
            .confirmed
            .as_ref()
            .is_some_and(|c| c.mode == writer && c.key_id == prepared.key_id)
        {
            return Err(SyncError::KeyRegistration.into());
        }
    }
    let mut restarts = 0;
    let resumed = match port.checkpoint_resume().await? {
        StageResume::Absent => None,
        StageResume::Active(s) => {
            validate_stage(&s)?;
            Some(s)
        }
        StageResume::Stale(s) => {
            port.checkpoint_discard(s).await?;
            restarts = 1;
            None
        }
    };
    let had_stage = resumed.is_some();
    let mut recovery_started = had_stage;
    if let Some(stage) = resumed {
        if mode != ReadMode::Versioned {
            return Err(SyncError::Invalid.into());
        }
        if !recover(
            port,
            Some(stage),
            None,
            &mut budget,
            &mut restarts,
            &mut progress,
        )
        .await?
        {
            progress.cursor = port.cursor().await?;
            return Ok(progress);
        }
    }
    if mode_request != ReconcileMode::Inbox && !had_stage {
        let probe = mode_request == ReconcileMode::CapacityProbe;
        let pending = if probe {
            port.claim_one().await?.into_iter().collect()
        } else {
            port.claim().await?
        };
        if pending.len() > if probe { 1 } else { MAX_UPLOADS } {
            return Err(SyncError::Invalid.into());
        }
        if probe && pending.is_empty() {
            progress.capacity_probe = Some(CapacityProbeOutcome::NoEligibleWork);
        }
        for pending in pending {
            if !budget.take_upload() {
                break;
            }
            let handled = match port.append_outcome(&pending).await? {
                AppendOutcome::Receipt(receipt) => {
                    port.acknowledge(pending, receipt).await?;
                    progress.uploaded += 1;
                    CapacityProbeOutcome::Receipt
                }
                AppendOutcome::Unknown(reason) => {
                    port.remember_unknown(&pending, reason).await?;
                    CapacityProbeOutcome::Unknown
                }
            };
            if probe {
                progress.capacity_probe = Some(handled);
            }
        }
        if probe {
            // A later inbox error must not hide the actual handled outcome.
            return Ok(progress);
        }
    }
    while budget.take_read() {
        let cursor = port.cursor().await?;
        match port.history_outcome(mode, cursor, MAX_PAGE_ITEMS).await? {
            ReadOutcome::Page(page) => {
                page.validate_after(cursor, mode)?;
                let more = page.has_more;
                progress.received += page.entries;
                progress.cursor = page.next_after;
                port.ingest(page.contents).await?;
                if !more {
                    progress.inbox_at_head = true;
                    progress.caught_up = port.caught_up(progress.cursor).await?;
                    break;
                }
            }
            ReadOutcome::LegacyExpired => {
                // Explicit legacy transport has no frozen-base recovery. Return
                // an existing visible typed refusal, never silent partial work.
                return Err(if mode == ReadMode::Legacy {
                    SyncError::Unavailable
                } else {
                    SyncError::Invalid
                }
                .into());
            }
            ReadOutcome::Expired(history) => {
                history.validate()?;
                if mode != ReadMode::Versioned {
                    return Err(SyncError::Invalid.into());
                }
                if recovery_started {
                    if restarts >= 1 {
                        break;
                    }
                    restarts += 1;
                }
                recovery_started = true;
                if !recover(
                    port,
                    None,
                    Some(history),
                    &mut budget,
                    &mut restarts,
                    &mut progress,
                )
                .await?
                {
                    break;
                }
            }
        }
    }
    progress.cursor = port.cursor().await?;
    Ok(progress)
}
/// Compatibility entry points are thin wrappers, never a second legacy loop.
pub async fn reconcile<P: CheckpointPort>(port: &P) -> Result<Progress, P::Error> {
    reconcile_history(port, false).await
}
pub async fn reconcile_inbox<P: CheckpointPort>(port: &P) -> Result<Progress, P::Error> {
    reconcile_history(port, true).await
}

async fn recover<P: CheckpointPort>(
    port: &P,
    mut stage: Option<ActiveStage<P::Stage, P::Guard>>,
    mut requested: Option<HistoryVersion>,
    budget: &mut BatchBudget,
    restarts: &mut usize,
    progress: &mut Progress,
) -> Result<bool, P::Error> {
    loop {
        if stage.as_ref().is_some_and(|s| {
            install_decision(
                &s.guard,
                &s.guard,
                s.install_version,
                s.install_version,
                s.through,
                s.base.complete(),
            )
            .is_ok()
        }) {
            let s = stage.take().ok_or(SyncError::Invalid)?;
            port.install_checkpoint(&s.guard, s.stage).await?;
            // Installation is not freshness. Caller must perform ordinary delta.
            return Ok(true);
        }
        if !budget.take_read() {
            return Ok(false);
        }
        if stage.as_ref().is_some_and(|s| s.base.complete()) {
            let s = stage.as_mut().ok_or(SyncError::Invalid)?;
            match port
                .history_outcome(ReadMode::Versioned, s.through, MAX_PAGE_ITEMS)
                .await?
            {
                ReadOutcome::Page(page) => {
                    let history = page.history.ok_or(SyncError::Invalid)?;
                    history.validate()?;
                    // Complete old base remains valid while its contiguous tail
                    // covers the current floor. Token expiry does not revoke
                    // already authenticated/staged bytes (canonical client install).
                    page.validate_after(s.through, ReadMode::Versioned)?;
                    let next = page.next_after;
                    let at_head = !page.has_more;
                    progress.received += page.entries;
                    port.checkpoint_delta(&s.stage, page).await?;
                    s.through = next;
                    s.tail_at_head = at_head;
                }
                ReadOutcome::Expired(v) => {
                    if !restart(port, &mut stage, v, &mut requested, restarts).await? {
                        return Ok(false);
                    }
                }
                ReadOutcome::LegacyExpired => return Err(SyncError::Invalid.into()),
            }
        } else {
            let (base, after) = if let Some(s) = &stage {
                (s.base.base, s.base.after_member)
            } else {
                let v = requested.ok_or(SyncError::Invalid)?;
                (v.base, 0)
            };
            match port
                .checkpoint_page(BaseRead {
                    base,
                    after_member: after,
                    limit: MAX_PAGE_ITEMS,
                })
                .await?
            {
                ReadOutcome::Page(page) => {
                    if page.base != base {
                        return Err(SyncError::Invalid.into());
                    }
                    if stage.is_none() {
                        let s = port
                            .checkpoint_begin(page.base, page.expected_members)
                            .await?;
                        validate_stage(&s)?;
                        if s.base
                            != (BaseProgress {
                                base: page.base,
                                total: page.expected_members,
                                received: 0,
                                after_member: 0,
                            })
                            || s.through != page.base
                            || s.tail_at_head
                        {
                            return Err(SyncError::Invalid.into());
                        }
                        stage = Some(s);
                    }
                    stage_base(
                        port,
                        stage.as_mut().ok_or(SyncError::Invalid)?,
                        page,
                        progress,
                    )
                    .await?;
                }
                ReadOutcome::Expired(v) => {
                    if !restart(port, &mut stage, v, &mut requested, restarts).await? {
                        return Ok(false);
                    }
                }
                ReadOutcome::LegacyExpired => return Err(SyncError::Invalid.into()),
            }
        }
    }
}
async fn stage_base<P: CheckpointPort>(
    port: &P,
    stage: &mut ActiveStage<P::Stage, P::Guard>,
    page: VerifiedBasePage<P::BaseContents>,
    progress: &mut Progress,
) -> Result<(), P::Error> {
    let next = stage.base.advance(
        page.base,
        page.expected_members,
        &page.sequences,
        page.next_member,
        page.has_more,
    )?;
    progress.received += page.sequences.len();
    port.stage_page(&stage.stage, page).await?;
    stage.base = next;
    Ok(())
}
async fn restart<P: CheckpointPort>(
    port: &P,
    stage: &mut Option<ActiveStage<P::Stage, P::Guard>>,
    history: HistoryVersion,
    requested: &mut Option<HistoryVersion>,
    restarts: &mut usize,
) -> Result<bool, P::Error> {
    history.validate()?;
    if let Some(s) = stage.take() {
        port.checkpoint_discard(s.stage).await?;
    }
    if *restarts >= 1 {
        return Ok(false);
    }
    *restarts += 1;
    *requested = Some(history);
    Ok(true)
}
#[cfg(test)]
mod tests;
