//! One bounded upload/catch-up use case for native and browser replicas.
//! Adapters own authorization, crypto, wire encoding and concrete I/O. Storage
//! commands remain whole transactions; this use case never splits a store read
//! and its guarded mutation across separate ports.
use nddev_device_sync_domain::sync::{MAX_PAGE_ITEMS, MAX_REVISION, SyncError};
use std::{future::Future, time::Duration};

pub const MAX_UPLOADS: usize = 16;
pub const MAX_PULL_PAGES: usize = 16;
pub const BATCH_DEADLINE: Duration = Duration::from_secs(60);

/// Metadata accompanying an entirely authenticated/validated page. The store
/// must still check every committed sequence against its cursor transactionally.
pub struct VerifiedPage<P> {
    pub contents: P,
    pub next_after: u64,
    pub entries: usize,
    pub has_more: bool,
}

impl<P> VerifiedPage<P> {
    fn validate_after(&self, cursor: u64) -> Result<(), SyncError> {
        if self.entries > MAX_PAGE_ITEMS
            || self.has_more && self.entries == 0
            || self.next_after > MAX_REVISION
            || cursor.checked_add(self.entries as u64) != Some(self.next_after)
        {
            return Err(SyncError::Invalid);
        }
        Ok(())
    }
}

pub struct Progress {
    pub uploaded: usize,
    pub received: usize,
    pub cursor: u64,
    pub caught_up: bool,
}

/// Implemented by the existing vault storage/transport/verification composition.
/// Associated payloads preserve one generated wire model in its adapter. Native
/// implementations produce Send futures; browser futures may remain local.
pub trait ReplicaPort {
    type Error: From<SyncError>;
    type Pending;
    type Receipt;
    type Page;

    /// Atomically claim at most MAX_UPLOADS immutable roots before network I/O.
    fn claim(&self) -> impl Future<Output = Result<Vec<Self::Pending>, Self::Error>>;
    /// Verify the local payload, then send its original persisted bytes. Every
    /// request rechecks authorization through the existing identity boundary.
    fn append(
        &self,
        pending: &Self::Pending,
    ) -> impl Future<Output = Result<Self::Receipt, Self::Error>>;
    /// One transaction checks the exact claimed bytes/device, stores the receipt
    /// and settles that root's successors. An already settled request is safe.
    fn acknowledge(
        &self,
        pending: Self::Pending,
        receipt: Self::Receipt,
    ) -> impl Future<Output = Result<(), Self::Error>>;
    fn cursor(&self) -> impl Future<Output = Result<u64, Self::Error>>;
    /// Decode and authenticate the entire page before exposing it for commit.
    fn verified_page(
        &self,
        after: u64,
        limit: usize,
    ) -> impl Future<Output = Result<VerifiedPage<Self::Page>, Self::Error>>;
    /// One transaction applies verified entries, scoped settlements and cursor.
    fn ingest(&self, page: Self::Page) -> impl Future<Output = Result<(), Self::Error>>;
    /// Atomically record freshness only if the cursor still matches and there
    /// are no pending operations. False means another bounded batch is needed.
    fn caught_up(&self, cursor: u64) -> impl Future<Output = Result<bool, Self::Error>>;
}

/// The caller first prepares authorized key access, admits one sync batch and
/// applies BATCH_DEADLINE plus its lifecycle cancellation. Dropping this future
/// never deletes pending work: unknown POST outcomes remain durable for replay,
/// and store adapters retain admission until actual transaction completion.
pub async fn reconcile<P: ReplicaPort>(port: &P) -> Result<Progress, P::Error> {
    let pending = port.claim().await?;
    if pending.len() > MAX_UPLOADS {
        return Err(SyncError::Invalid.into());
    }
    let mut progress = Progress {
        uploaded: 0,
        received: 0,
        cursor: 0,
        caught_up: false,
    };
    for pending in pending {
        let receipt = port.append(&pending).await?;
        port.acknowledge(pending, receipt).await?;
        progress.uploaded += 1;
    }
    for _ in 0..MAX_PULL_PAGES {
        let cursor = port.cursor().await?;
        let page = port.verified_page(cursor, MAX_PAGE_ITEMS).await?;
        page.validate_after(cursor)?;
        let more = page.has_more;
        progress.cursor = page.next_after;
        progress.received += page.entries;
        port.ingest(page.contents).await?;
        if !more {
            progress.caught_up = port.caught_up(progress.cursor).await?;
            break;
        }
    }
    Ok(progress)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_page_cannot_skip_history_or_claim_more_without_progress() {
        let page = |next_after, entries, has_more| VerifiedPage {
            contents: (),
            next_after,
            entries,
            has_more,
        };
        assert!(page(2, 2, true).validate_after(0).is_ok());
        assert!(page(2, 0, false).validate_after(2).is_ok());
        assert!(page(2, 0, true).validate_after(2).is_err());
        assert!(page(3, 2, false).validate_after(0).is_err());
        assert!(page(3, 3, false).validate_after(0).is_err());
        assert!(
            page(MAX_REVISION + 1, 1, false)
                .validate_after(MAX_REVISION)
                .is_err()
        );
    }
}
