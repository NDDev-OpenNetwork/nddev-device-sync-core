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
    /// The verified server page reported no more history at this cursor. This
    /// does not establish full reconciliation while local uploads remain.
    pub inbox_at_head: bool,
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
    /// are no pending operations. False may mean uploads remain even when the
    /// inbox has reached the observed server head.
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
    let mut uploaded = 0;
    for pending in pending {
        let receipt = port.append(&pending).await?;
        port.acknowledge(pending, receipt).await?;
        uploaded += 1;
    }
    let mut progress = reconcile_inbox(port).await?;
    progress.uploaded = uploaded;
    Ok(progress)
}

/// Catch up authenticated history without claiming or sending local uploads.
/// The caller applies the same authorization, admission, BATCH_DEADLINE and
/// cancellation as full reconciliation. The existing atomic freshness check
/// still refuses full caught_up/last_sync advancement while uploads remain.
pub async fn reconcile_inbox<P: ReplicaPort>(port: &P) -> Result<Progress, P::Error> {
    let mut progress = Progress {
        uploaded: 0,
        received: 0,
        cursor: 0,
        inbox_at_head: false,
        caught_up: false,
    };
    for _ in 0..MAX_PULL_PAGES {
        let cursor = port.cursor().await?;
        let page = port.verified_page(cursor, MAX_PAGE_ITEMS).await?;
        page.validate_after(cursor)?;
        let more = page.has_more;
        progress.cursor = page.next_after;
        progress.received += page.entries;
        port.ingest(page.contents).await?;
        if !more {
            progress.inbox_at_head = true;
            progress.caught_up = port.caught_up(progress.cursor).await?;
            break;
        }
    }
    Ok(progress)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        task::{Context, Poll, Waker},
    };

    // Pure use-case unit adapter, not storage/transport integration evidence.
    struct UnitPort {
        pending: Cell<usize>,
        pages: RefCell<VecDeque<VerifiedPage<u64>>>,
        cursor: Cell<u64>,
        upload_calls: Cell<usize>,
        ingested: Cell<usize>,
        freshness_marks: Cell<usize>,
    }
    impl UnitPort {
        fn new(pending: usize, pages: Vec<VerifiedPage<u64>>) -> Self {
            Self {
                pending: Cell::new(pending),
                pages: RefCell::new(pages.into()),
                cursor: Cell::new(0),
                upload_calls: Cell::new(0),
                ingested: Cell::new(0),
                freshness_marks: Cell::new(0),
            }
        }
    }
    impl ReplicaPort for UnitPort {
        type Error = SyncError;
        type Pending = usize;
        type Receipt = ();
        type Page = u64;

        async fn claim(&self) -> Result<Vec<usize>, SyncError> {
            self.upload_calls.set(self.upload_calls.get() + 1);
            Ok((0..self.pending.get()).collect())
        }
        async fn append(&self, _: &usize) -> Result<(), SyncError> {
            self.upload_calls.set(self.upload_calls.get() + 1);
            Ok(())
        }
        async fn acknowledge(&self, _: usize, _: ()) -> Result<(), SyncError> {
            self.upload_calls.set(self.upload_calls.get() + 1);
            self.pending.set(self.pending.get() - 1);
            Ok(())
        }
        async fn cursor(&self) -> Result<u64, SyncError> {
            Ok(self.cursor.get())
        }
        async fn verified_page(
            &self,
            after: u64,
            limit: usize,
        ) -> Result<VerifiedPage<u64>, SyncError> {
            assert_eq!(after, self.cursor.get());
            assert_eq!(limit, MAX_PAGE_ITEMS);
            Ok(self.pages.borrow_mut().pop_front().unwrap())
        }
        async fn ingest(&self, cursor: u64) -> Result<(), SyncError> {
            self.ingested.set(self.ingested.get() + 1);
            self.cursor.set(cursor);
            Ok(())
        }
        async fn caught_up(&self, cursor: u64) -> Result<bool, SyncError> {
            let complete = self.cursor.get() == cursor && self.pending.get() == 0;
            if complete {
                self.freshness_marks.set(self.freshness_marks.get() + 1);
            }
            Ok(complete)
        }
    }
    fn page(next_after: u64, entries: usize, has_more: bool) -> VerifiedPage<u64> {
        VerifiedPage {
            contents: next_after,
            next_after,
            entries,
            has_more,
        }
    }
    fn complete<T>(future: impl Future<Output = T>) -> T {
        let mut future = Box::pin(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("pure unit port futures complete immediately"),
        }
    }

    #[test]
    fn inbox_head_with_pending_uploads_does_not_claim_or_establish_full_freshness() {
        let port = UnitPort::new(1, vec![page(1, 1, true), page(2, 1, false)]);
        let progress = complete(reconcile_inbox(&port)).unwrap();
        assert_eq!(progress.uploaded, 0);
        assert_eq!(progress.received, 2);
        assert_eq!(progress.cursor, 2);
        assert!(progress.inbox_at_head);
        assert!(!progress.caught_up);
        assert_eq!(port.pending.get(), 1);
        assert_eq!(port.upload_calls.get(), 0);
        assert_eq!(port.freshness_marks.get(), 0);
    }

    #[test]
    fn full_reconcile_uploads_before_using_the_same_inbox_use_case() {
        let port = UnitPort::new(1, vec![page(2, 2, false)]);
        let progress = complete(reconcile(&port)).unwrap();
        assert_eq!(progress.uploaded, 1);
        assert_eq!(progress.received, 2);
        assert!(progress.inbox_at_head && progress.caught_up);
        assert_eq!(port.upload_calls.get(), 3);
        assert_eq!(port.freshness_marks.get(), 1);
    }

    #[test]
    fn inbox_budget_retains_more_history_without_marking_freshness() {
        let mut pages = (1..=MAX_PULL_PAGES)
            .map(|index| page((index * MAX_PAGE_ITEMS) as u64, MAX_PAGE_ITEMS, true))
            .collect::<Vec<_>>();
        let head = (MAX_PULL_PAGES * MAX_PAGE_ITEMS) as u64;
        pages.push(page(head, 0, false));
        let port = UnitPort::new(1, pages);
        let progress = complete(reconcile_inbox(&port)).unwrap();
        assert_eq!(progress.cursor, head);
        assert_eq!(progress.received, MAX_PULL_PAGES * MAX_PAGE_ITEMS);
        assert!(!progress.inbox_at_head && !progress.caught_up);
        assert_eq!(port.ingested.get(), MAX_PULL_PAGES);
        assert_eq!(port.pages.borrow().len(), 1);
        let next = complete(reconcile_inbox(&port)).unwrap();
        assert!(next.inbox_at_head && !next.caught_up);
        assert_eq!(port.upload_calls.get(), 0);
        assert_eq!(port.freshness_marks.get(), 0);
    }

    #[test]
    fn invalid_page_is_rejected_before_ingest_or_freshness() {
        let port = UnitPort::new(1, vec![page(3, 1, false)]);
        assert!(matches!(
            complete(reconcile_inbox(&port)),
            Err(SyncError::Invalid)
        ));
        assert_eq!(port.cursor.get(), 0);
        assert_eq!(port.ingested.get(), 0);
        assert_eq!(port.freshness_marks.get(), 0);
    }

    #[test]
    fn oversized_upload_claim_is_rejected_before_any_append() {
        let port = UnitPort::new(MAX_UPLOADS + 1, Vec::new());
        assert!(matches!(
            complete(reconcile(&port)),
            Err(SyncError::Invalid)
        ));
        assert_eq!(port.upload_calls.get(), 1);
        assert_eq!(port.pending.get(), MAX_UPLOADS + 1);
        assert_eq!(port.ingested.get(), 0);
    }

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
        assert!(
            page(MAX_PAGE_ITEMS as u64, MAX_PAGE_ITEMS, true)
                .validate_after(0)
                .is_ok()
        );
        assert!(
            page(MAX_PAGE_ITEMS as u64 + 1, MAX_PAGE_ITEMS + 1, false)
                .validate_after(0)
                .is_err()
        );
        assert!(
            page(MAX_REVISION + 1, 1, false)
                .validate_after(MAX_REVISION)
                .is_err()
        );
    }
}
