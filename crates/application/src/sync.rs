//! Authenticated synchronization ports; concrete signatures and transactions are
//! adapters. Never acknowledge a mutation before its durable atomic result.
pub use nddev_device_sync_domain::{DeviceId, identity::AuthenticatedSession, sync::*};
use std::future::Future;

pub struct SignedRequest {
    pub device: DeviceId,
    pub nonce: String,
    pub expires_at_ms: u64,
    pub fingerprint: [u8; 32],
}
pub struct StoredResult {
    pub status: u16,
    pub body: Vec<u8>,
}
pub struct Entry {
    pub request_body: Vec<u8>,
    pub result_body: Vec<u8>,
    pub server_seq: u64,
}
pub struct Page {
    pub entries: Vec<Entry>,
    pub next_after: u64,
    pub has_more: bool,
}
pub trait SyncStore: Send + Sync {
    /// Recheck the current session and active device under the same lock used
    /// by revocation. Consume nonce before replay, and atomically commit the
    /// committed-order sequence, entity transition, conflict and original bytes.
    fn append(
        &self,
        authorization: &AuthenticatedSession,
        signed: SignedRequest,
        operation: Operation,
        original_body: Vec<u8>,
        now: u64,
    ) -> impl Future<Output = Result<StoredResult, SyncError>> + Send;
    /// Read only the authenticated owner, from a commit-safe cursor. This alpha
    /// does not prune history or idempotency receipts; capacity is explicit.
    fn page(
        &self,
        authorization: &AuthenticatedSession,
        signed: SignedRequest,
        after: u64,
        limit: usize,
        now: u64,
    ) -> impl Future<Output = Result<Page, SyncError>> + Send;
}
pub struct SyncService<S> {
    store: S,
}
impl<S: SyncStore> SyncService<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
    pub async fn append(
        &self,
        authorization: &AuthenticatedSession,
        signed: SignedRequest,
        operation: Operation,
        original_body: Vec<u8>,
        now: u64,
    ) -> Result<StoredResult, SyncError> {
        active(authorization, &signed, now)?;
        // This existing service is explicitly the deployed V2 entrypoint.
        // New kinds/versions use HistoryStore's canonical versioned boundary.
        let legacy = nddev_device_sync_domain::sync::history::VersionedOperation {
            operation,
            version: nddev_device_sync_domain::sync::history::OperationVersion::V2,
        };
        legacy.validate(original_body.len())?;
        let operation = legacy.operation;
        if signed.device != operation.device {
            return Err(SyncError::Denied);
        }
        self.store
            .append(authorization, signed, operation, original_body, now)
            .await
    }
    pub async fn page(
        &self,
        authorization: &AuthenticatedSession,
        signed: SignedRequest,
        after: u64,
        limit: usize,
        now: u64,
    ) -> Result<Page, SyncError> {
        active(authorization, &signed, now)?;
        if after > MAX_REVISION || !(1..=100).contains(&limit) {
            return Err(SyncError::Invalid);
        }
        self.store
            .page(authorization, signed, after, limit.min(MAX_PAGE_ITEMS), now)
            .await
    }
}
pub(crate) fn active(
    authorization: &AuthenticatedSession,
    signed: &SignedRequest,
    now: u64,
) -> Result<(), SyncError> {
    if !authorization.session.active(now) {
        return Err(SyncError::Denied);
    }
    if signed.expires_at_ms <= now
        || signed.expires_at_ms > now.saturating_add(360_000)
        || !(16..=128).contains(&signed.nonce.len())
        || !signed
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    {
        return Err(SyncError::Signature);
    }
    Ok(())
}
