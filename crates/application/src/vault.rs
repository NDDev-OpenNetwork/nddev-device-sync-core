//! Authenticated server-managed key delivery. Adapters own wrapping and I/O.
pub use crate::sync::{AuthenticatedSession, SignedRequest, SyncError};
pub use nddev_device_sync_domain::vault::KeyMaterial;
use std::future::Future;

pub trait VaultKeyStore: Send + Sync {
    /// Recheck session/device and consume nonce transactionally. A retained
    /// client key may register an existing binding once; it cannot replace it.
    fn ensure(
        &self,
        authorization: &AuthenticatedSession,
        signed: SignedRequest,
        existing: Option<KeyMaterial>,
        now: u64,
    ) -> impl Future<Output = Result<KeyMaterial, SyncError>> + Send;
}

pub struct VaultKeyService<S> {
    store: S,
}

impl<S: VaultKeyStore> VaultKeyService<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub async fn ensure(
        &self,
        authorization: &AuthenticatedSession,
        signed: SignedRequest,
        existing: Option<KeyMaterial>,
        now: u64,
    ) -> Result<KeyMaterial, SyncError> {
        crate::sync::active(authorization, &signed, now)?;
        self.store
            .ensure(authorization, signed, existing, now)
            .await
    }
}
