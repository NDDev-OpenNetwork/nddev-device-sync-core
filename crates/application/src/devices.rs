//! Session-authorized device enrollment; adapters own cryptography and atomic I/O.
use crate::identity::{IdentityCrypto, IdentityError, ProtectedDigest, valid_opaque};
pub use nddev_device_sync_domain::{DeviceId, devices::*, identity::AuthenticatedSession};
use std::future::Future;

pub struct EnrollmentIssue {
    pub authorization: AuthenticatedSession,
    pub challenge: EnrollmentChallenge,
    pub source: ProtectedDigest,
}

pub struct EnrollmentInput {
    pub platform: DevicePlatform,
    pub name: DeviceName,
    pub public_key: PublicDeviceKey,
}

pub struct DevicePage {
    pub devices: Vec<Device>,
    /// Monotonic insertion position, scoped by the authenticated owner in storage.
    pub next_after: Option<u16>,
}

pub trait EnrollmentCrypto: IdentityCrypto {
    /// Decode a canonical, non-weak prime-order Ed25519 public key with the
    /// maintained crypto provider. Reject before allocating pending state.
    fn valid_public_key(&self, key: &PublicDeviceKey) -> bool;
    fn random_challenge(&self) -> Result<[u8; 32], DeviceError>;
    fn verify_proof(&self, challenge: &EnrollmentChallenge, signature: &[u8; 64]) -> bool;
}

pub trait DeviceStore: Send + Sync {
    /// Recheck the exact live session under the transaction. Source admission,
    /// pending/active/total bounds and retaining the immutable challenge binding
    /// are atomic. Reject a public key already registered, including revoked keys.
    fn issue(
        &self,
        issue: EnrollmentIssue,
        now: u64,
    ) -> impl Future<Output = Result<EnrollmentChallenge, DeviceError>> + Send;
    /// Lock the same live session and challenge; verify through EnrollmentCrypto,
    /// apply EnrollmentChallenge::consume and persist failure/expiry transitions.
    /// Success consumes and inserts exactly one device in that same transaction.
    /// The session binding must equal the initiating binding, not just its owner.
    fn complete(
        &self,
        authorization: &AuthenticatedSession,
        id: &str,
        signature: [u8; 64],
        now: u64,
    ) -> impl Future<Output = Result<Device, DeviceError>> + Send;
    /// Device rows and cursors always use both authenticated tenant/user IDs.
    fn list(
        &self,
        authorization: &AuthenticatedSession,
        after: u16,
        limit: usize,
        now: u64,
    ) -> impl Future<Output = Result<DevicePage, DeviceError>> + Send;
    /// Retain revoked rows; never reset their identity or public key. Future signed
    /// requests must share this row-lock authorization boundary before replay.
    fn revoke(
        &self,
        authorization: &AuthenticatedSession,
        id: &DeviceId,
        now: u64,
    ) -> impl Future<Output = Result<(), DeviceError>> + Send;
}

pub struct DeviceService<S, C> {
    store: S,
    crypto: C,
}
impl<S: DeviceStore, C: EnrollmentCrypto> DeviceService<S, C> {
    pub fn new(store: S, crypto: C) -> Self {
        Self { store, crypto }
    }

    pub async fn request(
        &self,
        authorization: &AuthenticatedSession,
        input: EnrollmentInput,
        source: &[u8],
        now: u64,
    ) -> Result<EnrollmentChallenge, DeviceError> {
        active(authorization, now)?;
        if !matches!(source.len(), 4 | 16) {
            return Err(DeviceError::InvalidInput);
        }
        if !self.crypto.valid_public_key(&input.public_key) {
            return Err(DeviceError::InvalidInput);
        }
        let device = Device {
            id: DeviceId::new(self.crypto.token().map_err(identity_error)?.into_inner())
                .map_err(|_| DeviceError::Unavailable)?,
            owner: authorization.session.owner.clone(),
            platform: input.platform,
            name: input.name,
            public_key: input.public_key,
            status: DeviceStatus::Active,
            created_at_ms: now,
        };
        let challenge = EnrollmentChallenge::new(
            self.crypto.token().map_err(identity_error)?.into_inner(),
            device,
            authorization,
            self.crypto.random_challenge()?,
            now,
        )?;
        self.store
            .issue(
                EnrollmentIssue {
                    authorization: authorization.clone(),
                    challenge,
                    source: self.crypto.protect("device_enrollment_source", &[source]),
                },
                now,
            )
            .await
    }
    pub async fn complete(
        &self,
        authorization: &AuthenticatedSession,
        id: &str,
        signature: [u8; 64],
        now: u64,
    ) -> Result<Device, DeviceError> {
        active(authorization, now)?;
        if !valid_opaque(id) {
            return Err(DeviceError::InvalidInput);
        }
        self.store.complete(authorization, id, signature, now).await
    }
    pub async fn list(
        &self,
        authorization: &AuthenticatedSession,
        after: u16,
        limit: usize,
        now: u64,
    ) -> Result<DevicePage, DeviceError> {
        active(authorization, now)?;
        if after as usize > MAX_DEVICE_IDENTITIES || !(1..=MAX_DEVICE_PAGE).contains(&limit) {
            return Err(DeviceError::InvalidInput);
        }
        self.store
            .list(authorization, after, limit.min(DEVICE_RESPONSE_ITEMS), now)
            .await
    }
    pub async fn revoke(
        &self,
        authorization: &AuthenticatedSession,
        id: &DeviceId,
        now: u64,
    ) -> Result<(), DeviceError> {
        active(authorization, now)?;
        self.store.revoke(authorization, id, now).await
    }
}
fn active(authorization: &AuthenticatedSession, now: u64) -> Result<(), DeviceError> {
    if authorization.session.active(now) {
        Ok(())
    } else {
        Err(DeviceError::Denied)
    }
}
pub fn identity_error(error: IdentityError) -> DeviceError {
    match error {
        IdentityError::InvalidInput => DeviceError::InvalidInput,
        IdentityError::Denied => DeviceError::Denied,
        IdentityError::RateLimited => DeviceError::RateLimited,
        IdentityError::Capacity => DeviceError::Capacity,
        IdentityError::Unavailable => DeviceError::Unavailable,
    }
}
