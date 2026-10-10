//! Enrollment rules, separate from module platform/capability declarations.
use crate::{
    DeviceId,
    identity::{AuthenticatedSession, Owner},
};

pub const ENROLLMENT_LIFETIME_MS: u64 = 300_000;
pub const ENROLLMENT_ATTEMPTS: u8 = 5;
pub const MAX_PENDING_ENROLLMENTS: usize = 8;
pub const MAX_ACTIVE_DEVICES: usize = 32;
// Revoked identities are retained, never silently forgotten or reassigned.
pub const MAX_DEVICE_IDENTITIES: usize = 128;
pub const MAX_DEVICE_PAGE: usize = 100;
// Even maximal Unicode names fit a 64 KiB response with this finite page cap.
pub const DEVICE_RESPONSE_ITEMS: usize = 32;
pub const ENROLLMENT_DOMAIN: &[u8] = b"NDS-ENROLLMENT-V2\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DevicePlatform {
    Macos,
    Linux,
    Windows,
    Ios,
    Android,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeviceError {
    #[error("invalid_device_input")]
    InvalidInput,
    #[error("device_authorization_denied")]
    Denied,
    #[error("invalid_enrollment_proof")]
    InvalidProof,
    #[error("enrollment_challenge_expired")]
    Expired,
    #[error("device_rate_limited")]
    RateLimited,
    #[error("device_capacity_reached")]
    Capacity,
    #[error("device_dependency_unavailable")]
    Unavailable,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeviceName(String);
impl DeviceName {
    pub fn new(value: String) -> Result<Self, DeviceError> {
        if value.trim() != value
            || value.is_empty()
            || value.chars().count() > 128
            || value.chars().any(char::is_control)
        {
            return Err(DeviceError::InvalidInput);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PublicDeviceKey(pub [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceStatus {
    Active,
    Revoked,
}

#[derive(Clone)]
pub struct Device {
    pub id: DeviceId,
    pub owner: Owner,
    pub platform: DevicePlatform,
    pub name: DeviceName,
    pub public_key: PublicDeviceKey,
    pub status: DeviceStatus,
    pub created_at_ms: u64,
}

#[derive(Clone)]
pub struct EnrollmentChallenge {
    pub id: String,
    pub device: Device,
    pub session: crate::identity::ProtectedDigest,
    pub challenge: [u8; 32],
    pub expires_at_ms: u64,
    pub attempts_remaining: u8,
    pub consumed: bool,
}
impl EnrollmentChallenge {
    pub fn new(
        id: String,
        device: Device,
        session: &AuthenticatedSession,
        challenge: [u8; 32],
        now: u64,
    ) -> Result<Self, DeviceError> {
        if !crate::valid_identifier(&id) {
            return Err(DeviceError::InvalidInput);
        }
        if !session.session.active(now)
            || device.owner != session.session.owner
            || device.status != DeviceStatus::Active
        {
            return Err(DeviceError::Denied);
        }
        let expires = now
            .checked_add(ENROLLMENT_LIFETIME_MS)
            .ok_or(DeviceError::InvalidInput)?;
        Ok(Self {
            id,
            device,
            session: session.binding,
            challenge,
            expires_at_ms: expires.min(session.session.expires_at_ms),
            attempts_remaining: ENROLLMENT_ATTEMPTS,
            consumed: false,
        })
    }
    pub fn signing_bytes(&self) -> [u8; ENROLLMENT_DOMAIN.len() + 32] {
        let mut bytes = [0; ENROLLMENT_DOMAIN.len() + 32];
        bytes[..ENROLLMENT_DOMAIN.len()].copy_from_slice(ENROLLMENT_DOMAIN);
        bytes[ENROLLMENT_DOMAIN.len()..].copy_from_slice(&self.challenge);
        bytes
    }
    /// The owning store checks the same current session, then verifies Ed25519
    /// and persists this transition under its row lock, including failed proofs.
    pub fn consume(&mut self, signature_valid: bool, now: u64) -> Result<(), DeviceError> {
        if self.consumed || self.attempts_remaining == 0 {
            return Err(DeviceError::InvalidProof);
        }
        if now >= self.expires_at_ms {
            self.consumed = true;
            return Err(DeviceError::Expired);
        }
        self.attempts_remaining -= 1;
        if !signature_valid {
            return Err(DeviceError::InvalidProof);
        }
        self.consumed = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TenantId, UserId,
        identity::{AuthMethod, ProtectedDigest, Session},
    };
    fn challenge(now: u64) -> EnrollmentChallenge {
        let owner = Owner {
            user_id: UserId::new("owner").unwrap(),
            tenant_id: TenantId::new("tenant").unwrap(),
        };
        let session = AuthenticatedSession {
            session: Session::new(owner.clone(), AuthMethod::EmailOtp, now).unwrap(),
            binding: ProtectedDigest([7; 32]),
        };
        let device = Device {
            id: DeviceId::new("device").unwrap(),
            owner,
            platform: DevicePlatform::Android,
            name: DeviceName::new("Test device".into()).unwrap(),
            public_key: PublicDeviceKey([9; 32]),
            status: DeviceStatus::Active,
            created_at_ms: now,
        };
        EnrollmentChallenge::new("challenge".into(), device, &session, [3; 32], now).unwrap()
    }
    #[test]
    fn proof_attempts_and_success_are_terminal() {
        let mut invalid = challenge(0);
        for _ in 0..ENROLLMENT_ATTEMPTS {
            assert_eq!(invalid.consume(false, 1), Err(DeviceError::InvalidProof));
        }
        assert_eq!(invalid.consume(true, 1), Err(DeviceError::InvalidProof));
        let mut valid = challenge(0);
        assert_eq!(valid.consume(true, 1), Ok(()));
        assert_eq!(valid.consume(true, 1), Err(DeviceError::InvalidProof));
    }
    #[test]
    fn observed_expiry_cannot_revive_with_clock_rollback() {
        let mut value = challenge(100);
        assert_eq!(
            value.consume(true, value.expires_at_ms),
            Err(DeviceError::Expired)
        );
        assert_eq!(value.consume(true, 101), Err(DeviceError::InvalidProof));
    }
    #[test]
    fn enrollment_cannot_outlive_or_cross_the_initiating_session() {
        let value = challenge(100);
        let mut session = AuthenticatedSession {
            session: Session::new(value.device.owner.clone(), AuthMethod::Github, 100).unwrap(),
            binding: ProtectedDigest([8; 32]),
        };
        session.session.expires_at_ms = 200;
        let short = EnrollmentChallenge::new(
            value.id.clone(),
            value.device.clone(),
            &session,
            value.challenge,
            100,
        )
        .unwrap();
        assert_eq!(short.expires_at_ms, 200);
        assert!(
            EnrollmentChallenge::new(
                value.id.clone(),
                value.device.clone(),
                &session,
                value.challenge,
                200
            )
            .is_err()
        );
        session.session.owner.user_id = UserId::new("other").unwrap();
        assert!(
            EnrollmentChallenge::new(value.id, value.device, &session, value.challenge, 100)
                .is_err()
        );
    }
    #[test]
    fn signing_domain_and_unicode_name_bounds_are_explicit() {
        let value = challenge(0);
        assert_eq!(
            &value.signing_bytes()[..ENROLLMENT_DOMAIN.len()],
            b"NDS-ENROLLMENT-V2\0"
        );
        assert_eq!(&value.signing_bytes()[ENROLLMENT_DOMAIN.len()..], &[3; 32]);
        assert!(DeviceName::new("я".repeat(128)).is_ok());
        for invalid in [
            "я".repeat(129),
            "bad\nname".into(),
            " leading".into(),
            String::new(),
        ] {
            assert!(DeviceName::new(invalid).is_err());
        }
    }
}
