//! Product identity rules. No clocks, randomness, cryptographic implementation,
//! persistence, network or platform APIs belong in this module.
use crate::{TenantId, UserId};
use std::fmt;

pub const OTP_LIFETIME_MS: u64 = 300_000;
pub const OTP_RESEND_MS: u64 = 60_000;
pub const OTP_ATTEMPTS: u8 = 5;
pub const GITHUB_LIFETIME_MS: u64 = 300_000;
pub const GITHUB_POLL_MS: u64 = 2_000;
pub const SESSION_LIFETIME_MS: u64 = 28_800_000;
pub const RECENT_AUTHENTICATION_MS: u64 = 300_000;
pub const MAX_SESSIONS: usize = 32;
pub const MAX_PENDING_EMAIL: usize = 1024;
pub const MAX_PENDING_GITHUB: usize = 128;
pub const MAX_RATE_KEYS: usize = 4096;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Locale {
    #[default]
    En,
    Ru,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid_identity_input")]
    InvalidInput,
    #[error("authentication_failed")]
    Denied,
    #[error("recent_authentication_required")]
    RecentAuthenticationRequired,
    #[error("authentication_rate_limited")]
    RateLimited,
    #[error("authentication_capacity_reached")]
    Capacity,
    #[error("identity_dependency_unavailable")]
    Unavailable,
}

/// Authentication secrets cannot accidentally acquire Serialize or plaintext Debug.
pub struct SecretText(String);
impl SecretText {
    pub fn new(value: String) -> Self {
        Self(value)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn into_inner(self) -> String {
        self.0
    }
}
impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EmailAddress(String);
impl EmailAddress {
    /// Alpha deliberately supports ASCII mailboxes. Both the configured binding
    /// and submitted address use trim + ASCII lowercase, including the local part.
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        let value = value.trim().to_ascii_lowercase();
        let (local, domain) = value.split_once('@').ok_or(IdentityError::InvalidInput)?;
        if value.len() > 254
            || local.is_empty()
            || local.len() > 64
            || domain.is_empty()
            || local.starts_with('.')
            || local.ends_with('.')
            || local.contains("..")
            || !local
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'*+-/=?^_`{|}~".contains(&b))
            || !domain.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(IdentityError::InvalidInput);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for EmailAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EmailAddress([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProtectedDigest(pub [u8; 32]);
impl fmt::Debug for ProtectedDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedDigest([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMethod {
    EmailOtp,
    Github,
    Passkey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Owner {
    pub user_id: UserId,
    pub tenant_id: TenantId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub owner: Owner,
    pub method: AuthMethod,
    pub expires_at_ms: u64,
}

/// A verified session and its protected storage binding. This is not a wire
/// credential; mutation stores revalidate the binding under their transaction.
#[derive(Clone)]
pub struct AuthenticatedSession {
    pub session: Session,
    pub binding: ProtectedDigest,
}
impl Session {
    pub fn new(owner: Owner, method: AuthMethod, now: u64) -> Result<Self, IdentityError> {
        Ok(Self {
            owner,
            method,
            expires_at_ms: now
                .checked_add(SESSION_LIFETIME_MS)
                .ok_or(IdentityError::InvalidInput)?,
        })
    }
    pub fn active(&self, now: u64) -> bool {
        now < self.expires_at_ms
    }
    /// Sensitive credential changes require a recent proof, while ordinary
    /// account/session authorization retains its original lifetime.
    pub fn recently_authenticated(&self, now: u64) -> bool {
        self.active(now)
            && self
                .expires_at_ms
                .checked_sub(SESSION_LIFETIME_MS)
                .is_some_and(|issued| now >= issued && now - issued <= RECENT_AUTHENTICATION_MS)
    }
}

/// A protected local observation, never authority for an online request.
/// Credential adapters persist it only after verifying the session and active
/// device, and invalidate it on sign-out or an observed revocation.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedDeviceAuthorization {
    pub origin: String,
    pub user_id: UserId,
    pub tenant_id: TenantId,
    pub device_id: crate::DeviceId,
    pub verified_at_ms: u64,
    pub expires_at_ms: u64,
}

impl CachedDeviceAuthorization {
    pub fn authorize_offline(
        &self,
        origin: &str,
        owner: &Owner,
        device: &crate::DeviceId,
        now: u64,
    ) -> Result<(), IdentityError> {
        if self.origin != origin
            || self.origin.is_empty()
            || self.origin.len() > 2048
            || self.origin.bytes().any(|c| c.is_ascii_control())
            || self.user_id != owner.user_id
            || self.tenant_id != owner.tenant_id
            || &self.device_id != device
            || self.expires_at_ms <= self.verified_at_ms
            || self.expires_at_ms - self.verified_at_ms > SESSION_LIFETIME_MS
            || now < self.verified_at_ms
            || now >= self.expires_at_ms
        {
            return Err(IdentityError::Denied);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct OtpChallenge {
    pub expires_at_ms: u64,
    pub attempts_remaining: u8,
    pub eligible: bool,
    pub consumed: bool,
}
impl OtpChallenge {
    pub fn new(now: u64, eligible: bool) -> Result<Self, IdentityError> {
        Ok(Self {
            expires_at_ms: now
                .checked_add(OTP_LIFETIME_MS)
                .ok_or(IdentityError::InvalidInput)?,
            attempts_remaining: OTP_ATTEMPTS,
            eligible,
            consumed: false,
        })
    }
    /// The store invokes this inside the same transaction that persists attempts
    /// and, on success, creates the session. Failed attempts are committed too.
    pub fn consume(&mut self, now: u64, verifier_matches: bool) -> Result<(), IdentityError> {
        if now >= self.expires_at_ms {
            self.consumed = true;
        }
        if self.consumed || self.attempts_remaining == 0 {
            return Err(IdentityError::Denied);
        }
        self.attempts_remaining -= 1;
        if !verifier_matches || !self.eligible {
            return Err(IdentityError::Denied);
        }
        self.consumed = true;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RatePolicy {
    pub limit: u32,
    pub window_ms: u64,
}
pub const START_RATE: RatePolicy = RatePolicy {
    limit: 10,
    window_ms: 900_000,
};
pub const SUBJECT_RATE: RatePolicy = RatePolicy {
    // A user may authenticate all32 devices within an hour. This budgets code
    // issuance, not guesses: resend spacing and five verification attempts stay.
    limit: 32,
    window_ms: 3_600_000,
};
pub const VERIFY_RATE: RatePolicy = RatePolicy {
    limit: 30,
    window_ms: 900_000,
};
pub const POLL_RATE: RatePolicy = RatePolicy {
    limit: 180,
    window_ms: 900_000,
};

#[derive(Clone, Copy, Debug, Default)]
pub struct RateWindow {
    pub count: u32,
    pub ends_at_ms: u64,
}
impl RateWindow {
    pub fn admit(&mut self, now: u64, policy: RatePolicy) -> Result<(), IdentityError> {
        if now >= self.ends_at_ms {
            self.count = 0;
            self.ends_at_ms = now
                .checked_add(policy.window_ms)
                .ok_or(IdentityError::InvalidInput)?;
        }
        if self.count >= policy.limit {
            return Err(IdentityError::RateLimited);
        }
        self.count += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubStage {
    Pending,
    Verifying,
    AwaitingApproval,
    Approved,
    Denied,
    Consumed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GithubPoll {
    Pending,
    Approved,
}

#[derive(Clone, Copy, Debug)]
pub struct BrowserProof {
    pub cookie: ProtectedDigest,
    pub csrf: ProtectedDigest,
}

#[derive(Debug)]
pub struct GithubFlow {
    pub id: String,
    pub state: ProtectedDigest,
    pub exchange: ProtectedDigest,
    pub expires_at_ms: u64,
    pub locale: Locale,
    verifier: Option<SecretText>,
    verification_code: SecretText,
    approval: Option<BrowserProof>,
    stage: GithubStage,
    next_poll_at_ms: u64,
}
impl GithubFlow {
    pub fn new(
        id: String,
        state: ProtectedDigest,
        exchange: ProtectedDigest,
        verifier: SecretText,
        verification_code: SecretText,
        locale: Locale,
        now: u64,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            id,
            state,
            exchange,
            expires_at_ms: now
                .checked_add(GITHUB_LIFETIME_MS)
                .ok_or(IdentityError::InvalidInput)?,
            verifier: Some(verifier),
            verification_code,
            locale,
            approval: None,
            stage: GithubStage::Pending,
            next_poll_at_ms: now,
        })
    }
    pub fn claim_callback(&mut self, now: u64) -> Result<SecretText, IdentityError> {
        self.check_expiry(now)?;
        if self.stage != GithubStage::Pending {
            return Err(IdentityError::Denied);
        }
        self.stage = GithubStage::Verifying;
        self.verifier.take().ok_or(IdentityError::Denied)
    }
    pub fn complete_callback(
        &mut self,
        proof: Option<BrowserProof>,
        now: u64,
    ) -> Result<(), IdentityError> {
        self.check_expiry(now)?;
        if self.stage != GithubStage::Verifying {
            return Err(IdentityError::Denied);
        }
        self.stage = if proof.is_some() {
            GithubStage::AwaitingApproval
        } else {
            GithubStage::Denied
        };
        self.approval = proof;
        Ok(())
    }
    fn check_expiry(&mut self, now: u64) -> Result<(), IdentityError> {
        if now >= self.expires_at_ms {
            self.stage = GithubStage::Denied;
            self.verifier = None;
            self.approval = None;
        }
        if self.stage == GithubStage::Denied {
            Err(IdentityError::Denied)
        } else {
            Ok(())
        }
    }
    pub fn verification_code(&self) -> &str {
        self.verification_code.expose()
    }
    pub fn browser_proof(&self) -> Option<BrowserProof> {
        self.approval
    }
    pub fn approve(
        &mut self,
        proof_matches: bool,
        permit: bool,
        now: u64,
    ) -> Result<(), IdentityError> {
        self.check_expiry(now)?;
        if !proof_matches || self.stage != GithubStage::AwaitingApproval {
            return Err(IdentityError::Denied);
        }
        self.approval = None;
        self.stage = if permit {
            GithubStage::Approved
        } else {
            GithubStage::Denied
        };
        Ok(())
    }
    pub fn poll(&mut self, token_matches: bool, now: u64) -> Result<GithubPoll, IdentityError> {
        self.check_expiry(now)?;
        if !token_matches {
            return Err(IdentityError::Denied);
        }
        if now < self.next_poll_at_ms {
            return Err(IdentityError::RateLimited);
        }
        self.next_poll_at_ms = now
            .checked_add(GITHUB_POLL_MS)
            .ok_or(IdentityError::InvalidInput)?;
        match self.stage {
            GithubStage::Pending | GithubStage::Verifying | GithubStage::AwaitingApproval => {
                Ok(GithubPoll::Pending)
            }
            GithubStage::Approved => {
                self.stage = GithubStage::Consumed;
                Ok(GithubPoll::Approved)
            }
            GithubStage::Denied | GithubStage::Consumed => Err(IdentityError::Denied),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recent_authentication_is_distinct_from_session_validity() {
        let issued = 1_000_000;
        let session = Session::new(
            Owner {
                user_id: UserId::new("owner").unwrap(),
                tenant_id: TenantId::new("tenant").unwrap(),
            },
            AuthMethod::EmailOtp,
            issued,
        )
        .unwrap();
        assert!(!session.recently_authenticated(issued - 1));
        assert!(session.recently_authenticated(issued));
        assert!(session.recently_authenticated(issued + RECENT_AUTHENTICATION_MS));
        assert!(!session.recently_authenticated(issued + RECENT_AUTHENTICATION_MS + 1));
        assert!(session.active(issued + RECENT_AUTHENTICATION_MS + 1));
        assert!(!session.recently_authenticated(issued + SESSION_LIFETIME_MS));
    }
    #[test]
    fn cached_authorization_is_scoped_and_expires_without_online_authority() {
        let owner = Owner {
            user_id: UserId::new("owner").unwrap(),
            tenant_id: TenantId::new("tenant").unwrap(),
        };
        let device = crate::DeviceId::new("browser-installation").unwrap();
        let origin = "https://instance.example/";
        let grant = CachedDeviceAuthorization {
            origin: origin.into(),
            user_id: owner.user_id.clone(),
            tenant_id: owner.tenant_id.clone(),
            device_id: device.clone(),
            verified_at_ms: 10_000,
            expires_at_ms: 20_000,
        };
        for now in [10_000, 19_999] {
            assert!(
                grant
                    .authorize_offline(origin, &owner, &device, now)
                    .is_ok()
            );
        }
        for now in [0, 9_999, 20_000, u64::MAX] {
            assert_eq!(
                grant.authorize_offline(origin, &owner, &device, now),
                Err(IdentityError::Denied)
            );
        }
        assert!(
            grant
                .authorize_offline("https://other.example/", &owner, &device, 15_000)
                .is_err()
        );
        assert!(
            grant
                .authorize_offline(
                    origin,
                    &owner,
                    &crate::DeviceId::new("other").unwrap(),
                    15_000
                )
                .is_err()
        );
        for owner in [
            Owner {
                user_id: UserId::new("other").unwrap(),
                ..owner.clone()
            },
            Owner {
                tenant_id: TenantId::new("other").unwrap(),
                ..owner.clone()
            },
        ] {
            assert!(
                grant
                    .authorize_offline(origin, &owner, &device, 15_000)
                    .is_err()
            );
        }
    }

    #[test]
    fn cached_authorization_cannot_extend_the_existing_session_lifetime() {
        let owner = Owner {
            user_id: UserId::new("owner").unwrap(),
            tenant_id: TenantId::new("tenant").unwrap(),
        };
        let device = crate::DeviceId::new("device").unwrap();
        let mut grant = CachedDeviceAuthorization {
            origin: "https://instance.example/".into(),
            user_id: owner.user_id.clone(),
            tenant_id: owner.tenant_id.clone(),
            device_id: device.clone(),
            verified_at_ms: 1,
            expires_at_ms: SESSION_LIFETIME_MS + 1,
        };
        assert!(
            grant
                .authorize_offline(&grant.origin, &owner, &device, 2)
                .is_ok()
        );
        for expiry in [0, 1, SESSION_LIFETIME_MS + 2, u64::MAX] {
            grant.expires_at_ms = expiry;
            assert!(
                grant
                    .authorize_offline(&grant.origin, &owner, &device, 2)
                    .is_err()
            );
        }
    }

    #[test]
    fn otp_checks_eligibility_expiry_attempts_and_single_use() {
        let mut challenge = OtpChallenge::new(100, true).unwrap();
        for _ in 0..OTP_ATTEMPTS {
            assert_eq!(challenge.consume(101, false), Err(IdentityError::Denied));
        }
        assert_eq!(challenge.consume(101, true), Err(IdentityError::Denied));
        let mut challenge = OtpChallenge::new(100, false).unwrap();
        assert_eq!(challenge.consume(101, true), Err(IdentityError::Denied));
        let mut challenge = OtpChallenge::new(100, true).unwrap();
        assert_eq!(
            challenge.consume(100 + OTP_LIFETIME_MS, true),
            Err(IdentityError::Denied)
        );
        assert_eq!(challenge.consume(101, true), Err(IdentityError::Denied));
        let mut challenge = OtpChallenge::new(100, true).unwrap();
        assert!(challenge.consume(101, true).is_ok());
        assert_eq!(challenge.consume(101, true), Err(IdentityError::Denied));
    }
    #[test]
    fn github_callback_and_exchange_are_independently_single_use() {
        let mut flow = GithubFlow::new(
            "flow".into(),
            ProtectedDigest([1; 32]),
            ProtectedDigest([2; 32]),
            SecretText::new("ephemeral".into()),
            SecretText::new("12345678".into()),
            Locale::En,
            100,
        )
        .unwrap();
        assert!(flow.claim_callback(101).is_ok());
        assert!(flow.claim_callback(101).is_err());
        assert_eq!(flow.poll(false, 101), Err(IdentityError::Denied));
        assert_eq!(flow.poll(true, 101), Ok(GithubPoll::Pending));
        let proof = BrowserProof {
            cookie: ProtectedDigest([3; 32]),
            csrf: ProtectedDigest([4; 32]),
        };
        flow.complete_callback(Some(proof), 102).unwrap();
        assert_eq!(flow.poll(true, 102), Err(IdentityError::RateLimited));
        assert_eq!(
            flow.poll(true, 101 + GITHUB_POLL_MS),
            Ok(GithubPoll::Pending)
        );
        assert!(flow.approve(false, true, 102 + GITHUB_POLL_MS).is_err());
        flow.approve(true, true, 102 + GITHUB_POLL_MS).unwrap();
        assert!(flow.approve(true, true, 103 + GITHUB_POLL_MS).is_err());
        assert_eq!(
            flow.poll(true, 101 + 2 * GITHUB_POLL_MS),
            Ok(GithubPoll::Approved)
        );
        assert!(flow.poll(true, 101 + 3 * GITHUB_POLL_MS).is_err());
    }
    #[test]
    fn observed_github_expiry_and_browser_denial_are_terminal() {
        for deny in [false, true] {
            let mut flow = GithubFlow::new(
                "flow".into(),
                ProtectedDigest([1; 32]),
                ProtectedDigest([2; 32]),
                SecretText::new("ephemeral".into()),
                SecretText::new("12345678".into()),
                Locale::En,
                100,
            )
            .unwrap();
            if deny {
                flow.claim_callback(101).unwrap();
                flow.complete_callback(
                    Some(BrowserProof {
                        cookie: ProtectedDigest([3; 32]),
                        csrf: ProtectedDigest([4; 32]),
                    }),
                    102,
                )
                .unwrap();
                flow.approve(true, false, 103).unwrap();
            } else {
                assert!(flow.poll(true, 100 + GITHUB_LIFETIME_MS).is_err());
            }
            assert!(flow.claim_callback(101).is_err());
            assert!(flow.poll(true, 101).is_err());
            assert!(flow.approve(true, true, 101).is_err());
        }
    }
    #[test]
    fn email_normalization_and_rate_window_are_explicit() {
        assert_eq!(
            EmailAddress::parse(" Owner@Example.Invalid ").unwrap(),
            EmailAddress::parse("owner@example.invalid").unwrap()
        );
        for invalid in ["", "a@@b", "a\r\n@b", "a..b@c", "a@-b", "é@b", "a@b..c"] {
            assert!(EmailAddress::parse(invalid).is_err());
        }
        let mut window = RateWindow::default();
        for _ in 0..START_RATE.limit {
            assert!(window.admit(1, START_RATE).is_ok());
        }
        assert_eq!(window.admit(2, START_RATE), Err(IdentityError::RateLimited));
        assert!(window.admit(1 + START_RATE.window_ms, START_RATE).is_ok());
    }

    #[test]
    fn fleet_email_issuance_does_not_expand_otp_verification_attempts() {
        let mut issuance = RateWindow::default();
        for device in 0..32 {
            assert!(
                issuance
                    .admit(1000 + device * OTP_RESEND_MS, SUBJECT_RATE)
                    .is_ok()
            );
        }
        assert_eq!(
            issuance.admit(1000 + 32 * OTP_RESEND_MS, SUBJECT_RATE),
            Err(IdentityError::RateLimited)
        );
        let mut proof = OtpChallenge::new(1000, true).unwrap();
        for _ in 0..5 {
            assert_eq!(proof.consume(1001, false), Err(IdentityError::Denied));
        }
        assert_eq!(proof.consume(1002, true), Err(IdentityError::Denied));
    }
}
