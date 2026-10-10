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
    limit: 5,
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
}
