//! Owner authentication use cases. Stores implement the documented atomic
//! boundaries; adapters own cryptography, time sources, delivery and provider I/O.
pub use nddev_device_sync_domain::identity::*;
pub use nddev_device_sync_domain::{TenantId, UserId};
use std::future::Future;

pub struct EmailIssue {
    pub id: String,
    pub subject: ProtectedDigest,
    /// Existing protected email binding; the store resolves the active user
    /// inside issuance, never from a caller-provided user or company ID.
    pub owner_binding: ProtectedDigest,
    pub source: ProtectedDigest,
    pub verifier: ProtectedDigest,
    pub challenge: OtpChallenge,
    pub created_at_ms: u64,
}

/// A fresh token's protected binding before the store has authenticated its
/// principal. Email consumption resolves the owner from its retained challenge.
pub struct SessionSeed {
    pub digest: ProtectedDigest,
    pub issued_at_ms: u64,
}
impl SessionSeed {
    pub fn issue(self, owner: Owner, method: AuthMethod) -> Result<SessionIssue, IdentityError> {
        Ok(SessionIssue {
            digest: self.digest,
            session: Session::new(owner, method, self.issued_at_ms)?,
        })
    }
}

pub struct SessionIssue {
    pub digest: ProtectedDigest,
    pub session: Session,
}
pub struct IssuedSession {
    pub token: SecretText,
    pub session: Session,
}
pub struct EmailReceipt {
    pub id: String,
    pub expires_in_seconds: u64,
    pub resend_after_seconds: u64,
}
pub struct EmailMessage {
    pub challenge_id: String,
    pub recipient: EmailAddress,
    pub code: SecretText,
    pub expires_at_ms: u64,
    pub locale: Locale,
}
pub struct GithubStart {
    pub flow_id: String,
    pub authorization_url: String,
    pub exchange_token: SecretText,
    pub verification_code: String,
}
pub struct ApprovalDisplay {
    pub verification_code: String,
    pub expires_at_ms: u64,
    pub locale: Locale,
}
pub struct BrowserApproval {
    pub flow_id: String,
    pub display: ApprovalDisplay,
    pub cookie: SecretText,
    pub csrf: SecretText,
}
pub enum GithubCallback {
    Approval(BrowserApproval),
    Complete(Locale),
}
pub enum GithubExchange {
    Pending,
    Session(IssuedSession),
}

pub trait IdentityStore: Send + Sync {
    /// A false result has the same public receipt, but no mail is queued. Issue,
    /// source/subject limits, capacity and invalidating prior codes are atomic.
    /// Resolve owner_binding against current active membership, bind the retained
    /// challenge to that owner, and set eligibility under the transaction. The
    /// supplied challenge contains timing/attempt bounds, not authorization.
    fn issue_email(
        &self,
        issue: EmailIssue,
    ) -> impl Future<Output = Result<bool, IdentityError>> + Send;
    fn invalidate_email(&self, id: &str) -> impl Future<Output = Result<(), IdentityError>> + Send;
    /// Verify in constant time, run OtpChallenge::consume under the row lock,
    /// persist failed attempts, and consume+create session in one transaction.
    /// Resolve the owner from the retained challenge and recheck active membership;
    /// the seed contains no owner selected by an unverified request.
    fn consume_email(
        &self,
        id: &str,
        verifier: ProtectedDigest,
        source: ProtectedDigest,
        issue: SessionSeed,
        now: u64,
    ) -> impl Future<Output = Result<Session, IdentityError>> + Send;
    /// Lookup only an explicitly bound, active principal. Provider email/name
    /// cannot substitute for this stable numeric binding.
    fn github_owner(
        &self,
        provider_id: u64,
        now: u64,
    ) -> impl Future<Output = Result<Option<Owner>, IdentityError>> + Send;
    /// Recheck the exact approved owner/provider binding and active membership
    /// transactionally; a changed binding cannot retarget a pending approval.
    fn create_github_session(
        &self,
        identity: VerifiedGithubIdentity,
        issue: SessionSeed,
        now: u64,
    ) -> impl Future<Output = Result<Session, IdentityError>> + Send;
    /// Return only a live session whose principal still has active membership.
    /// Cached roles or a process-wide bootstrap identity are not authorization.
    fn session(
        &self,
        digest: ProtectedDigest,
        now: u64,
    ) -> impl Future<Output = Result<Session, IdentityError>> + Send;
    fn revoke(
        &self,
        digest: ProtectedDigest,
        now: u64,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send;
    fn admit_source(
        &self,
        source: ProtectedDigest,
        policy: RatePolicy,
        now: u64,
    ) -> impl Future<Output = Result<(), IdentityError>> + Send;
}

pub trait IdentityCrypto: Send + Sync {
    /// 32 bytes of OS CSPRNG entropy encoded as canonical unpadded base64url.
    fn token(&self) -> Result<SecretText, IdentityError>;
    /// Uniform eight-digit code generated from the OS CSPRNG.
    fn otp(&self) -> Result<SecretText, IdentityError>;
    /// Domain-separated HMAC under the operator's private server pepper.
    fn protect(&self, purpose: &'static str, parts: &[&[u8]]) -> ProtectedDigest;
    fn pkce_challenge(&self, verifier: &SecretText) -> String;
}

pub trait EmailDelivery: Send + Sync {
    fn available(&self) -> bool;
    /// Finite in-memory delivery queue. Acceptance is not mailbox delivery;
    /// adapters record terminal failure and invalidate undelivered challenges.
    fn queue(&self, message: EmailMessage) -> Result<(), IdentityError>;
}

pub trait GithubIdentity: Send + Sync {
    fn available(&self) -> bool;
    fn authorization_url(
        &self,
        state: &SecretText,
        challenge: &str,
    ) -> Result<String, IdentityError>;
    /// Fixed provider/callback allowlist, S256 and bounded total exchange time.
    /// Revalidate GET /user, return only stable numeric identity, discard tokens.
    fn identify(
        &self,
        code: &SecretText,
        verifier: &SecretText,
    ) -> impl Future<Output = Result<u64, IdentityError>> + Send;
}

pub trait GithubFlowStore: Send + Sync {
    /// At most MAX_PENDING_GITHUB. All flows are invalid after process restart.
    fn insert(&self, flow: GithubFlow, now: u64) -> Result<(), IdentityError>;
    fn claim_callback(
        &self,
        state: ProtectedDigest,
        now: u64,
    ) -> Result<(String, SecretText), IdentityError>;
    fn complete_callback(
        &self,
        id: &str,
        approval: Option<GithubApproval>,
        now: u64,
    ) -> Result<ApprovalDisplay, IdentityError>;
    /// Both digests are compared in constant time. Approval is one-use and
    /// browser-bound; a successful provider callback alone never grants a session.
    fn approve(
        &self,
        id: &str,
        proof: BrowserProof,
        permit: bool,
        now: u64,
    ) -> Result<Locale, IdentityError>;
    /// Constant-time exchange verifier check and the GithubFlow::poll transition
    /// are atomic. Approved is returned at most once, before session persistence.
    fn poll(
        &self,
        id: &str,
        exchange: ProtectedDigest,
        now: u64,
    ) -> Result<GithubPoll, IdentityError>;
}

pub struct IdentityService<S, C, E, G, F> {
    store: S,
    crypto: C,
    email: E,
    github: G,
    flows: F,
}

impl<S: IdentityStore, C: IdentityCrypto, E: EmailDelivery, G: GithubIdentity, F: GithubFlowStore>
    IdentityService<S, C, E, G, F>
{
    pub fn new(store: S, crypto: C, email: E, github: G, flows: F) -> Self {
        Self {
            store,
            crypto,
            email,
            github,
            flows,
        }
    }
    pub fn methods(&self) -> (bool, bool) {
        (self.email.available(), self.github.available())
    }
    fn session_seed(&self, now: u64) -> Result<(SecretText, SessionSeed), IdentityError> {
        // Reject an impossible issuance time before generating or storing work.
        now.checked_add(SESSION_LIFETIME_MS)
            .ok_or(IdentityError::InvalidInput)?;
        let token = self.crypto.token()?;
        let digest = self.crypto.protect("session", &[token.expose().as_bytes()]);
        Ok((
            token,
            SessionSeed {
                digest,
                issued_at_ms: now,
            },
        ))
    }
    fn source(&self, action: &'static str, source: &[u8]) -> ProtectedDigest {
        self.crypto.protect(action, &[source])
    }

    pub async fn request_email(
        &self,
        address: &str,
        source: &[u8],
        locale: Locale,
        now: u64,
    ) -> Result<EmailReceipt, IdentityError> {
        if !self.email.available() {
            return Err(IdentityError::Unavailable);
        }
        let address = EmailAddress::parse(address)?;
        let id = self.crypto.token()?.into_inner();
        let code = self.crypto.otp()?;
        let challenge = OtpChallenge::new(now, false)?;
        let issue = EmailIssue {
            id: id.clone(),
            source: self.source("email_source", source),
            subject: self
                .crypto
                .protect("email_subject", &[address.as_str().as_bytes()]),
            owner_binding: self
                .crypto
                .protect("owner_binding", &[address.as_str().as_bytes()]),
            verifier: self
                .crypto
                .protect("email_code", &[id.as_bytes(), code.expose().as_bytes()]),
            challenge,
            created_at_ms: now,
        };
        if self.store.issue_email(issue).await?
            && self
                .email
                .queue(EmailMessage {
                    challenge_id: id.clone(),
                    recipient: address,
                    code,
                    expires_at_ms: challenge.expires_at_ms,
                    locale,
                })
                .is_err()
        {
            // Preserve a generic receipt when an allowed recipient's delivery
            // queue is full. Never leave an undelivered code usable on failure.
            self.store.invalidate_email(&id).await?;
        }
        Ok(EmailReceipt {
            id,
            expires_in_seconds: OTP_LIFETIME_MS / 1000,
            resend_after_seconds: OTP_RESEND_MS / 1000,
        })
    }

    pub async fn verify_email(
        &self,
        id: &str,
        code: &str,
        source: &[u8],
        now: u64,
    ) -> Result<IssuedSession, IdentityError> {
        if !valid_opaque(id) || code.len() != 8 || !code.bytes().all(|b| b.is_ascii_digit()) {
            return Err(IdentityError::InvalidInput);
        }
        let (token, issue) = self.session_seed(now)?;
        let verifier = self
            .crypto
            .protect("email_code", &[id.as_bytes(), code.as_bytes()]);
        let session = self
            .store
            .consume_email(
                id,
                verifier,
                self.source("email_verify", source),
                issue,
                now,
            )
            .await?;
        Ok(IssuedSession { token, session })
    }

    pub async fn start_github(
        &self,
        source: &[u8],
        locale: Locale,
        now: u64,
    ) -> Result<GithubStart, IdentityError> {
        if !self.methods().1 {
            return Err(IdentityError::Unavailable);
        }
        self.store
            .admit_source(self.source("github_start", source), START_RATE, now)
            .await?;
        let id = self.crypto.token()?.into_inner();
        let state = self.crypto.token()?;
        let exchange = self.crypto.token()?;
        let verifier = self.crypto.token()?;
        let verification_code = self.crypto.otp()?;
        let display_code = verification_code.expose().to_owned();
        let url = self
            .github
            .authorization_url(&state, &self.crypto.pkce_challenge(&verifier))?;
        let flow = GithubFlow::new(
            id.clone(),
            self.crypto
                .protect("github_state", &[state.expose().as_bytes()]),
            self.crypto
                .protect("github_exchange", &[exchange.expose().as_bytes()]),
            verifier,
            verification_code,
            locale,
            now,
        )?;
        self.flows.insert(flow, now)?;
        Ok(GithubStart {
            flow_id: id,
            authorization_url: url,
            exchange_token: exchange,
            verification_code: display_code,
        })
    }

    pub async fn github_callback(
        &self,
        state: &str,
        code: Option<&str>,
        source: &[u8],
        now: u64,
    ) -> Result<GithubCallback, IdentityError> {
        if !valid_opaque(state)
            || code.is_some_and(|code| {
                code.is_empty()
                    || code.len() > 512
                    || !code.is_ascii()
                    || code.bytes().any(|b| b.is_ascii_control())
            })
        {
            return Err(IdentityError::InvalidInput);
        }
        self.store
            .admit_source(self.source("github_callback", source), VERIFY_RATE, now)
            .await?;
        let (id, verifier) = self.flows.claim_callback(
            self.crypto.protect("github_state", &[state.as_bytes()]),
            now,
        )?;
        let result = match code {
            Some(code) => {
                self.github
                    .identify(&SecretText::new(code.into()), &verifier)
                    .await
            }
            None => Err(IdentityError::Denied),
        };
        let verified = match result {
            Ok(provider_id) if provider_id > 0 => self
                .store
                .github_owner(provider_id, now)
                .await
                .map(|owner| owner.map(|owner| VerifiedGithubIdentity { provider_id, owner })),
            Ok(_) => Ok(None),
            Err(error) => Err(error),
        };
        let identity = match verified {
            Ok(Some(identity)) => identity,
            other => {
                let display = self.flows.complete_callback(&id, None, now)?;
                return match other {
                    Err(IdentityError::Unavailable) => Err(IdentityError::Unavailable),
                    _ => Ok(GithubCallback::Complete(display.locale)),
                };
            }
        };
        let (cookie, csrf) = match (self.crypto.token(), self.crypto.token()) {
            (Ok(cookie), Ok(csrf)) => (cookie, csrf),
            _ => {
                self.flows.complete_callback(&id, None, now)?;
                return Err(IdentityError::Unavailable);
            }
        };
        let proof = BrowserProof {
            cookie: self.crypto.protect(
                "github_browser",
                &[id.as_bytes(), cookie.expose().as_bytes()],
            ),
            csrf: self
                .crypto
                .protect("github_csrf", &[id.as_bytes(), csrf.expose().as_bytes()]),
        };
        let display =
            self.flows
                .complete_callback(&id, Some(GithubApproval { identity, proof }), now)?;
        Ok(GithubCallback::Approval(BrowserApproval {
            flow_id: id,
            display,
            cookie,
            csrf,
        }))
    }

    pub async fn approve_github(
        &self,
        id: &str,
        cookie: &str,
        csrf: &str,
        permit: bool,
        source: &[u8],
        now: u64,
    ) -> Result<Locale, IdentityError> {
        if !valid_opaque(id) || !valid_opaque(cookie) || !valid_opaque(csrf) {
            return Err(IdentityError::Denied);
        }
        self.store
            .admit_source(self.source("github_approval", source), VERIFY_RATE, now)
            .await?;
        self.flows.approve(
            id,
            BrowserProof {
                cookie: self
                    .crypto
                    .protect("github_browser", &[id.as_bytes(), cookie.as_bytes()]),
                csrf: self
                    .crypto
                    .protect("github_csrf", &[id.as_bytes(), csrf.as_bytes()]),
            },
            permit,
            now,
        )
    }

    pub async fn exchange_github(
        &self,
        id: &str,
        exchange: &str,
        source: &[u8],
        now: u64,
    ) -> Result<GithubExchange, IdentityError> {
        if !valid_opaque(id) || !valid_opaque(exchange) {
            return Err(IdentityError::InvalidInput);
        }
        self.store
            .admit_source(self.source("github_poll", source), POLL_RATE, now)
            .await?;
        match self.flows.poll(
            id,
            self.crypto
                .protect("github_exchange", &[exchange.as_bytes()]),
            now,
        )? {
            GithubPoll::Pending => Ok(GithubExchange::Pending),
            GithubPoll::Approved(identity) => {
                let (token, issue) = self.session_seed(now)?;
                let session = self
                    .store
                    .create_github_session(identity, issue, now)
                    .await?;
                Ok(GithubExchange::Session(IssuedSession { token, session }))
            }
        }
    }

    pub async fn session(&self, token: &str, now: u64) -> Result<Session, IdentityError> {
        Ok(self.authenticate(token, now).await?.session)
    }
    pub async fn authenticate(
        &self,
        token: &str,
        now: u64,
    ) -> Result<AuthenticatedSession, IdentityError> {
        if !valid_opaque(token) {
            return Err(IdentityError::Denied);
        }
        let binding = self.crypto.protect("session", &[token.as_bytes()]);
        let session = self.store.session(binding, now).await?;
        // Storage is the authority for current membership and the exact retained
        // session. A process-wide bootstrap owner cannot represent invited users.
        if !session.active(now) {
            return Err(IdentityError::Denied);
        }
        Ok(AuthenticatedSession { session, binding })
    }
    pub async fn revoke(&self, token: &str, now: u64) -> Result<(), IdentityError> {
        if !valid_opaque(token) {
            return Err(IdentityError::Denied);
        }
        self.store
            .revoke(self.crypto.protect("session", &[token.as_bytes()]), now)
            .await
    }
}

pub fn valid_opaque(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
