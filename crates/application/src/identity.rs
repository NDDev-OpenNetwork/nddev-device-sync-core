//! Owner authentication use cases. Stores implement the documented atomic
//! boundaries; adapters own cryptography, time sources, delivery and provider I/O.
pub use nddev_device_sync_domain::identity::*;
pub use nddev_device_sync_domain::{TenantId, UserId};
use std::future::Future;

pub struct EmailIssue {
    pub id: String,
    pub subject: ProtectedDigest,
    pub source: ProtectedDigest,
    pub verifier: ProtectedDigest,
    pub challenge: OtpChallenge,
    pub created_at_ms: u64,
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
}
pub struct BrowserApproval {
    pub flow_id: String,
    pub display: ApprovalDisplay,
    pub cookie: SecretText,
    pub csrf: SecretText,
}
pub enum GithubExchange {
    Pending,
    Session(IssuedSession),
}

/// The operator's explicit binding, after persistence has fixed the stable IDs.
pub struct IdentityBinding {
    pub owner: Owner,
    pub email: EmailAddress,
    pub github_id: Option<u64>,
}

pub trait IdentityStore: Send + Sync {
    /// A false result has the same public receipt, but no mail is queued. Issue,
    /// source/subject limits, capacity and invalidating prior codes are atomic.
    fn issue_email(
        &self,
        issue: EmailIssue,
    ) -> impl Future<Output = Result<bool, IdentityError>> + Send;
    fn invalidate_email(&self, id: &str) -> impl Future<Output = Result<(), IdentityError>> + Send;
    /// Verify in constant time, run OtpChallenge::consume under the row lock,
    /// persist failed attempts, and consume+create session in one transaction.
    fn consume_email(
        &self,
        id: &str,
        verifier: ProtectedDigest,
        source: ProtectedDigest,
        issue: SessionIssue,
        now: u64,
    ) -> impl Future<Output = Result<Session, IdentityError>> + Send;
    fn create_session(
        &self,
        issue: SessionIssue,
        now: u64,
    ) -> impl Future<Output = Result<Session, IdentityError>> + Send;
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
        proof: Option<BrowserProof>,
        now: u64,
    ) -> Result<Option<ApprovalDisplay>, IdentityError>;
    /// Both digests are compared in constant time. Approval is one-use and
    /// browser-bound; a successful provider callback alone never grants a session.
    fn approve(
        &self,
        id: &str,
        proof: BrowserProof,
        permit: bool,
        now: u64,
    ) -> Result<(), IdentityError>;
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
    owner: Owner,
    owner_email: EmailAddress,
    owner_github_id: Option<u64>,
}

impl<S: IdentityStore, C: IdentityCrypto, E: EmailDelivery, G: GithubIdentity, F: GithubFlowStore>
    IdentityService<S, C, E, G, F>
{
    pub fn new(
        store: S,
        crypto: C,
        email: E,
        github: G,
        flows: F,
        binding: IdentityBinding,
    ) -> Self {
        Self {
            store,
            crypto,
            email,
            github,
            flows,
            owner: binding.owner,
            owner_email: binding.email,
            owner_github_id: binding.github_id,
        }
    }
    pub fn methods(&self) -> (bool, bool) {
        (
            self.email.available(),
            self.owner_github_id.is_some() && self.github.available(),
        )
    }
    fn session_issue(
        &self,
        method: AuthMethod,
        now: u64,
    ) -> Result<(SecretText, SessionIssue), IdentityError> {
        let token = self.crypto.token()?;
        let digest = self.crypto.protect("session", &[token.expose().as_bytes()]);
        Ok((
            token,
            SessionIssue {
                digest,
                session: Session::new(self.owner.clone(), method, now)?,
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
        now: u64,
    ) -> Result<EmailReceipt, IdentityError> {
        if !self.email.available() {
            return Err(IdentityError::Unavailable);
        }
        let address = EmailAddress::parse(address)?;
        let id = self.crypto.token()?.into_inner();
        let code = self.crypto.otp()?;
        let challenge = OtpChallenge::new(now, address == self.owner_email)?;
        let issue = EmailIssue {
            id: id.clone(),
            source: self.source("email_source", source),
            subject: self
                .crypto
                .protect("email_subject", &[address.as_str().as_bytes()]),
            verifier: self
                .crypto
                .protect("email_code", &[id.as_bytes(), code.expose().as_bytes()]),
            challenge,
            created_at_ms: now,
        };
        if self.store.issue_email(issue).await?
            && challenge.eligible
            && self
                .email
                .queue(EmailMessage {
                    challenge_id: id.clone(),
                    recipient: self.owner_email.clone(),
                    code,
                    expires_at_ms: challenge.expires_at_ms,
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
        let (token, issue) = self.session_issue(AuthMethod::EmailOtp, now)?;
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
    ) -> Result<Option<BrowserApproval>, IdentityError> {
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
        let permitted = result
            .as_ref()
            .is_ok_and(|id| Some(*id) == self.owner_github_id);
        if !permitted {
            self.flows.complete_callback(&id, None, now)?;
            return match result {
                Err(IdentityError::Unavailable) => Err(IdentityError::Unavailable),
                _ => Ok(None),
            };
        }
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
        let display = self
            .flows
            .complete_callback(&id, Some(proof), now)?
            .ok_or(IdentityError::Denied)?;
        Ok(Some(BrowserApproval {
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
    ) -> Result<(), IdentityError> {
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
            GithubPoll::Approved => {
                let (token, issue) = self.session_issue(AuthMethod::Github, now)?;
                let session = self.store.create_session(issue, now).await?;
                Ok(GithubExchange::Session(IssuedSession { token, session }))
            }
        }
    }

    pub async fn session(&self, token: &str, now: u64) -> Result<Session, IdentityError> {
        if !valid_opaque(token) {
            return Err(IdentityError::Denied);
        }
        self.store
            .session(self.crypto.protect("session", &[token.as_bytes()]), now)
            .await
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
