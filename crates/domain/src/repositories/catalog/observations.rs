//! Canonical positive repository observations for the named NdsClient caller.
//! No store, provider I/O, authorization capability or admission-basis envelope.
use super::*;
use crate::sync::{
    Decision, EntityKind, Receipt,
    history::{OperationVersion, VersionedOperation},
};

pub mod projection;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ObservationKey {
    Owner(GithubAccountId),
    Repository(RepositoryId),
    Scope {
        principal: GithubAccountId,
        record_ref: String,
    },
}
impl ObservationKey {
    /// Decode a stored identity without accepting aliases or changing its realm.
    pub fn parse(value: &str) -> Result<Self, ModuleError> {
        let invalid = || ModuleError::InvalidInput;
        if !crate::sync::long_id(value) {
            return Err(invalid());
        }
        let key = if let Some(id) = value.strip_prefix("github:owner:") {
            Self::Owner(GithubAccountId::new(id.parse().map_err(|_| invalid())?)?)
        } else if let Some(id) = value.strip_prefix("github:repo:") {
            Self::Repository(RepositoryId::new(id.parse().map_err(|_| invalid())?)?)
        } else if let Some(scope) = value.strip_prefix("github:scope:") {
            let (principal, rest) = scope.split_once(':').ok_or_else(invalid)?;
            let (length, record_ref) = rest.split_once(':').ok_or_else(invalid)?;
            if length.parse::<usize>().map_err(|_| invalid())? != record_ref.len() {
                return Err(invalid());
            }
            Self::Scope {
                principal: GithubAccountId::new(principal.parse().map_err(|_| invalid())?)?,
                record_ref: record_ref.into(),
            }
        } else {
            return Err(invalid());
        };
        key.validate()?;
        if key.entity_id() != value {
            return Err(invalid());
        }
        Ok(key)
    }
    pub fn entity_id(&self) -> String {
        match self {
            Self::Owner(id) => format!("github:owner:{}", id.value()),
            Self::Repository(id) => format!("github:repo:{}", id.value()),
            Self::Scope {
                principal,
                record_ref,
            } => format!(
                "github:scope:{}:{}:{record_ref}",
                principal.value(),
                record_ref.len()
            ),
        }
    }
    pub fn validate(&self) -> Result<(), ModuleError> {
        if let Self::Scope { record_ref, .. } = self
            && !valid_identifier(record_ref)
        {
            return Err(ModuleError::InvalidInput);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationContext {
    pub principal: GithubAccountId,
    pub selection: CredentialSelection,
    pub scan_id: String,
}
impl ObservationContext {
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.selection.validate()?;
        if !valid_identifier(&self.scan_id) {
            return Err(ModuleError::InvalidInput);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSource {
    pub context: ObservationContext,
    pub page: Option<u8>,
}
impl ObservationSource {
    fn validate(&self) -> Result<(), ModuleError> {
        self.context.validate()?;
        if self
            .page
            .is_some_and(|p| !(1..=MAX_CATALOG_PAGES).contains(&p))
        {
            return Err(ModuleError::InvalidInput);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryFact {
    pub id: RepositoryId,
    pub owner_id: GithubAccountId,
    pub name: String,
    pub visibility: RepositoryVisibility,
    pub archived: bool,
    pub default_branch: Option<String>,
}
impl RepositoryFact {
    pub fn from_summary(value: &RepositorySummary) -> Result<Self, ModuleError> {
        value.owner.validate()?;
        let fact = Self {
            id: value.id,
            owner_id: value.owner.id,
            name: value.name.clone(),
            visibility: value.visibility,
            archived: value.archived,
            default_branch: value.default_branch.clone(),
        };
        fact.validate()?;
        Ok(fact)
    }
    fn validate(&self) -> Result<(), ModuleError> {
        if !repository_fields(&self.name, &self.default_branch) {
            return Err(ModuleError::InvalidResponse);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalOutcome {
    Complete,
    Partial,
    LimitReached,
    Failed(ModuleError),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteTraversal {
    pub pages: u8,
    pub repositories: u16,
    pub observed_at_ms: u64,
    pub scan_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeScan {
    pub outcome: TraversalOutcome,
    pub pages: u8,
    pub repositories: u16,
    pub last_complete: Option<CompleteTraversal>,
}
impl ScopeScan {
    fn validate(&self) -> Result<(), ModuleError> {
        let valid = |pages: u8, repositories: u16| {
            pages <= MAX_CATALOG_PAGES
                && usize::from(repositories) <= usize::from(pages) * REPOSITORIES_PER_PAGE
        };
        if !valid(self.pages, self.repositories)
            || matches!(self.outcome, TraversalOutcome::Complete) && self.pages == 0
        {
            return Err(ModuleError::InvalidResponse);
        }
        if matches!(self.outcome, TraversalOutcome::Complete)
            && self
                .last_complete
                .as_ref()
                .is_none_or(|c| c.pages != self.pages || c.repositories != self.repositories)
        {
            return Err(ModuleError::InvalidResponse);
        }
        if matches!(self.outcome, TraversalOutcome::LimitReached) && self.pages != MAX_CATALOG_PAGES
        {
            return Err(ModuleError::InvalidResponse);
        }
        if let Some(c) = &self.last_complete
            && (c.pages == 0
                || !valid(c.pages, c.repositories)
                || c.observed_at_ms == 0
                || c.observed_at_ms > MAX_REVISION
                || !valid_identifier(&c.scan_id))
        {
            return Err(ModuleError::InvalidResponse);
        }
        Ok(())
    }
    fn material_eq(&self, other: &Self) -> bool {
        self.outcome == other.outcome
            && self.pages == other.pages
            && self.repositories == other.repositories
            && self
                .last_complete
                .as_ref()
                .map(|c| (c.pages, c.repositories))
                == other
                    .last_complete
                    .as_ref()
                    .map(|c| (c.pages, c.repositories))
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationData {
    Owner { owner: GithubOwner },
    Repository { repository: RepositoryFact },
    ScopeScan { scan: ScopeScan },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryObservation {
    pub source: ObservationSource,
    pub data: ObservationData,
}
impl RepositoryObservation {
    pub fn key(&self) -> ObservationKey {
        match &self.data {
            ObservationData::Owner { owner } => ObservationKey::Owner(owner.id),
            ObservationData::Repository { repository } => ObservationKey::Repository(repository.id),
            ObservationData::ScopeScan { .. } => ObservationKey::Scope {
                principal: self.source.context.principal,
                record_ref: self.source.context.selection.record_ref().into(),
            },
        }
    }
    pub fn validate(&self) -> Result<(), ModuleError> {
        self.source.validate()?;
        match &self.data {
            ObservationData::Owner { owner } => owner.validate(),
            ObservationData::Repository { repository } => repository.validate(),
            ObservationData::ScopeScan { scan } => scan.validate(),
        }
    }
    pub fn material_eq(&self, other: &Self) -> bool {
        if self.key() != other.key() {
            return false;
        }
        match (&self.data, &other.data) {
            (ObservationData::ScopeScan { scan: a }, ObservationData::ScopeScan { scan: b }) => {
                // A scan describes access through this exact selected credential
                // version; equal counts do not make a replacement scope equal.
                self.source.context.selection == other.source.context.selection && a.material_eq(b)
            }
            _ => self.data == other.data,
        }
    }
}
/// Local target metadata, deliberately independent of server admission basis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetVersion {
    pub revision: u64,
    pub next_base: u64,
    pub pending_id: Option<String>,
    pub conflicted: bool,
}
impl TargetVersion {
    pub fn absent() -> Self {
        Self {
            revision: 0,
            next_base: 0,
            pending_id: None,
            conflicted: false,
        }
    }
    pub fn validate(&self) -> Result<(), ModuleError> {
        if self.revision > MAX_REVISION
            // A retained pending original may still target an older head after
            // inbox catch-up. This is a real pending state, not a corrupt row or
            // permission to rebase its immutable operation.
            || self.next_base < self.revision && self.pending_id.is_none()
            || self.next_base > MAX_REVISION
            || self
                .pending_id
                .as_ref()
                .is_some_and(|id| !valid_identifier(id))
        {
            return Err(ModuleError::InvalidInput);
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct ObservedTarget {
    pub key: ObservationKey,
    pub version: TargetVersion,
    pub value: Option<RepositoryObservation>,
    pub history_cursor: u64,
}
impl ObservedTarget {
    fn validate(&self) -> Result<(), ModuleError> {
        self.key.validate()?;
        self.version.validate()?;
        if self.history_cursor > MAX_REVISION {
            return Err(ModuleError::InvalidInput);
        }
        if let Some(v) = &self.value {
            v.validate()?;
            if v.key() != self.key {
                return Err(ModuleError::InvalidInput);
            }
        }
        Ok(())
    }
}
/// Capture before I/O. Candidate expectations have no public rebase setter.
#[derive(Clone, Debug)]
pub struct Capture {
    key: ObservationKey,
    version: TargetVersion,
}
impl Capture {
    pub fn before_read(key: ObservationKey, version: TargetVersion) -> Result<Self, ModuleError> {
        key.validate()?;
        version.validate()?;
        Ok(Self { key, version })
    }
    pub fn confirm(self, observation: RepositoryObservation) -> Result<Candidate, ModuleError> {
        observation.validate()?;
        if observation.key() != self.key {
            return Err(ModuleError::InvalidInput);
        }
        Ok(Candidate {
            observation,
            expected: self.version,
        })
    }
}
#[derive(Clone, Debug)]
pub struct Candidate {
    observation: RepositoryObservation,
    expected: TargetVersion,
}
impl Candidate {
    pub fn observation(&self) -> &RepositoryObservation {
        &self.observation
    }
    pub fn expected(&self) -> &TargetVersion {
        &self.expected
    }
    pub fn decide(
        self,
        current: &ObservedTarget,
        active: Option<&ObservationContext>,
    ) -> Result<PublicationDecision, ModuleError> {
        current.validate()?;
        if active != Some(&self.observation.source.context) {
            return Ok(PublicationDecision::SourceChanged);
        }
        if current.key != self.observation.key() {
            return Err(ModuleError::InvalidInput);
        }
        if current
            .value
            .as_ref()
            .is_some_and(|v| v.material_eq(&self.observation))
            && !current.version.conflicted
        {
            return Ok(PublicationDecision::Noop);
        }
        if current.version != self.expected || current.version.conflicted {
            return Ok(PublicationDecision::ReRead);
        }
        Ok(PublicationDecision::Write(Box::new(self)))
    }
    pub fn bind_dispatched(
        self,
        operation: VersionedOperation,
        wire_bytes: usize,
    ) -> Result<DispatchedObservation, ModuleError> {
        operation
            .validate(wire_bytes)
            .map_err(|_| ModuleError::InvalidInput)?;
        if !matches!(operation.version, OperationVersion::V3 { .. })
            || operation.operation.entity_kind != EntityKind::RepositoryState
            || operation.operation.entity_id != self.observation.key().entity_id()
            || operation.operation.base_revision != self.expected.next_base
        {
            return Err(ModuleError::InvalidInput);
        }
        Ok(DispatchedObservation {
            candidate: self,
            operation,
        })
    }
}
#[derive(Debug)]
pub enum PublicationDecision {
    Noop,
    Write(Box<Candidate>),
    ReRead,
    SourceChanged,
}
/// Adapter retains original exact request bytes; this decision never generates
/// or rewrites an operation/UUID. It validates the existing canonical receipt.
pub struct DispatchedObservation {
    candidate: Candidate,
    operation: VersionedOperation,
}
pub enum ReceiptAction {
    ReplayOriginal,
    Applied {
        revision: u64,
        server_seq: u64,
        preserve_current: bool,
    },
    Conflict(Box<KnownConflict>),
}
pub struct KnownConflict {
    observation: RepositoryObservation,
    current_revision: u64,
    server_seq: u64,
}
pub struct SettlementGuard {
    pub key: ObservationKey,
    pub version: TargetVersion,
    pub history_cursor: u64,
    pub through_seq: u64,
}
impl SettlementGuard {
    /// A new explicit resolution targets the observed committed head. The old
    /// pending operation's base remains a separate fact in the comparison guard.
    pub fn resolution_base(&self) -> u64 {
        self.version.revision
    }
    pub fn matches(&self, current: &ObservedTarget) -> bool {
        self.key == current.key
            && self.version == current.version
            && self.history_cursor == current.history_cursor
            && current.history_cursor >= self.through_seq
    }
}
pub struct ResolutionRead {
    capture: Capture,
    guard: SettlementGuard,
    old_scan: String,
}
pub struct ResolutionCandidate {
    candidate: Candidate,
    guard: SettlementGuard,
}
pub enum ResolutionDecision {
    ReRead,
    SourceChanged,
    /// Equal material still needs the existing confirmed resolution operation;
    /// this guard is never permission to delete retained conflicts locally.
    Equivalent(SettlementGuard),
    Write {
        candidate: Box<Candidate>,
        guard: SettlementGuard,
    },
}
impl ResolutionRead {
    /// A fresh scan marker cannot turn an old Candidate into a rebased one.
    /// The caller use case must actually read the provider again.
    pub fn confirm(
        self,
        observation: RepositoryObservation,
    ) -> Result<ResolutionCandidate, ModuleError> {
        if observation.source.context.scan_id == self.old_scan {
            return Err(ModuleError::InvalidInput);
        }
        Ok(ResolutionCandidate {
            candidate: self.capture.confirm(observation)?,
            guard: self.guard,
        })
    }
}
impl ResolutionCandidate {
    pub fn decide(
        self,
        current: &ObservedTarget,
        active: Option<&ObservationContext>,
    ) -> Result<ResolutionDecision, ModuleError> {
        current.validate()?;
        if active != Some(&self.candidate.observation.source.context) {
            return Ok(ResolutionDecision::SourceChanged);
        }
        if current.key != self.candidate.observation.key() || !self.guard.matches(current) {
            return Ok(ResolutionDecision::ReRead);
        }
        if current
            .value
            .as_ref()
            .is_some_and(|v| v.material_eq(&self.candidate.observation))
        {
            return Ok(ResolutionDecision::Equivalent(self.guard));
        }
        Ok(ResolutionDecision::Write {
            candidate: Box::new(self.candidate),
            guard: self.guard,
        })
    }
}
pub enum ConflictAction {
    CatchUp,
    Equivalent(SettlementGuard),
    FreshRead(ResolutionRead),
}
impl DispatchedObservation {
    pub fn operation(&self) -> &VersionedOperation {
        &self.operation
    }
    pub fn settle(
        &self,
        receipt: Option<&Receipt>,
        current_committed_revision: u64,
    ) -> Result<ReceiptAction, ModuleError> {
        if current_committed_revision > MAX_REVISION {
            return Err(ModuleError::InvalidInput);
        }
        let Some(receipt) = receipt else {
            return Ok(ReceiptAction::ReplayOriginal);
        };
        receipt
            .validate_for(&self.operation.operation)
            .map_err(|_| ModuleError::InvalidResponse)?;
        Ok(match receipt.decision {
            Decision::Apply { revision } => ReceiptAction::Applied {
                revision,
                server_seq: receipt.server_seq,
                preserve_current: current_committed_revision >= revision,
            },
            Decision::Conflict {
                current_revision, ..
            } => ReceiptAction::Conflict(Box::new(KnownConflict {
                observation: self.candidate.observation.clone(),
                current_revision,
                server_seq: receipt.server_seq,
            })),
        })
    }
}
impl KnownConflict {
    /// Restore one actual retained conflict without inventing the pre-dispatch
    /// target revision/pending ID, which cannot be recovered from the wire body.
    /// The adapter authenticates/decrypts the snapshot and retains exact bytes.
    pub fn restore(
        observation: RepositoryObservation,
        operation: &VersionedOperation,
        wire_bytes: usize,
        receipt: &Receipt,
    ) -> Result<Self, ModuleError> {
        observation.validate()?;
        operation
            .validate(wire_bytes)
            .map_err(|_| ModuleError::InvalidInput)?;
        if !matches!(operation.version, OperationVersion::V3 { .. })
            || operation.operation.entity_kind != EntityKind::RepositoryState
            || operation.operation.entity_id != observation.key().entity_id()
        {
            return Err(ModuleError::InvalidInput);
        }
        receipt
            .validate_for(&operation.operation)
            .map_err(|_| ModuleError::InvalidResponse)?;
        let Decision::Conflict {
            current_revision, ..
        } = receipt.decision
        else {
            return Err(ModuleError::InvalidResponse);
        };
        Ok(Self {
            observation,
            current_revision,
            server_seq: receipt.server_seq,
        })
    }

    /// A whole family may contain other alternatives or a blocked successor.
    /// Its caller can require fresh provider evidence even if this one receipt
    /// is equivalent. None means the committed projection must catch up first.
    pub fn fresh_read(
        self,
        current: &ObservedTarget,
    ) -> Result<Option<ResolutionRead>, ModuleError> {
        let old_scan = self.observation.source.context.scan_id.clone();
        Ok(match self.review(current)? {
            ConflictAction::CatchUp => None,
            ConflictAction::FreshRead(read) => Some(read),
            ConflictAction::Equivalent(guard) => Some(ResolutionRead {
                capture: Capture::before_read(current.key.clone(), current.version.clone())?,
                guard,
                old_scan,
            }),
        })
    }

    /// through_seq is only a transient reviewed receipt guard, never a payload
    /// lifecycle declaration or authority to prune server history.
    pub fn review(self, current: &ObservedTarget) -> Result<ConflictAction, ModuleError> {
        current.validate()?;
        if current.key != self.observation.key() {
            return Err(ModuleError::InvalidInput);
        }
        if current.version.revision < self.current_revision
            || current.history_cursor < self.server_seq
        {
            return Ok(ConflictAction::CatchUp);
        }
        let guard = SettlementGuard {
            key: current.key.clone(),
            version: current.version.clone(),
            history_cursor: current.history_cursor,
            through_seq: self.server_seq,
        };
        if current
            .value
            .as_ref()
            .is_some_and(|v| v.material_eq(&self.observation))
        {
            Ok(ConflictAction::Equivalent(guard))
        } else {
            Ok(ConflictAction::FreshRead(ResolutionRead {
                capture: Capture::before_read(current.key.clone(), current.version.clone())?,
                guard,
                old_scan: self.observation.source.context.scan_id.clone(),
            }))
        }
    }
}
