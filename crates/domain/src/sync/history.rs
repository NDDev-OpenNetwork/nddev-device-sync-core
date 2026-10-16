//! Canonical lifecycle semantics; no wire DTO, database, ciphertext copies or I/O.
//! Adapters own current authorization/nonce, exact original-byte lookup, verified
//! payload reads and one atomic durable publication under their existing locks.
use super::*;
use serde::{Serialize, Serializer, ser::SerializeTuple};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lifecycle {
    pub resolved_through_seq: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationVersion {
    V2,
    V3 {
        basis_seq: u64,
        lifecycle: Lifecycle,
    },
}
/// Domain envelope over the existing operation, never a second wire DTO.
#[derive(Clone, PartialEq, Eq)]
pub struct VersionedOperation {
    pub operation: Operation,
    pub version: OperationVersion,
}
impl VersionedOperation {
    pub fn validate(&self, bytes: usize) -> Result<(), SyncError> {
        self.operation.validate(bytes)?;
        self.validate_header()
    }
    pub fn validate_header(&self) -> Result<(), SyncError> {
        self.operation.validate_header()?;
        match self.version {
            OperationVersion::V2 if self.operation.entity_kind != EntityKind::RepositoryState => {
                Ok(())
            }
            OperationVersion::V3 {
                basis_seq,
                lifecycle,
            } => {
                if basis_seq > MAX_REVISION || lifecycle.resolved_through_seq > basis_seq {
                    return Err(SyncError::Invalid);
                }
                let prefix = format!("v3:{basis_seq}:");
                if [&self.operation.id, &self.operation.idempotency_key]
                    .iter()
                    .any(|id| !id.starts_with(&prefix) || id.len() == prefix.len())
                {
                    return Err(SyncError::Invalid);
                }
                Ok(())
            }
            _ => Err(SyncError::Invalid),
        }
    }
    /// Qualify identity before encryption; never call this on dispatched/Unknown
    /// work. This does not authorize automatic unsent requalification either.
    pub fn qualify(
        mut operation: Operation,
        basis_seq: u64,
        lifecycle: Lifecycle,
    ) -> Result<Self, SyncError> {
        operation.id = format!("v3:{basis_seq}:{}", operation.id);
        operation.idempotency_key = format!("v3:{basis_seq}:{}", operation.idempotency_key);
        let value = Self {
            operation,
            version: OperationVersion::V3 {
                basis_seq,
                lifecycle,
            },
        };
        value.validate_header()?;
        Ok(value)
    }
    pub fn lifecycle(&self) -> Lifecycle {
        match self.version {
            OperationVersion::V2 => Lifecycle {
                resolved_through_seq: 0,
            },
            OperationVersion::V3 { lifecycle, .. } => lifecycle,
        }
    }
    pub fn aad<'a>(
        &'a self,
        scope: AadScope<'a>,
        key_id: &'a str,
    ) -> Result<RecordAad<'a>, SyncError> {
        if scope.origin.is_empty()
            || scope.origin.len() > 2048
            || crate::TenantId::new(scope.tenant).is_err()
            || crate::UserId::new(scope.user).is_err()
            || !crate::valid_identifier(key_id)
        {
            return Err(SyncError::Invalid);
        }
        // Encryption precedes ciphertext validation; validate metadata with the
        // same canonical rules, using the already-shaped placeholder payload.
        self.validate_header()?;
        Ok(RecordAad {
            scope,
            operation: self,
            key_id,
        })
    }
}
#[derive(Clone, Copy)]
pub struct AadScope<'a> {
    pub origin: &'a str,
    pub tenant: &'a str,
    pub user: &'a str,
}
/// Serialize with the adapter's existing serde_json. V2 is byte-identical to
/// deployed Vault record_aad; V3 adds canonical header values in this one place.
pub struct RecordAad<'a> {
    scope: AadScope<'a>,
    operation: &'a VersionedOperation,
    key_id: &'a str,
}
impl Serialize for RecordAad<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let v = self.operation;
        let o = &v.operation;
        let mut tuple = serializer.serialize_tuple(if v.version == OperationVersion::V2 {
            10
        } else {
            14
        })?;
        tuple.serialize_element(if v.version == OperationVersion::V2 {
            "NDS-RECORD-V2"
        } else {
            "NDS-RECORD-V3"
        })?;
        if v.version != OperationVersion::V2 {
            tuple.serialize_element(&3_u8)?;
        }
        tuple.serialize_element(self.scope.origin)?;
        tuple.serialize_element(self.scope.tenant)?;
        tuple.serialize_element(self.scope.user)?;
        tuple.serialize_element(o.device.as_str())?;
        tuple.serialize_element(o.entity_kind.as_str())?;
        tuple.serialize_element(&o.entity_id)?;
        tuple.serialize_element(&o.id)?;
        tuple.serialize_element(&o.base_revision)?;
        tuple.serialize_element(self.key_id)?;
        if let OperationVersion::V3 {
            basis_seq,
            lifecycle,
        } = v.version
        {
            tuple.serialize_element(&o.idempotency_key)?;
            tuple.serialize_element(&basis_seq)?;
            tuple.serialize_element(&lifecycle)?;
        }
        tuple.end()
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryVersion {
    pub head: u64,
    pub floor: u64,
    pub base: u64,
}
impl HistoryVersion {
    pub fn validate(self) -> Result<(), SyncError> {
        if self.floor > self.head || self.base != self.floor || self.head > MAX_REVISION {
            Err(SyncError::Invalid)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    ExactOriginal,
    Collision,
    Missing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownOutcome {
    BasisExpired,
    LegacyMissing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    ReplayOriginal,
    New,
    Unknown(UnknownOutcome),
}
/// Call only after current authenticated owner/device and fresh nonce checks.
/// Exact lookup compares original raw request bytes, not a reconstructed DTO.
pub fn admission(
    lookup: Lookup,
    version: OperationVersion,
    history: HistoryVersion,
    legacy_new: bool,
) -> Result<Admission, SyncError> {
    match lookup {
        Lookup::ExactOriginal => return Ok(Admission::ReplayOriginal),
        Lookup::Collision => return Err(SyncError::Idempotency),
        Lookup::Missing => {}
    }
    history.validate()?;
    Ok(match version {
        OperationVersion::V2 if legacy_new => Admission::New,
        OperationVersion::V2 => Admission::Unknown(UnknownOutcome::LegacyMissing),
        OperationVersion::V3 { .. } if legacy_new => return Err(SyncError::Invalid),
        OperationVersion::V3 { basis_seq, .. } if basis_seq < history.floor => {
            Admission::Unknown(UnknownOutcome::BasisExpired)
        }
        OperationVersion::V3 { basis_seq, .. } if basis_seq <= history.head => Admission::New,
        _ => return Err(SyncError::Invalid),
    })
}
/// Raw UTF-8 byte counts, never encoded-string character counts. Owning row
/// adapters call this before parsing/staging; metadata plans use the same caps.
pub fn validate_original_lengths(
    request_bytes: usize,
    result_bytes: usize,
) -> Result<(), SyncError> {
    if !(1..=MAX_OPERATION_BYTES).contains(&request_bytes)
        || !(1..=MAX_RESULT_BYTES).contains(&result_bytes)
    {
        Err(SyncError::Invalid)
    } else {
        Ok(())
    }
}
fn committed_resolution(version: OperationVersion) -> u64 {
    match version {
        OperationVersion::V2 => 0,
        OperationVersion::V3 { lifecycle, .. } => lifecycle.resolved_through_seq,
    }
}

/// Borrowed existing row metadata, not payload/receipt bodies or a new store.
/// The adapter derives this from immutable full original rows in one scope.
#[derive(Clone, Copy)]
pub struct RetainedMeta<'a> {
    pub sequence: u64,
    pub kind: EntityKind,
    pub entity: &'a str,
    pub decision: Decision,
    pub version: OperationVersion,
    pub request_bytes: u32,
    pub result_bytes: u32,
}
impl RetainedMeta<'_> {
    pub fn cost(self) -> u64 {
        2 * u64::from(self.request_bytes) + u64::from(self.result_bytes)
    }
    fn resolution(self) -> u64 {
        committed_resolution(self.version)
    }
    fn validate(self) -> Result<(), SyncError> {
        validate_original_lengths(self.request_bytes as usize, self.result_bytes as usize)?;
        if !(1..=MAX_REVISION).contains(&self.sequence) || !long_id(self.entity) {
            return Err(SyncError::Invalid);
        }
        if self.version == OperationVersion::V2 && self.kind == EntityKind::RepositoryState {
            return Err(SyncError::Invalid);
        }
        if let OperationVersion::V3 {
            basis_seq,
            lifecycle,
        } = self.version
            && (basis_seq >= self.sequence || lifecycle.resolved_through_seq > basis_seq)
        {
            return Err(SyncError::Invalid);
        }
        match self.decision {
            Decision::Apply { revision } if revision == 0 || revision > MAX_REVISION => {
                Err(SyncError::Invalid)
            }
            Decision::Conflict {
                base_revision,
                current_revision,
            } if base_revision == current_revision
                || base_revision > MAX_REVISION
                || current_revision > MAX_REVISION =>
            {
                Err(SyncError::Invalid)
            }
            _ => Ok(()),
        }
    }
}
#[derive(Clone, Copy)]
pub struct RetentionCaps {
    pub rows: u64,
    pub bytes: u64,
    pub entities: u64,
}
impl RetentionCaps {
    fn reserving(self, rows: u64) -> Self {
        let row_bytes = (2 * MAX_OPERATION_BYTES + MAX_RESULT_BYTES) as u64;
        Self {
            rows: self.rows.saturating_sub(rows),
            bytes: self.bytes.saturating_sub(rows.saturating_mul(row_bytes)),
            entities: self.entities,
        }
    }
    fn fits_append(self, count: u64, bytes: u64, extra: RetainedMeta<'_>) -> bool {
        count < self.rows
            && bytes
                .checked_add(extra.cost())
                .is_some_and(|n| n <= self.bytes)
    }
    /// Applied writes replenish headroom before the hard limit. Conflicts may
    /// consume that reserve, but never initiate maintenance at the soft limit.
    pub fn requires_retention(
        self,
        count: u64,
        bytes: u64,
        extra: RetainedMeta<'_>,
        reserve_rows: u64,
    ) -> bool {
        !self.fits_append(count, bytes, extra)
            || matches!(extra.decision, Decision::Apply { .. })
                && !self
                    .reserving(reserve_rows)
                    .fits_append(count, bytes, extra)
    }
}
impl Default for RetentionCaps {
    fn default() -> Self {
        Self {
            rows: MAX_OPERATIONS,
            bytes: MAX_STORED_BYTES,
            entities: MAX_ENTITY_COUNT,
        }
    }
}
pub struct RetentionPlan {
    pub base: u64,
    pub members: Vec<u64>,
    pub keep: Vec<u64>,
    pub bytes: u64,
    pub entities: u64,
}
/// O(MAX_OPERATIONS) metadata, with at most one prospective extra row. The
/// returned sequence references are resolved to original full rows by the SAME
/// adapter transaction; no payload is cloned and no deletion occurs here.
pub fn retention_plan(
    rows: &[RetainedMeta<'_>],
    extra: Option<RetainedMeta<'_>>,
    history: HistoryVersion,
    cut: u64,
    caps: RetentionCaps,
) -> Result<RetentionPlan, SyncError> {
    history.validate()?;
    if rows.len() > MAX_OPERATIONS as usize
        || cut < history.floor
        || cut > history.head
        || extra.is_some_and(|r| r.sequence != history.head)
    {
        return Err(SyncError::Invalid);
    }
    let all = || rows.iter().copied().chain(extra);
    let mut last = 0;
    let mut suffix = history.floor;
    let mut applied = BTreeMap::new();
    let mut latest_seen = BTreeMap::new();
    for row in all() {
        row.validate()?;
        if row.sequence <= last || row.sequence > history.head {
            return Err(SyncError::Invalid);
        }
        last = row.sequence;
        if row.sequence > history.floor {
            suffix = suffix.checked_add(1).ok_or(SyncError::Invalid)?;
            if suffix != row.sequence {
                return Err(SyncError::Invalid);
            }
        }
        let key = (row.kind, row.entity);
        if matches!(row.decision, Decision::Apply { .. }) {
            // Validate every Applied progression, including the retained suffix.
            // The as-of-cut selector is independent of this publication guard.
            if let Some(previous) = latest_seen.insert(key, row)
                && applied_projection(previous, row)? != AppliedProjection::Replace
            {
                return Err(SyncError::Invalid);
            }
            if row.sequence <= cut {
                applied.insert(key, row);
            }
        }
    }
    if suffix != history.head {
        return Err(SyncError::Invalid);
    }
    let mut keep = Vec::new();
    let mut members = Vec::new();
    let mut bytes = 0_u64;
    for row in all() {
        let latest = applied.get(&(row.kind, row.entity));
        let required = row.sequence > cut
            || match row.decision {
                Decision::Apply { .. } => latest.is_some_and(|r| r.sequence == row.sequence),
                Decision::Conflict { .. } => row.sequence > latest.map_or(0, |r| r.resolution()),
            };
        if required {
            keep.push(row.sequence);
            bytes = bytes
                .checked_add(row.cost())
                .ok_or(SyncError::CapacityExhausted)?;
            if row.sequence <= cut {
                members.push(row.sequence)
            }
        }
    }
    if keep.len() as u64 > caps.rows
        || bytes > caps.bytes
        || latest_seen.len() as u64 > caps.entities
    {
        return Err(SyncError::CapacityExhausted);
    }
    Ok(RetentionPlan {
        base: cut,
        members,
        keep,
        bytes,
        entities: latest_seen.len() as u64,
    })
}
/// Prepare an explicit choice from the complete observed conflict set for one
/// entity. The adapter supplies its committed outer lifecycle and actual scoped
/// conflict receipts from the same snapshot. Neither cursor nor legacy inner R
/// grants resolution authority. An unsent local choice may carry the existing R.
pub fn resolution_lifecycle(
    previous: Lifecycle,
    witnessed: &[u64],
    observed_through: u64,
) -> Result<Lifecycle, SyncError> {
    if observed_through > MAX_REVISION
        || previous.resolved_through_seq > observed_through
        || witnessed.len() > MAX_OPERATIONS as usize
    {
        return Err(SyncError::Invalid);
    }
    let proof: BTreeSet<_> = witnessed.iter().copied().collect();
    if proof.len() != witnessed.len()
        || proof.iter().any(|seq| *seq == 0 || *seq > observed_through)
    {
        return Err(SyncError::Invalid);
    }
    Ok(Lifecycle {
        resolved_through_seq: previous
            .resolved_through_seq
            .max(proof.last().copied().unwrap_or(0)),
    })
}

/// Plan only: actual CAS Applied + full-row preservation + publication must
/// commit together. Failure cannot consume a sequence or resolve alternatives.
pub fn atomic_resolution(
    rows: &[RetainedMeta<'_>],
    resolver: RetainedMeta<'_>,
    witnessed: &[u64],
    expected: HistoryVersion,
    current: HistoryVersion,
    caps: RetentionCaps,
) -> Result<RetentionPlan, SyncError> {
    current.validate()?;
    if expected != current || witnessed.len() > MAX_OPERATIONS as usize {
        return Err(SyncError::Invalid);
    }
    let next = current
        .head
        .checked_add(1)
        .filter(|v| *v <= MAX_REVISION)
        .ok_or(SyncError::CapacityExhausted)?;
    resolver.validate()?;
    if resolver.sequence != next || !matches!(resolver.decision, Decision::Apply { .. }) {
        return Err(SyncError::KeyConflict);
    }
    if admission(Lookup::Missing, resolver.version, current, false)? != Admission::New {
        return Err(SyncError::Invalid);
    }
    let previous = rows
        .iter()
        .rev()
        .find(|r| {
            r.kind == resolver.kind
                && r.entity == resolver.entity
                && matches!(r.decision, Decision::Apply { .. })
        })
        .ok_or(SyncError::Invalid)?;
    let (Decision::Apply { revision: old }, Decision::Apply { revision: new }) =
        (previous.decision, resolver.decision)
    else {
        unreachable!()
    };
    if old.checked_add(1) != Some(new) || resolver.resolution() <= previous.resolution() {
        return Err(SyncError::Invalid);
    }
    // The first current-format edit may preserve an already-Applied legacy
    // decision. Its watermark predates that actual legacy commit and cannot
    // cover later conflicts. All other raises require exact new witnesses.
    let legacy_carry = previous.version == OperationVersion::V2
        && previous.kind == EntityKind::VaultRecord
        && resolver.resolution() < previous.sequence
        && matches!(resolver.version, OperationVersion::V3 { basis_seq, .. } if basis_seq >= previous.sequence);
    let proof: BTreeSet<_> = witnessed.iter().copied().collect();
    if proof.is_empty() && !legacy_carry || proof.len() != witnessed.len() {
        return Err(SyncError::Invalid);
    }
    for seq in &proof {
        let row = &rows[rows
            .binary_search_by_key(seq, |r| r.sequence)
            .map_err(|_| SyncError::Invalid)?];
        if row.kind != resolver.kind
            || row.entity != resolver.entity
            || !matches!(row.decision, Decision::Conflict { .. })
            || *seq > resolver.resolution()
        {
            return Err(SyncError::Invalid);
        }
    }
    let known = resolution_lifecycle(
        Lifecycle {
            resolved_through_seq: previous.resolution(),
        },
        witnessed,
        current.head,
    )?;
    if resolver.resolution() != known.resolved_through_seq && !legacy_carry {
        return Err(SyncError::Invalid);
    }
    for row in rows {
        if row.kind == resolver.kind
            && row.entity == resolver.entity
            && matches!(row.decision, Decision::Conflict { .. })
            && row.sequence > previous.resolution()
            && row.sequence <= resolver.resolution()
            && !proof.contains(&row.sequence)
        {
            return Err(SyncError::Invalid);
        }
    }
    retention_plan(
        rows,
        Some(resolver),
        HistoryVersion {
            head: next,
            ..current
        },
        next,
        caps,
    )
}

/// Admit a pressured append with room for a bounded following upload wave when
/// the keep-set permits it. Hard quotas never increase. A resolver must first
/// pass the same witness/CAS checks as atomic_resolution; an ordinary failed CAS
/// cannot publish maintenance. Prefer the earliest sufficient cut so original
/// receipts and in-flight admission bases survive for as long as possible.
pub fn append_retention_plan(
    rows: &[RetainedMeta<'_>],
    extra: RetainedMeta<'_>,
    current: HistoryVersion,
    caps: RetentionCaps,
    reserve_rows: u64,
) -> Result<RetentionPlan, SyncError> {
    current.validate()?;
    let next = current
        .head
        .checked_add(1)
        .filter(|v| *v <= MAX_REVISION)
        .ok_or(SyncError::CapacityExhausted)?;
    if rows.len() > MAX_OPERATIONS as usize
        || extra.sequence != next
        || reserve_rows > MAX_OPERATIONS
    {
        return Err(SyncError::Invalid);
    }
    let history = HistoryVersion {
        head: next,
        ..current
    };
    let previous = rows.iter().rev().find(|r| {
        r.kind == extra.kind
            && r.entity == extra.entity
            && matches!(r.decision, Decision::Apply { .. })
    });
    let previous_resolution = previous.map_or(0, |r| r.resolution());
    let last = if extra.resolution() > previous_resolution {
        let witnesses = rows
            .iter()
            .filter(|r| {
                r.kind == extra.kind
                    && r.entity == extra.entity
                    && matches!(r.decision, Decision::Conflict { .. })
                    && r.sequence <= extra.resolution()
            })
            .map(|r| r.sequence)
            .collect::<Vec<_>>();
        atomic_resolution(rows, extra, &witnesses, current, current, caps)?
    } else {
        if !matches!(extra.decision, Decision::Apply { .. }) {
            return Err(SyncError::CapacityExhausted);
        }
        retention_plan(rows, Some(extra), history, current.head, caps)?
    };
    let latest_cut = last.base;
    let preferred = caps.reserving(reserve_rows);
    // Reserve is a preference, never a prerequisite for a meaningful resolution.
    // A pinned keep-set may only permit that one append to make progress.
    let (mut best, target) = match retention_plan(rows, Some(extra), history, latest_cut, preferred)
    {
        Ok(plan) => (plan, preferred),
        Err(SyncError::CapacityExhausted) => (last, caps),
        Err(error) => return Err(error),
    };
    let mut cuts = rows
        .iter()
        .filter(|r| {
            r.sequence >= current.floor
                && r.sequence <= latest_cut
                && matches!(r.decision, Decision::Apply { .. })
        })
        .map(|r| r.sequence)
        .collect::<Vec<_>>();
    cuts.extend([current.floor, latest_cut]);
    cuts.sort_unstable();
    cuts.dedup();
    let (mut low, mut high) = (0, cuts.len() - 1);
    while low < high {
        let mid = low + (high - low) / 2;
        match retention_plan(rows, Some(extra), history, cuts[mid], target) {
            Ok(plan) => {
                best = plan;
                high = mid;
            }
            Err(SyncError::CapacityExhausted) => low = mid + 1,
            Err(error) => return Err(error),
        }
    }
    if best.base != cuts[low] {
        best = retention_plan(rows, Some(extra), history, cuts[low], target)?;
    }
    Ok(best)
}
/// Sparse base members do not advance an inbox cursor. Complete image install
/// is always partial until an ordinary contiguous delta/freshness transaction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InstallVersion {
    pub cursor: u64,
    pub local_revision: u64,
    pub known_committed_seq: u64,
}
pub fn install_decision<G: Eq>(
    expected: &G,
    current: &G,
    before: InstallVersion,
    now: InstallVersion,
    stage_through: u64,
    complete: bool,
) -> Result<(), SyncError> {
    if expected != current
        || before != now
        || !complete
        || stage_through > MAX_REVISION
        || stage_through < now.cursor.max(now.known_committed_seq)
    {
        Err(SyncError::Invalid)
    } else {
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppliedProjection {
    IgnoreEarlier,
    VerifySameOriginal,
    Replace,
}
/// Validated current Applied-head metadata; no invented receipt or cost.
/// Fields are private: a missing-receipt input is only supported for an actually
/// verified V2 operation with known stored revision and nonzero server sequence.
#[derive(Clone, Copy)]
pub struct AppliedHeadMeta<'a> {
    sequence: u64,
    kind: EntityKind,
    entity: &'a str,
    revision: u64,
    version: OperationVersion,
}
impl<'a> AppliedHeadMeta<'a> {
    /// The owning adapter authenticates the same committed legacy payload and
    /// supplies its actual stored revision/sequence. Preserve its prior decision
    /// in a NEW unencrypted operation; never rewrite a retained/dispatched body.
    pub fn inherit_legacy_resolution(
        self,
        authenticated_resolution: u64,
        mut next: VersionedOperation,
    ) -> Result<VersionedOperation, SyncError> {
        if self.version != OperationVersion::V2
            || self.kind != EntityKind::VaultRecord
            || next.operation.entity_kind != self.kind
            || next.operation.entity_id != self.entity
            || next.operation.base_revision < self.revision
            || authenticated_resolution >= self.sequence
            || !next.operation.payload.ciphertext.is_empty()
        {
            return Err(SyncError::Invalid);
        }
        let OperationVersion::V3 {
            basis_seq,
            ref mut lifecycle,
        } = next.version
        else {
            return Err(SyncError::Invalid);
        };
        if self.sequence > basis_seq {
            return Err(SyncError::Invalid);
        }
        lifecycle.resolved_through_seq =
            lifecycle.resolved_through_seq.max(authenticated_resolution);
        next.validate_header()?;
        Ok(next)
    }

    /// The adapter supplies the existing verified stored V2 body and its real
    /// byte count/revision/sequence in the original scope. This does not recover
    /// receipt bytes, status or cost, and never extracts legacy payload inner R.
    pub fn verified_v2(
        operation: &'a VersionedOperation,
        original_bytes: usize,
        revision: u64,
        sequence: u64,
    ) -> Result<Self, SyncError> {
        if operation.version != OperationVersion::V2
            || original_bytes == 0
            || !(1..=MAX_REVISION).contains(&sequence)
        {
            return Err(SyncError::Invalid);
        }
        operation.validate(original_bytes)?;
        if operation
            .operation
            .decide(operation.operation.base_revision)?
            != (Decision::Apply { revision })
        {
            return Err(SyncError::Invalid);
        }
        Ok(Self {
            sequence,
            kind: operation.operation.entity_kind,
            entity: &operation.operation.entity_id,
            revision,
            version: operation.version,
        })
    }
    fn from_retained(row: RetainedMeta<'a>) -> Result<Self, SyncError> {
        // Ordinary full rows still require nonzero actual original lengths and
        // all existing version/R/header/decision validation before projection.
        row.validate()?;
        let Decision::Apply { revision } = row.decision else {
            return Err(SyncError::Invalid);
        };
        Ok(Self {
            sequence: row.sequence,
            kind: row.kind,
            entity: row.entity,
            revision,
            version: row.version,
        })
    }
    fn resolution(self) -> u64 {
        committed_resolution(self.version)
    }
}

/// Existing retained-row callers preserve the full-row validation/cost boundary.
pub fn applied_projection(
    current: RetainedMeta<'_>,
    incoming: RetainedMeta<'_>,
) -> Result<AppliedProjection, SyncError> {
    applied_head_projection(AppliedHeadMeta::from_retained(current)?, incoming)
}

/// Incoming is always a full original retained row. Same revision/sequence only
/// authorizes VerifySameOriginal; the adapter must still check the scoped exact
/// original body/identity using its established V2 normalization compatibility.
pub fn applied_head_projection(
    current: AppliedHeadMeta<'_>,
    incoming: RetainedMeta<'_>,
) -> Result<AppliedProjection, SyncError> {
    let incoming = AppliedHeadMeta::from_retained(incoming)?;
    if current.kind != incoming.kind || current.entity != incoming.entity {
        return Err(SyncError::Invalid);
    }
    let (old, new) = (current.revision, incoming.revision);
    if new < old && incoming.sequence < current.sequence {
        return Ok(AppliedProjection::IgnoreEarlier);
    }
    if new == old
        && incoming.sequence == current.sequence
        && incoming.resolution() == current.resolution()
    {
        return Ok(AppliedProjection::VerifySameOriginal);
    }
    if new <= old
        || incoming.sequence <= current.sequence
        || incoming.resolution() < current.resolution()
    {
        return Err(SyncError::Invalid);
    }
    Ok(AppliedProjection::Replace)
}

/// Sparse membership progress is not an inbox cursor. This value contains no
/// payloads; the owning stage transaction persists it only after whole-page
/// scope/key/AEAD/receipt verification succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseProgress {
    pub base: u64,
    pub total: usize,
    pub received: usize,
    pub after_member: u64,
}
impl BaseProgress {
    pub fn advance(
        self,
        base: u64,
        total: usize,
        sequences: &[u64],
        next: u64,
        more: bool,
    ) -> Result<Self, SyncError> {
        if self.base != base
            || base > MAX_REVISION
            || self.total != total
            || total > MAX_OPERATIONS as usize
            || self.received > total
            || sequences.len() > MAX_PAGE_ITEMS
            || self.after_member > base
        {
            return Err(SyncError::Invalid);
        }
        let mut last = self.after_member;
        for sequence in sequences {
            if *sequence <= last || *sequence > base {
                return Err(SyncError::Invalid);
            }
            last = *sequence;
        }
        let received = self
            .received
            .checked_add(sequences.len())
            .ok_or(SyncError::Invalid)?;
        if next != last
            || received > total
            || more != (received < total)
            || more && sequences.is_empty()
        {
            return Err(SyncError::Invalid);
        }
        Ok(Self {
            base,
            total,
            received,
            after_member: last,
        })
    }
    pub fn complete(self) -> bool {
        self.received == self.total
    }
}
pub fn delta_progress(
    after: u64,
    sequences: &[u64],
    next: u64,
    more: bool,
) -> Result<(), SyncError> {
    if after > MAX_REVISION
        || next > MAX_REVISION
        || sequences.len() > MAX_PAGE_ITEMS
        || more && sequences.is_empty()
    {
        return Err(SyncError::Invalid);
    }
    let mut cursor = after;
    for sequence in sequences {
        cursor = cursor
            .checked_add(1)
            .filter(|n| *n <= MAX_REVISION)
            .ok_or(SyncError::Invalid)?;
        if cursor != *sequence {
            return Err(SyncError::Invalid);
        }
    }
    if cursor != next {
        return Err(SyncError::Invalid);
    }
    Ok(())
}
