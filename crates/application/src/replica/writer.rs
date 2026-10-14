//! Persisted format facts are metadata, never serialized authorization grants.
use nddev_device_sync_domain::sync::{history::*, *};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterMode {
    V2,
    V3,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedWriter {
    pub mode: WriterMode,
    pub key_id: String,
    pub basis: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriterFacts {
    pub confirmed: Option<ConfirmedWriter>,
    pub legacy_v2_initialized: bool,
}
pub struct LocalWriterContext<'a> {
    /// Current successful protected authorization supplied by the owning adapter.
    pub authorized: bool,
    pub actual_key: &'a str,
    pub cursor: u64,
    pub known_committed: u64,
}

pub fn confirm_writer_facts(
    old: &WriterFacts,
    mode: WriterMode,
    actual_key: &str,
    observed_basis: u64,
) -> Result<ConfirmedWriter, SyncError> {
    if actual_key.is_empty() || observed_basis > MAX_REVISION {
        return Err(SyncError::Invalid);
    }
    let basis = if let Some(previous) = &old.confirmed {
        if previous.key_id != actual_key {
            return Err(SyncError::KeyConflict);
        }
        if previous.mode == WriterMode::V3 && mode != WriterMode::V3 {
            return Err(SyncError::Invalid);
        }
        if previous.basis > MAX_REVISION {
            return Err(SyncError::Invalid);
        }
        previous.basis.max(observed_basis)
    } else {
        observed_basis
    };
    Ok(ConfirmedWriter {
        mode,
        key_id: actual_key.into(),
        basis,
    })
}

/// Prepare a NEW never-dispatched operation before existing canonical AEAD.
/// Pending/Unknown requests never enter this function and retain original bytes.
pub fn prepare_offline_operation(
    operation: Operation,
    lifecycle: Lifecycle,
    facts: &WriterFacts,
    current: LocalWriterContext<'_>,
) -> Result<VersionedOperation, SyncError> {
    if !current.authorized {
        return Err(SyncError::Denied);
    }
    if current.actual_key.is_empty() {
        return Err(SyncError::KeyRegistration);
    }
    if operation.payload.key_id != current.actual_key {
        return Err(SyncError::KeyConflict);
    }
    if current.cursor > MAX_REVISION || current.known_committed > MAX_REVISION {
        return Err(SyncError::Invalid);
    }
    let mode = match &facts.confirmed {
        Some(context) => {
            if context.key_id != current.actual_key {
                return Err(SyncError::KeyConflict);
            }
            if context.basis > MAX_REVISION {
                return Err(SyncError::Invalid);
            }
            context.mode
        }
        None if facts.legacy_v2_initialized => WriterMode::V2,
        None => return Err(SyncError::KeyRegistration),
    };
    match mode {
        WriterMode::V2 => {
            if lifecycle.resolved_through_seq != 0 {
                return Err(SyncError::Invalid);
            }
            let value = VersionedOperation {
                operation,
                version: OperationVersion::V2,
            };
            value.validate_header()?;
            Ok(value)
        }
        WriterMode::V3 => {
            let confirmed = facts.confirmed.as_ref().ok_or(SyncError::Invalid)?;
            let basis = confirmed
                .basis
                .max(current.cursor)
                .max(current.known_committed);
            VersionedOperation::qualify(operation, basis, lifecycle)
        }
    }
}
