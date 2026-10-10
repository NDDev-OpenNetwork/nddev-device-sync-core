//! Pure operation validation and revision/conflict decisions. Storage commits
//! authorization, entity state, log position and the original result atomically.
use crate::{DeviceId, valid_identifier};

pub const MAX_REVISION: u64 = 9_007_199_254_740_991;
pub const MAX_OPERATION_BYTES: usize = 24 * 1024;
pub const MAX_PLAIN_BYTES: usize = 16 * 1024;
pub const MAX_OPERATIONS: u64 = 16_384;
pub const MAX_STORED_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_ENTITY_COUNT: u64 = 4096;
pub const MAX_PAGE_ITEMS: usize = 2;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum EntityKind {
    DeviceState,
    ModuleState,
    VaultRecord,
    AccountState,
    ClipboardItem,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn operation() -> Operation {
        Operation {
            id: "operation".into(),
            device: DeviceId::new("device").unwrap(),
            entity_kind: EntityKind::DeviceState,
            entity_id: "device".into(),
            base_revision: 0,
            idempotency_key: "operation".into(),
            payload: EncryptedPayload {
                key_id: "key".into(),
                nonce: [0; 12],
                ciphertext: vec![0; 16],
            },
        }
    }
    #[test]
    fn conflict_retains_both_revisions_and_never_silently_overwrites() {
        let mut operation = operation();
        assert!(matches!(
            operation.decide(0),
            Ok(Decision::Apply { revision: 1 })
        ));
        assert!(matches!(
            operation.decide(7),
            Ok(Decision::Conflict {
                base_revision: 0,
                current_revision: 7
            })
        ));
        operation.base_revision = MAX_REVISION;
        assert_eq!(
            operation.decide(MAX_REVISION).err(),
            Some(SyncError::Revision)
        );
    }
    #[test]
    fn encrypted_operations_have_bounded_payloads_and_device_owned_state() {
        let mut operation = operation();
        assert!(operation.validate(MAX_OPERATION_BYTES).is_ok());
        assert_eq!(
            operation.validate(MAX_OPERATION_BYTES + 1),
            Err(SyncError::Invalid)
        );
        operation.entity_id = "another-device:module".into();
        assert_eq!(operation.validate(100), Err(SyncError::Denied));
        operation.entity_kind = EntityKind::VaultRecord;
        assert!(operation.validate(100).is_ok());
        operation.payload.ciphertext.resize(MAX_PLAIN_BYTES + 17, 0);
        assert_eq!(operation.validate(100), Err(SyncError::Invalid));
    }
}
impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeviceState => "device_state",
            Self::ModuleState => "module_state",
            Self::VaultRecord => "vault_record",
            Self::AccountState => "account_state",
            Self::ClipboardItem => "clipboard_item",
        }
    }
}
#[derive(Clone)]
pub struct EncryptedPayload {
    pub key_id: String,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}
#[derive(Clone)]
pub struct Operation {
    pub id: String,
    pub device: DeviceId,
    pub entity_kind: EntityKind,
    pub entity_id: String,
    pub base_revision: u64,
    pub idempotency_key: String,
    pub payload: EncryptedPayload,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    #[error("invalid_request")]
    Invalid,
    #[error("device_revoked")]
    Revoked,
    #[error("authentication_failed")]
    Denied,
    #[error("invalid_signature")]
    Signature,
    #[error("replayed_nonce")]
    Nonce,
    #[error("idempotency_conflict")]
    Idempotency,
    #[error("operation_conflict")]
    KeyConflict,
    #[error("revision_exhausted")]
    Revision,
    #[error("server_busy")]
    Capacity,
    #[error("dependency_unavailable")]
    Unavailable,
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Decision {
    Apply {
        revision: u64,
    },
    Conflict {
        base_revision: u64,
        current_revision: u64,
    },
}
fn long_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}
impl Operation {
    pub fn validate(&self, bytes: usize) -> Result<(), SyncError> {
        if !valid_identifier(&self.id)
            || !long_id(&self.entity_id)
            || !long_id(&self.idempotency_key)
            || !valid_identifier(&self.payload.key_id)
            || self.base_revision > MAX_REVISION
            || bytes > MAX_OPERATION_BYTES
            || !(16..=MAX_PLAIN_BYTES + 16).contains(&self.payload.ciphertext.len())
        {
            return Err(SyncError::Invalid);
        }
        // A device cannot impersonate another installation's device/module state.
        if matches!(
            self.entity_kind,
            EntityKind::DeviceState | EntityKind::ModuleState
        ) && !(self.entity_id == self.device.as_str()
            || self
                .entity_id
                .starts_with(&format!("{}:", self.device.as_str())))
        {
            return Err(SyncError::Denied);
        }
        Ok(())
    }
    pub fn decide(&self, current_revision: u64) -> Result<Decision, SyncError> {
        if current_revision > MAX_REVISION {
            return Err(SyncError::Revision);
        }
        if current_revision != self.base_revision {
            Ok(Decision::Conflict {
                base_revision: self.base_revision,
                current_revision,
            })
        } else {
            Ok(Decision::Apply {
                revision: current_revision
                    .checked_add(1)
                    .filter(|value| *value <= MAX_REVISION)
                    .ok_or(SyncError::Revision)?,
            })
        }
    }
}
