//! Operational key material; no encryption, randomness, storage or transport.
use crate::sync::SyncError;
use zeroize::Zeroizing;

pub struct KeyMaterial(Zeroizing<[u8; 48]>);

impl KeyMaterial {
    pub fn new(bytes: &[u8]) -> Result<Self, SyncError> {
        let bytes: [u8; 48] = bytes.try_into().map_err(|_| SyncError::Invalid)?;
        if uuid::Uuid::from_slice(&bytes[..16])
            .map_err(|_| SyncError::Invalid)?
            .is_nil()
        {
            return Err(SyncError::Invalid);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn id(&self) -> String {
        // Construction checked this fixed-length public identifier.
        uuid::Uuid::from_slice(&self.0[..16])
            .expect("validated UUID")
            .to_string()
    }

    /// Only authenticated native adapters consume this material. Never expose
    /// it through a presentation bridge, metadata store or diagnostic event.
    pub fn expose(&self) -> &[u8; 48] {
        &self.0
    }
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeyMaterial([REDACTED])")
    }
}

/// Versioned encrypted record payload. Resolution is an explicit owner decision
/// over observed committed history, never an automatic last-write-wins rule.
/// Version 1 remains readable for retained ciphertext; only a version 2 record
/// can carry a resolution watermark. Native adapters own AEAD and durability.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: u8,
    pub deleted: bool,
    pub title: String,
    pub username: String,
    pub secret: Zeroizing<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub resolved_through_seq: u64,
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}
impl Record {
    pub fn validate(&self) -> Result<(), SyncError> {
        if !matches!(self.version, 1 | 2)
            || self.version == 1 && self.resolved_through_seq != 0
            || self.resolved_through_seq > crate::sync::MAX_REVISION
            || self.title.trim().is_empty()
            || self.title.chars().count() > 128
            || self.username.len() > 254
            || self.secret.len() > crate::sync::MAX_PLAIN_BYTES
            || self.deleted && !self.secret.is_empty()
        {
            return Err(SyncError::Invalid);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_records_and_explicit_resolution_have_distinct_versioned_bounds() {
        let mut record = Record {
            version: 1,
            deleted: false,
            title: "Owned record".into(),
            username: String::new(),
            secret: Zeroizing::new("secret".into()),
            resolved_through_seq: 0,
        };
        assert!(record.validate().is_ok());
        record.resolved_through_seq = 1;
        assert!(record.validate().is_err());
        record.version = 2;
        assert!(record.validate().is_ok());
        record.resolved_through_seq = crate::sync::MAX_REVISION + 1;
        assert!(record.validate().is_err());
        record.resolved_through_seq = 1;
        record.deleted = true;
        assert!(record.validate().is_err());
        record.secret.clear();
        assert!(record.validate().is_ok());
    }
}
