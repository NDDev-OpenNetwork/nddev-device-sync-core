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
