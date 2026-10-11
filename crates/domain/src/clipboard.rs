//! Canonical encrypted text payload. Native clipboard adapters own MIME/privacy
//! admission; committed server sequence, never a device clock, orders items.
use crate::sync::SyncError;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAX_TEXT_BYTES: usize = 8192;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Text {
    pub schema_version: u16,
    pub text: Zeroizing<String>,
}
impl Text {
    pub fn new(text: Zeroizing<String>) -> Result<Self, SyncError> {
        let value = Self {
            schema_version: 1,
            text,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), SyncError> {
        if self.schema_version != 1 || self.text.len() > MAX_TEXT_BYTES || self.text.contains('\0')
        {
            return Err(SyncError::Invalid);
        }
        Ok(())
    }
}
