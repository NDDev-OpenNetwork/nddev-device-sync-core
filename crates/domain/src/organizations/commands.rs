//! A command's lifetime is bound to its immutable UUIDv7 timestamp. After its
//! receipt expires, reusing the same ID cannot acquire a fresh mutation window.
use super::OrganizationError;

pub const COMMAND_LIFETIME_MS: u64 = 300_000;
pub const MAX_COMMANDS_PER_DEVICE: usize = 128;
pub const MAX_COMMAND_RESULT_BYTES: usize = 4096;
pub const PAGE_SIZE: usize = 50;
pub const MAX_RETAINED_INVITATIONS: usize = 1024;
pub const DELIVERY_LIFETIME_MS: u64 = 300_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandId {
    value: String,
    issued_at_ms: u64,
}
impl CommandId {
    pub fn new(value: String) -> Result<Self, OrganizationError> {
        let id = uuid::Uuid::parse_str(&value).map_err(|_| OrganizationError::InvalidInput)?;
        if id.get_version_num() != 7
            || id.get_variant() != uuid::Variant::RFC4122
            || id.hyphenated().to_string() != value
        {
            return Err(OrganizationError::InvalidInput);
        }
        let (seconds, nanos) = id
            .get_timestamp()
            .ok_or(OrganizationError::InvalidInput)?
            .to_unix();
        let issued_at_ms = seconds
            .checked_mul(1000)
            .and_then(|value| value.checked_add(u64::from(nanos) / 1_000_000))
            .ok_or(OrganizationError::InvalidInput)?;
        Ok(Self {
            value,
            issued_at_ms,
        })
    }
    pub fn as_str(&self) -> &str {
        &self.value
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.issued_at_ms + COMMAND_LIFETIME_MS
    }
    pub fn validate(&self, now: u64) -> Result<(), OrganizationError> {
        if self.issued_at_ms > now.saturating_add(60_000) {
            return Err(OrganizationError::InvalidInput);
        }
        if now >= self.expires_at_ms() {
            return Err(OrganizationError::CommandExpired);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryState {
    Pending,
    Accepted,
    Failed,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_expiry_cannot_be_renewed_after_receipt_cleanup() {
        let command = CommandId::new("0000000f-4240-7000-8000-000000000001".into()).unwrap();
        assert_eq!(command.expires_at_ms(), 1_300_000);
        assert!(command.validate(940_000).is_ok());
        assert_eq!(
            command.validate(939_999),
            Err(OrganizationError::InvalidInput)
        );
        assert!(command.validate(1_299_999).is_ok());
        assert_eq!(
            command.validate(1_300_000),
            Err(OrganizationError::CommandExpired)
        );
        assert_eq!(
            CommandId::new(command.as_str().into())
                .unwrap()
                .validate(1_400_000),
            Err(OrganizationError::CommandExpired)
        );
        for invalid in [
            "0000000f-4240-4000-8000-000000000001",
            "0000000f-4240-7000-0000-000000000001",
            "0000000F-4240-7000-8000-000000000001",
            "0000000f424070008000000000000001",
            "not-an-id",
        ] {
            assert!(CommandId::new(invalid.into()).is_err());
        }
    }
}
