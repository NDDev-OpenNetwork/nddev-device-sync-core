//! Portable encrypted device/module/account read models. Values are observations
//! by a signing device, never an instruction to mutate a provider's own state.
use crate::{
    DeviceId, ModuleId,
    devices::DeviceName,
    sync::{EntityKind, MAX_REVISION, SyncError},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema_version: u16,
    pub observed_at_ms: u64,
    pub data: State,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum State {
    Device {
        display_name: String,
        platform: String,
        client_version: String,
    },
    Module {
        module_id: String,
        version: String,
        configured: bool,
        reachability: Reachability,
        checked_at_ms: Option<u64>,
        error_class: Option<String>,
    },
    Account {
        auth_method: String,
        checked_at_ms: u64,
        expires_at_ms: u64,
    },
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Reachability {
    NotChecked,
    Reachable,
    Unavailable,
    Failed,
}

fn version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}
impl Snapshot {
    /// Match the encrypted payload to its signed writer/kind/entity and reject
    /// impossible freshness or health claims before displaying remote state.
    pub fn validate(
        &self,
        writer: &DeviceId,
        kind: EntityKind,
        entity: &str,
    ) -> Result<(), SyncError> {
        if !crate::valid_identifier(entity)
            || self.schema_version != 1
            || self.observed_at_ms == 0
            || self.observed_at_ms > MAX_REVISION
        {
            return Err(SyncError::Invalid);
        }
        let valid = match (&self.data, kind) {
            (
                State::Device {
                    display_name,
                    platform,
                    client_version,
                },
                EntityKind::DeviceState,
            ) => {
                entity == writer.as_str()
                    && DeviceName::new(display_name.clone()).is_ok()
                    && matches!(
                        platform.as_str(),
                        "linux" | "macos" | "windows" | "android" | "ios"
                    )
                    && (client_version.is_empty() || version(client_version))
            }
            (
                State::Module {
                    module_id,
                    version: release,
                    configured,
                    reachability,
                    checked_at_ms,
                    error_class,
                },
                EntityKind::ModuleState,
            ) => {
                ModuleId::new(module_id.clone()).is_ok()
                    && version(release)
                    && entity == format!("{}:{module_id}", writer.as_str())
                    && checked_at_ms.is_none_or(|time| time > 0 && time <= self.observed_at_ms)
                    && error_class.as_ref().is_none_or(|error| {
                        matches!(
                            error.as_str(),
                            "provider_unavailable"
                                | "provider_failed"
                                | "operation_timeout"
                                | "invalid_response"
                        )
                    })
                    && match reachability {
                        Reachability::NotChecked => {
                            checked_at_ms.is_none() && error_class.is_none()
                        }
                        Reachability::Reachable => {
                            *configured && checked_at_ms.is_some() && error_class.is_none()
                        }
                        Reachability::Unavailable | Reachability::Failed => {
                            *configured && checked_at_ms.is_some() && error_class.is_some()
                        }
                    }
            }
            (
                State::Account {
                    auth_method,
                    checked_at_ms,
                    expires_at_ms,
                },
                EntityKind::AccountState,
            ) => {
                entity == format!("{}:nds", writer.as_str())
                    && matches!(auth_method.as_str(), "email_otp" | "github" | "passkey")
                    && *checked_at_ms > 0
                    && *checked_at_ms <= self.observed_at_ms
                    && *expires_at_ms > *checked_at_ms
                    && *expires_at_ms <= MAX_REVISION
            }
            _ => false,
        };
        if valid {
            Ok(())
        } else {
            Err(SyncError::Invalid)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_state_cannot_claim_another_writer_or_unobserved_provider_success() {
        let writer = DeviceId::new("device").unwrap();
        let mut value = Snapshot {
            schema_version: 1,
            observed_at_ms: 100,
            data: State::Module {
                module_id: "gds".into(),
                version: "0.0.1-alpha.1".into(),
                configured: false,
                reachability: Reachability::NotChecked,
                checked_at_ms: None,
                error_class: None,
            },
        };
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "device:gds")
                .is_ok()
        );
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "other:gds")
                .is_err()
        );
        assert!(
            value
                .validate(&writer, EntityKind::DeviceState, "device")
                .is_err()
        );
        if let State::Module { reachability, .. } = &mut value.data {
            *reachability = Reachability::Reachable;
        }
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "device:gds")
                .is_err()
        );
        if let State::Module {
            configured,
            checked_at_ms,
            ..
        } = &mut value.data
        {
            *configured = true;
            *checked_at_ms = Some(101);
        }
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "device:gds")
                .is_err()
        );
        if let State::Module { checked_at_ms, .. } = &mut value.data {
            *checked_at_ms = Some(99);
        }
        assert!(
            value
                .validate(&writer, EntityKind::ModuleState, "device:gds")
                .is_ok()
        );
    }
}
