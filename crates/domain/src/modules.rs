//! Shared native-query outcomes and observations; no provider I/O or logging.
use crate::{
    state::{Reachability, State},
    sync::MAX_REVISION,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ModuleError {
    #[error("unsupported_platform")]
    UnsupportedPlatform,
    #[error("provider_unavailable")]
    Unavailable,
    #[error("operation_busy")]
    Busy,
    #[error("invalid_input")]
    InvalidInput,
    #[error("operation_timeout")]
    Timeout,
    #[error("operation_cancelled")]
    Cancelled,
    #[error("provider_failed")]
    ProviderFailed,
    #[error("invalid_response")]
    InvalidResponse,
    #[error("invalid_module_contract")]
    InvalidContract,
}

/// This describes the query result, not the workflow contained in its response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleOutcome {
    Completed,
    NotAdmitted,
    Cancelled,
    Failed,
}
impl ModuleOutcome {
    pub fn terminal_failure(self) -> bool {
        self == Self::Failed
    }
}

pub fn query_outcome<T>(result: &Result<T, ModuleError>) -> ModuleOutcome {
    match result {
        Ok(_) => ModuleOutcome::Completed,
        Err(ModuleError::Cancelled) => ModuleOutcome::Cancelled,
        Err(
            ModuleError::Busy
            | ModuleError::InvalidInput
            | ModuleError::UnsupportedPlatform
            | ModuleError::InvalidContract,
        ) => ModuleOutcome::NotAdmitted,
        Err(
            ModuleError::Unavailable
            | ModuleError::Timeout
            | ModuleError::ProviderFailed
            | ModuleError::InvalidResponse,
        ) => ModuleOutcome::Failed,
    }
}

/// Last actual native query, separate from remote connection/workflow success.
/// Registration supplies the validated module ID/version from ModuleDescriptor.
#[derive(Clone)]
pub struct ModuleObservation {
    pub id: String,
    pub version: String,
    pub configured: bool,
    pub reachability: Reachability,
    pub observed_at_ms: Option<u64>,
    pub error: Option<ModuleError>,
}
impl ModuleObservation {
    /// Admission/cancellation and cached absence cannot refresh provider state.
    /// Invalid/missing clock evidence preserves the previous observation.
    pub fn observe<T>(&mut self, result: &Result<T, ModuleError>, observed_at_ms: Option<u64>) {
        if !self.configured
            || matches!(
                query_outcome(result),
                ModuleOutcome::NotAdmitted | ModuleOutcome::Cancelled
            )
        {
            return;
        }
        let Some(time) = observed_at_ms.filter(|time| *time > 0 && *time <= MAX_REVISION) else {
            return;
        };
        if self.observed_at_ms.is_some_and(|previous| time < previous) {
            return;
        }
        self.observed_at_ms = Some(time);
        self.error = result.as_ref().err().copied();
        self.reachability = match result {
            Ok(_) => Reachability::Reachable,
            Err(ModuleError::Unavailable) => Reachability::Unavailable,
            Err(_) => Reachability::Failed,
        };
    }
    /// One projection into the existing encrypted sync state contract.
    pub fn state(&self) -> State {
        State::Module {
            module_id: self.id.clone(),
            version: self.version.clone(),
            configured: self.configured,
            reachability: self.reachability,
            checked_at_ms: self.observed_at_ms,
            error_class: self.error.map(|error| error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn initial() -> ModuleObservation {
        ModuleObservation {
            id: "gds".into(),
            version: "0.0.1-alpha.1".into(),
            configured: true,
            reachability: Reachability::NotChecked,
            observed_at_ms: None,
            error: None,
        }
    }
    #[test]
    fn query_policy_distinguishes_admission_cancellation_and_terminal_failure() {
        for error in [
            ModuleError::Unavailable,
            ModuleError::Timeout,
            ModuleError::ProviderFailed,
            ModuleError::InvalidResponse,
        ] {
            assert!(query_outcome(&Err::<(), _>(error)).terminal_failure());
        }
        for error in [
            ModuleError::Busy,
            ModuleError::InvalidInput,
            ModuleError::UnsupportedPlatform,
            ModuleError::InvalidContract,
            ModuleError::Cancelled,
        ] {
            assert!(!query_outcome(&Err::<(), _>(error)).terminal_failure());
        }
        // A valid response can describe not-proven/partial provider workflow state.
        assert_eq!(
            query_outcome(&Ok::<_, ModuleError>("not-proven")),
            ModuleOutcome::Completed
        );
    }
    #[test]
    fn only_actual_timed_provider_results_change_observation() {
        let mut value = initial();
        value.observe(&Ok::<_, ModuleError>(()), None);
        assert!(value.observed_at_ms.is_none());
        value.observe(&Ok::<_, ModuleError>(()), Some(100));
        for error in [
            ModuleError::Busy,
            ModuleError::InvalidInput,
            ModuleError::Cancelled,
            ModuleError::UnsupportedPlatform,
            ModuleError::InvalidContract,
        ] {
            value.observe(&Err::<(), _>(error), Some(200));
            assert_eq!(value.observed_at_ms, Some(100));
            assert!(value.error.is_none() && value.reachability == Reachability::Reachable);
        }
        value.observe(&Err::<(), _>(ModuleError::Timeout), Some(99));
        assert_eq!(value.observed_at_ms, Some(100));
        value.observe(&Err::<(), _>(ModuleError::Timeout), Some(200));
        assert!(
            value.reachability == Reachability::Failed && value.error == Some(ModuleError::Timeout)
        );
        let snapshot = crate::state::Snapshot {
            schema_version: 1,
            observed_at_ms: 200,
            data: value.state(),
        };
        assert!(
            snapshot
                .validate(
                    &crate::DeviceId::new("device").unwrap(),
                    crate::sync::EntityKind::ModuleState,
                    "device:gds"
                )
                .is_ok()
        );
        let mut unavailable = initial();
        unavailable.configured = false;
        unavailable.observe(&Err::<(), _>(ModuleError::Unavailable), Some(200));
        assert!(unavailable.observed_at_ms.is_none() && unavailable.error.is_none());
    }
}
