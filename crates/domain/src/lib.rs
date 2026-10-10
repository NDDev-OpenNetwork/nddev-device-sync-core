//! Pure domain model for nddev-device-sync.
//!
//! This crate intentionally contains no filesystem, process, network, UI, or
//! credential-store code. That boundary keeps the core portable and makes the
//! safety rules testable on every supported operating system.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                let value = value.into();
                if !valid_identifier(&value) {
                    return Err(DomainError::InvalidIdentifier);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

id_type!(ModuleId);
id_type!(HarnessId);
id_type!(AccountId);
id_type!(UserId);
id_type!(TenantId);
id_type!(DeviceId);

pub mod devices;
pub mod identity;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Macos,
    Linux,
    Windows,
}

impl Platform {
    pub const ALL: [Self; 3] = [Self::Macos, Self::Linux, Self::Windows];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    Gds,
    Rds,
    Tool,
    Accounts,
    Integration,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCapability {
    ReadDeviceState,
    ManageDeviceState,
    RunExistingTool,
    ManageHarnessAccounts,
    SwitchHarnessAccount,
    ReadModuleHealth,
    ApplyUpdates,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    ReadOnly,
    CredentialStore,
    ProcessExecution,
    LocalNetwork,
    UserService,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleDependency {
    pub id: ModuleId,
    pub minimum_api: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModuleDescriptor {
    pub id: ModuleId,
    pub version: String,
    pub api_version: u16,
    pub kind: ModuleKind,
    pub platforms: BTreeSet<Platform>,
    pub capabilities: BTreeSet<ModuleCapability>,
    pub permissions: BTreeSet<Permission>,
    pub dependencies: Vec<ModuleDependency>,
}

impl ModuleDescriptor {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.version.trim().is_empty() || self.api_version == 0 || self.platforms.is_empty() {
            return Err(DomainError::InvalidModuleDescriptor);
        }
        let mut ids = BTreeSet::new();
        for dependency in &self.dependencies {
            if dependency.id == self.id || !ids.insert(dependency.id.clone()) {
                return Err(DomainError::InvalidModuleDescriptor);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum DomainError {
    #[error("identifier must be 1..128 ASCII letters, digits, '.', '_', ':', or '-'")]
    InvalidIdentifier,
    #[error("module descriptor is invalid")]
    InvalidModuleDescriptor,
    #[error("module is already registered")]
    DuplicateModule,
    #[error("module dependency is missing")]
    MissingDependency,
    #[error("module dependency graph contains a cycle")]
    DependencyCycle,
    #[error("module is not registered")]
    UnknownModule,
    #[error("account belongs to another harness")]
    WrongHarness,
    #[error("official account switching is not supported by this harness")]
    SwitchingNotSupported,
}

#[derive(Clone, Debug, Default)]
pub struct ModuleGraph {
    modules: BTreeMap<ModuleId, ModuleDescriptor>,
}

impl ModuleGraph {
    pub fn register(&mut self, descriptor: ModuleDescriptor) -> Result<(), DomainError> {
        descriptor.validate()?;
        if self.modules.contains_key(&descriptor.id) {
            return Err(DomainError::DuplicateModule);
        }
        self.modules.insert(descriptor.id.clone(), descriptor);
        Ok(())
    }

    pub fn get(&self, id: &ModuleId) -> Option<&ModuleDescriptor> {
        self.modules.get(id)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ModuleDescriptor> {
        self.modules.values()
    }

    pub fn activation_order(&self) -> Result<Vec<ModuleId>, DomainError> {
        self.validate()?;
        let mut visited = BTreeSet::new();
        let mut active = BTreeSet::new();
        let mut result = Vec::with_capacity(self.modules.len());
        for id in self.modules.keys() {
            self.visit(id, &mut visited, &mut active, &mut result)?;
        }
        Ok(result)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        for descriptor in self.modules.values() {
            for dependency in &descriptor.dependencies {
                let Some(found) = self.modules.get(&dependency.id) else {
                    return Err(DomainError::MissingDependency);
                };
                if found.api_version < dependency.minimum_api {
                    return Err(DomainError::MissingDependency);
                }
            }
        }
        let _ = self.activation_order_inner()?;
        Ok(())
    }

    fn activation_order_inner(&self) -> Result<Vec<ModuleId>, DomainError> {
        let mut visited = BTreeSet::new();
        let mut active = BTreeSet::new();
        let mut result = Vec::with_capacity(self.modules.len());
        for id in self.modules.keys() {
            self.visit(id, &mut visited, &mut active, &mut result)?;
        }
        Ok(result)
    }

    fn visit(
        &self,
        id: &ModuleId,
        visited: &mut BTreeSet<ModuleId>,
        active: &mut BTreeSet<ModuleId>,
        result: &mut Vec<ModuleId>,
    ) -> Result<(), DomainError> {
        if visited.contains(id) {
            return Ok(());
        }
        if !active.insert(id.clone()) {
            return Err(DomainError::DependencyCycle);
        }
        let descriptor = self.modules.get(id).ok_or(DomainError::UnknownModule)?;
        for dependency in &descriptor.dependencies {
            self.visit(&dependency.id, visited, active, result)?;
        }
        active.remove(id);
        visited.insert(id.clone());
        result.push(id.clone());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    PendingAuthorization,
    Authorized,
    Active,
    Inactive,
    Revoked,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchSupport {
    Official,
    Unsupported,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HarnessDescriptor {
    pub id: HarnessId,
    pub display_name: String,
    pub switch_support: SwitchSupport,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountRecord {
    pub id: AccountId,
    pub harness_id: HarnessId,
    pub label: String,
    pub username_hint: Option<String>,
    pub status: AccountStatus,
    pub switch_support: SwitchSupport,
    pub created_at_ms: u64,
    pub last_used_at_ms: Option<u64>,
}

impl AccountRecord {
    pub fn new(
        id: AccountId,
        harness_id: HarnessId,
        label: impl Into<String>,
        username_hint: Option<String>,
        now_ms: u64,
        switch_support: SwitchSupport,
    ) -> Self {
        Self {
            id,
            harness_id,
            label: label.into(),
            username_hint,
            status: AccountStatus::Authorized,
            switch_support,
            created_at_ms: now_ms,
            last_used_at_ms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_deserialization_enforces_the_constructor_contract() {
        use serde::de::value::{Error, StrDeserializer};

        for value in [
            "",
            " ",
            "a/b",
            "a b",
            " a",
            "a\n",
            "\0",
            "é",
            &"a".repeat(129),
        ] {
            assert!(ModuleId::new(value).is_err());
            assert!(HarnessId::new(value).is_err());
            assert!(AccountId::new(value).is_err());
            assert!(ModuleId::deserialize(StrDeserializer::<Error>::new(value)).is_err());
            assert!(HarnessId::deserialize(StrDeserializer::<Error>::new(value)).is_err());
            assert!(AccountId::deserialize(StrDeserializer::<Error>::new(value)).is_err());
        }
        for value in ["a", "AZ09-_.:", &"a".repeat(128)] {
            assert_eq!(
                ModuleId::deserialize(StrDeserializer::<Error>::new(value)).unwrap(),
                ModuleId::new(value).unwrap()
            );
            assert_eq!(
                HarnessId::deserialize(StrDeserializer::<Error>::new(value)).unwrap(),
                HarnessId::new(value).unwrap()
            );
            assert_eq!(
                AccountId::deserialize(StrDeserializer::<Error>::new(value)).unwrap(),
                AccountId::new(value).unwrap()
            );
        }
    }

    fn descriptor(id: &str, dependencies: Vec<ModuleDependency>) -> ModuleDescriptor {
        ModuleDescriptor {
            id: ModuleId::new(id).unwrap(),
            version: "0.1.0".into(),
            api_version: 1,
            kind: ModuleKind::Tool,
            platforms: Platform::ALL.into_iter().collect(),
            capabilities: BTreeSet::from([ModuleCapability::ReadModuleHealth]),
            permissions: BTreeSet::from([Permission::ReadOnly]),
            dependencies,
        }
    }

    #[test]
    fn graph_orders_dependencies_before_dependants() {
        let base = ModuleId::new("base").unwrap();
        let mut graph = ModuleGraph::default();
        graph
            .register(descriptor(
                "app",
                vec![ModuleDependency {
                    id: base,
                    minimum_api: 1,
                }],
            ))
            .unwrap();
        graph.register(descriptor("base", vec![])).unwrap();
        let order = graph.activation_order().unwrap();
        assert_eq!(
            order,
            vec![
                ModuleId::new("base").unwrap(),
                ModuleId::new("app").unwrap()
            ]
        );
    }

    #[test]
    fn graph_rejects_missing_dependencies_and_leaves_previous_state() {
        let b = ModuleId::new("b").unwrap();
        let mut graph = ModuleGraph::default();
        graph
            .register(descriptor(
                "b",
                vec![ModuleDependency {
                    id: ModuleId::new("missing").unwrap(),
                    minimum_api: 1,
                }],
            ))
            .unwrap();
        let error = graph.activation_order().unwrap_err();
        assert_eq!(error, DomainError::MissingDependency);
        assert!(graph.get(&b).is_some());
    }

    #[test]
    fn graph_rejects_cycles() {
        let a = ModuleId::new("a").unwrap();
        let b = ModuleId::new("b").unwrap();
        let mut graph = ModuleGraph {
            modules: BTreeMap::new(),
        };
        graph.modules.insert(
            a.clone(),
            descriptor(
                "a",
                vec![ModuleDependency {
                    id: b.clone(),
                    minimum_api: 1,
                }],
            ),
        );
        graph.modules.insert(
            b,
            descriptor(
                "b",
                vec![ModuleDependency {
                    id: a,
                    minimum_api: 1,
                }],
            ),
        );
        assert_eq!(
            graph.activation_order().unwrap_err(),
            DomainError::DependencyCycle
        );
    }
}
