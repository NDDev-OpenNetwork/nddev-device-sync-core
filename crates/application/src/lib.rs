//! Use cases and ports. Adapters implement these traits; the application core
//! never reaches into an OS API, a harness config file, or a credential store.

use nddev_device_sync_domain::{
    AccountId, AccountRecord, AccountStatus, DomainError, HarnessId, ModuleCapability,
    ModuleDescriptor, ModuleGraph, ModuleId, ModuleKind, Permission, Platform, SwitchSupport,
};
use std::collections::BTreeSet;
use thiserror::Error;

pub const ACCOUNT_SECRET_SERVICE: &str = "com.nddev.device-sync.account";

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ApplicationError {
    #[error(transparent)]
    Domain(#[from] DomainError),
    #[error("account store error: {0}")]
    AccountStore(String),
    #[error("secret store error: {0}")]
    SecretStore(String),
    #[error("harness error: {0}")]
    Harness(String),
    #[error("account does not exist")]
    UnknownAccount,
    #[error("account is not authorized")]
    AccountNotAuthorized,
    #[error("secret write failed and pending account cleanup failed")]
    AccountCleanupFailed,
}

/// Mutations are atomic: an error leaves the existing records unchanged.
pub trait AccountStore {
    /// Reserve an ID; duplicates must fail without replacing the existing record.
    fn insert(&mut self, record: AccountRecord) -> Result<(), String>;
    /// Complete only a pending authorization after its secret has been persisted.
    fn mark_authorized(&mut self, id: &AccountId) -> Result<(), String>;
    fn remove(&mut self, id: &AccountId) -> Result<(), String>;
    fn get(&self, id: &AccountId) -> Result<Option<AccountRecord>, String>;
    fn list(&self, harness_id: &HarnessId) -> Result<Vec<AccountRecord>, String>;
    fn mark_active(
        &mut self,
        harness_id: &HarnessId,
        id: &AccountId,
        now_ms: u64,
    ) -> Result<(), String>;
}

pub trait SecretStore {
    fn put(&mut self, service: &str, key: &str, secret: &[u8]) -> Result<(), String>;
    fn get(&self, service: &str, key: &str) -> Result<Vec<u8>, String>;
    fn delete(&mut self, service: &str, key: &str) -> Result<(), String>;
}

pub trait HarnessAccountPort {
    fn harness_id(&self) -> &HarnessId;
    fn switch_support(&self) -> SwitchSupport;
    fn activate(&self, account: &AccountRecord, secret: &[u8]) -> Result<(), String>;
}

pub struct AccountService<A, S> {
    accounts: A,
    secrets: S,
}

impl<A, S> AccountService<A, S>
where
    A: AccountStore,
    S: SecretStore,
{
    pub fn new(accounts: A, secrets: S) -> Self {
        Self { accounts, secrets }
    }

    pub fn into_parts(self) -> (A, S) {
        (self.accounts, self.secrets)
    }

    pub fn list(&self, harness_id: &HarnessId) -> Result<Vec<AccountRecord>, ApplicationError> {
        self.accounts
            .list(harness_id)
            .map_err(ApplicationError::AccountStore)
    }

    pub fn add_authorized(
        &mut self,
        mut record: AccountRecord,
        secret: &[u8],
    ) -> Result<AccountId, ApplicationError> {
        let id = record.id.clone();
        let key = secret_key(&record.harness_id, &record.id);
        record.status = AccountStatus::PendingAuthorization;
        self.accounts
            .insert(record)
            .map_err(ApplicationError::AccountStore)?;
        if let Err(error) = self.secrets.put(ACCOUNT_SECRET_SERVICE, &key, secret) {
            self.accounts
                .remove(&id)
                .map_err(|_| ApplicationError::AccountCleanupFailed)?;
            return Err(ApplicationError::SecretStore(error));
        }
        // A failed finalization leaves a pending record, never a usable account.
        // Do not delete a secret after an uncertain write or metadata failure.
        self.accounts
            .mark_authorized(&id)
            .map_err(ApplicationError::AccountStore)?;
        Ok(id)
    }

    pub fn activate<P: HarnessAccountPort>(
        &mut self,
        account_id: &AccountId,
        now_ms: u64,
        port: &P,
    ) -> Result<(), ApplicationError> {
        if port.switch_support() != SwitchSupport::Official {
            return Err(ApplicationError::Domain(DomainError::SwitchingNotSupported));
        }
        let record = self
            .accounts
            .get(account_id)
            .map_err(ApplicationError::AccountStore)?
            .ok_or(ApplicationError::UnknownAccount)?;
        if record.harness_id != *port.harness_id() {
            return Err(ApplicationError::Domain(DomainError::WrongHarness));
        }
        if !matches!(
            record.status,
            AccountStatus::Authorized | AccountStatus::Active | AccountStatus::Inactive
        ) {
            return Err(ApplicationError::AccountNotAuthorized);
        }
        let key = secret_key(&record.harness_id, &record.id);
        let secret = self
            .secrets
            .get(ACCOUNT_SECRET_SERVICE, &key)
            .map_err(ApplicationError::SecretStore)?;
        port.activate(&record, &secret)
            .map_err(ApplicationError::Harness)?;
        self.accounts
            .mark_active(port.harness_id(), account_id, now_ms)
            .map_err(ApplicationError::AccountStore)
    }
}

fn secret_key(harness_id: &HarnessId, account_id: &AccountId) -> String {
    // IDs exclude '/', so this existing native key format is unambiguous.
    // Keep it unchanged: no credential rename, fallback lookup or copying.
    format!("{}/{}", harness_id.as_str(), account_id.as_str())
}

pub fn builtin_modules() -> Vec<ModuleDescriptor> {
    [
        ("gds", ModuleKind::Gds, [ModuleCapability::ReadModuleHealth]),
        ("rds", ModuleKind::Rds, [ModuleCapability::ReadModuleHealth]),
        (
            "sysinfo",
            ModuleKind::Tool,
            [ModuleCapability::ReadDeviceState],
        ),
        (
            "clipboard",
            ModuleKind::Tool,
            [ModuleCapability::RunExistingTool],
        ),
        (
            "cleaner",
            ModuleKind::Tool,
            [ModuleCapability::RunExistingTool],
        ),
        (
            "updater",
            ModuleKind::Tool,
            [ModuleCapability::ApplyUpdates],
        ),
        (
            "accounts",
            ModuleKind::Accounts,
            [ModuleCapability::ManageHarnessAccounts],
        ),
    ]
    .into_iter()
    .map(|(id, kind, capabilities)| ModuleDescriptor {
        id: ModuleId::new(id).expect("static module id"),
        version: "0.1.0".into(),
        api_version: 1,
        kind,
        platforms: Platform::ALL.into_iter().collect(),
        capabilities: capabilities.into_iter().collect(),
        permissions: if kind == ModuleKind::Accounts {
            BTreeSet::from([Permission::CredentialStore, Permission::ReadOnly])
        } else {
            BTreeSet::from([Permission::ReadOnly])
        },
        dependencies: Vec::new(),
    })
    .collect()
}

pub fn builtin_graph() -> Result<ModuleGraph, DomainError> {
    let mut graph = ModuleGraph::default();
    for module in builtin_modules() {
        graph.register(module)?;
    }
    Ok(graph)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_key_names_preserve_existing_valid_identifiers() {
        let harness = HarnessId::new("codex").unwrap();
        let account = AccountId::new("personal").unwrap();
        assert_eq!(secret_key(&harness, &account), "codex/personal");
        assert!(HarnessId::new("a/b").is_err());
        assert!(AccountId::new("b/c").is_err());
    }

    #[test]
    fn builtin_graph_is_platform_neutral() {
        let graph = builtin_graph().unwrap();
        assert_eq!(graph.iter().count(), 7);
        assert_eq!(graph.activation_order().unwrap().len(), 7);
    }
}
