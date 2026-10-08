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
}

pub trait AccountStore {
    fn insert(&mut self, record: AccountRecord) -> Result<(), String>;
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
        self.secrets
            .put(ACCOUNT_SECRET_SERVICE, &key, secret)
            .map_err(ApplicationError::SecretStore)?;
        record.status = AccountStatus::Authorized;
        if let Err(error) = self.accounts.insert(record) {
            let _ = self.secrets.delete(ACCOUNT_SECRET_SERVICE, &key);
            return Err(ApplicationError::AccountStore(error));
        }
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
    use nddev_device_sync_domain::SwitchSupport;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Accounts(BTreeMap<AccountId, AccountRecord>);
    impl AccountStore for Accounts {
        fn insert(&mut self, record: AccountRecord) -> Result<(), String> {
            if self.0.insert(record.id.clone(), record).is_some() {
                Err("duplicate".into())
            } else {
                Ok(())
            }
        }
        fn remove(&mut self, id: &AccountId) -> Result<(), String> {
            self.0.remove(id);
            Ok(())
        }
        fn get(&self, id: &AccountId) -> Result<Option<AccountRecord>, String> {
            Ok(self.0.get(id).cloned())
        }
        fn list(&self, harness_id: &HarnessId) -> Result<Vec<AccountRecord>, String> {
            Ok(self
                .0
                .values()
                .filter(|record| &record.harness_id == harness_id)
                .cloned()
                .collect())
        }
        fn mark_active(
            &mut self,
            harness_id: &HarnessId,
            id: &AccountId,
            now_ms: u64,
        ) -> Result<(), String> {
            for record in self
                .0
                .values_mut()
                .filter(|record| &record.harness_id == harness_id)
            {
                record.status = if &record.id == id {
                    AccountStatus::Active
                } else {
                    AccountStatus::Inactive
                };
                if &record.id == id {
                    record.last_used_at_ms = Some(now_ms);
                }
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct Secrets(BTreeMap<String, Vec<u8>>);
    impl SecretStore for Secrets {
        fn put(&mut self, service: &str, key: &str, secret: &[u8]) -> Result<(), String> {
            self.0.insert(format!("{service}/{key}"), secret.to_vec());
            Ok(())
        }
        fn get(&self, service: &str, key: &str) -> Result<Vec<u8>, String> {
            self.0
                .get(&format!("{service}/{key}"))
                .cloned()
                .ok_or_else(|| "missing".into())
        }
        fn delete(&mut self, service: &str, key: &str) -> Result<(), String> {
            self.0.remove(&format!("{service}/{key}"));
            Ok(())
        }
    }

    struct Harness {
        id: HarnessId,
        activated: std::cell::Cell<bool>,
    }
    impl HarnessAccountPort for Harness {
        fn harness_id(&self) -> &HarnessId {
            &self.id
        }
        fn switch_support(&self) -> SwitchSupport {
            SwitchSupport::Official
        }
        fn activate(&self, _: &AccountRecord, secret: &[u8]) -> Result<(), String> {
            self.activated.set(secret == b"secret");
            Ok(())
        }
    }

    #[test]
    fn accounts_keep_secret_out_of_record_and_switch_atomically_in_memory() {
        let harness_id = HarnessId::new("codex").unwrap();
        let account_id = AccountId::new("personal").unwrap();
        let record = AccountRecord::new(
            account_id.clone(),
            harness_id.clone(),
            "Personal",
            Some("user".into()),
            1,
            SwitchSupport::Official,
        );
        let mut service = AccountService::new(Accounts::default(), Secrets::default());
        service.add_authorized(record, b"secret").unwrap();
        let port = Harness {
            id: harness_id.clone(),
            activated: std::cell::Cell::new(false),
        };
        service.activate(&account_id, 2, &port).unwrap();
        assert!(port.activated.get());
        let (accounts, secrets) = service.into_parts();
        assert_eq!(accounts.0[&account_id].status, AccountStatus::Active);
        assert!(secrets.0.values().any(|secret| secret == b"secret"));
    }

    #[test]
    fn builtin_graph_is_platform_neutral() {
        let graph = builtin_graph().unwrap();
        assert_eq!(graph.iter().count(), 7);
        assert_eq!(graph.activation_order().unwrap().len(), 7);
    }
}
