//! Deterministic adapters for tests and development. No runtime secrets are
//! persisted here; production uses the native credential-store adapter.

use nddev_device_sync_application::{AccountStore, SecretStore};
use nddev_device_sync_domain::{AccountId, AccountRecord, AccountStatus, HarnessId};
use std::collections::BTreeMap;

#[derive(Default)]
pub struct MemoryAccountStore {
    records: BTreeMap<AccountId, AccountRecord>,
}

impl AccountStore for MemoryAccountStore {
    fn insert(&mut self, record: AccountRecord) -> Result<(), String> {
        if self.records.contains_key(&record.id) {
            return Err("account already exists".into());
        }
        self.records.insert(record.id.clone(), record);
        Ok(())
    }

    fn remove(&mut self, id: &AccountId) -> Result<(), String> {
        self.records.remove(id);
        Ok(())
    }

    fn get(&self, id: &AccountId) -> Result<Option<AccountRecord>, String> {
        Ok(self.records.get(id).cloned())
    }

    fn list(&self, harness_id: &HarnessId) -> Result<Vec<AccountRecord>, String> {
        Ok(self
            .records
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
        let Some(target) = self.records.get(id) else {
            return Err("account does not exist".into());
        };
        if target.harness_id != *harness_id {
            return Err("account belongs to another harness".into());
        }
        for record in self
            .records
            .values_mut()
            .filter(|record| &record.harness_id == harness_id)
        {
            if &record.id == id {
                record.status = AccountStatus::Active;
                record.last_used_at_ms = Some(now_ms);
            } else if record.status == AccountStatus::Active {
                record.status = AccountStatus::Inactive;
            }
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemorySecretStore {
    secrets: BTreeMap<String, Vec<u8>>,
}

impl SecretStore for MemorySecretStore {
    fn put(&mut self, service: &str, key: &str, secret: &[u8]) -> Result<(), String> {
        self.secrets
            .insert(format!("{service}/{key}"), secret.to_vec());
        Ok(())
    }

    fn get(&self, service: &str, key: &str) -> Result<Vec<u8>, String> {
        self.secrets
            .get(&format!("{service}/{key}"))
            .cloned()
            .ok_or_else(|| "secret does not exist".into())
    }

    fn delete(&mut self, service: &str, key: &str) -> Result<(), String> {
        self.secrets.remove(&format!("{service}/{key}"));
        Ok(())
    }
}
