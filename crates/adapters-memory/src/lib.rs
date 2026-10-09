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

    fn mark_authorized(&mut self, id: &AccountId) -> Result<(), String> {
        let record = self.records.get_mut(id).ok_or("account does not exist")?;
        if record.status != AccountStatus::PendingAuthorization {
            return Err("account is not pending authorization".into());
        }
        record.status = AccountStatus::Authorized;
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
    secrets: BTreeMap<(String, String), Vec<u8>>,
}

impl SecretStore for MemorySecretStore {
    fn put(&mut self, service: &str, key: &str, secret: &[u8]) -> Result<(), String> {
        self.secrets
            .insert((service.into(), key.into()), secret.to_vec());
        Ok(())
    }

    fn get(&self, service: &str, key: &str) -> Result<Vec<u8>, String> {
        self.secrets
            .get(&(service.into(), key.into()))
            .cloned()
            .ok_or_else(|| "secret does not exist".into())
    }

    fn delete(&mut self, service: &str, key: &str) -> Result<(), String> {
        self.secrets.remove(&(service.into(), key.into()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nddev_device_sync_application::{
        ACCOUNT_SECRET_SERVICE, AccountService, ApplicationError, HarnessAccountPort,
    };
    use nddev_device_sync_domain::SwitchSupport;

    fn record(harness: &str) -> AccountRecord {
        AccountRecord::new(
            AccountId::new("account").unwrap(),
            HarnessId::new(harness).unwrap(),
            "Test account",
            None,
            1,
            SwitchSupport::Official,
        )
    }

    #[test]
    fn duplicate_add_preserves_the_existing_metadata_and_secret() {
        let original = record("harness");
        let mut service =
            AccountService::new(MemoryAccountStore::default(), MemorySecretStore::default());
        service
            .add_authorized(original.clone(), b"original")
            .unwrap();
        for mut duplicate in [original.clone(), record("another-harness")] {
            duplicate.label = "Replacement".into();
            assert!(matches!(
                service.add_authorized(duplicate, b"replacement"),
                Err(ApplicationError::AccountStore(_))
            ));
        }
        let (accounts, secrets) = service.into_parts();
        assert_eq!(accounts.get(&original.id).unwrap(), Some(original));
        assert!(
            secrets
                .get(ACCOUNT_SECRET_SERVICE, "harness/account")
                .unwrap()
                == b"original"
        );
        assert!(
            secrets
                .get(ACCOUNT_SECRET_SERVICE, "another-harness/account")
                .is_err()
        );
    }

    #[test]
    fn memory_secret_store_keeps_service_and_key_boundaries() {
        let mut secrets = MemorySecretStore::default();
        secrets.put("a/b", "c", b"first").unwrap();
        secrets.put("a", "b/c", b"second").unwrap();
        secrets.delete("a/b", "c").unwrap();
        assert!(secrets.get("a/b", "c").is_err());
        assert!(secrets.get("a", "b/c").unwrap() == b"second");
    }

    // Focused port-failure unit tests, not evidence of native adapter acceptance.
    #[derive(Default)]
    struct FailingAccounts {
        inner: MemoryAccountStore,
        cleanup: bool,
        finalization: bool,
    }

    impl AccountStore for FailingAccounts {
        fn insert(&mut self, record: AccountRecord) -> Result<(), String> {
            self.inner.insert(record)
        }
        fn mark_authorized(&mut self, id: &AccountId) -> Result<(), String> {
            if self.finalization {
                return Err("authorization unavailable".into());
            }
            self.inner.mark_authorized(id)
        }
        fn remove(&mut self, id: &AccountId) -> Result<(), String> {
            if self.cleanup {
                return Err("cleanup unavailable".into());
            }
            self.inner.remove(id)
        }
        fn get(&self, id: &AccountId) -> Result<Option<AccountRecord>, String> {
            self.inner.get(id)
        }
        fn list(&self, id: &HarnessId) -> Result<Vec<AccountRecord>, String> {
            self.inner.list(id)
        }
        fn mark_active(
            &mut self,
            harness: &HarnessId,
            id: &AccountId,
            now: u64,
        ) -> Result<(), String> {
            self.inner.mark_active(harness, id, now)
        }
    }

    struct UnavailableSecrets;
    impl SecretStore for UnavailableSecrets {
        fn put(&mut self, _: &str, _: &str, _: &[u8]) -> Result<(), String> {
            Err("secret store unavailable".into())
        }
        fn get(&self, _: &str, _: &str) -> Result<Vec<u8>, String> {
            panic!("pending account must not read credentials")
        }
        fn delete(&mut self, _: &str, _: &str) -> Result<(), String> {
            panic!("failed write must not delete a credential")
        }
    }

    struct UnusedHarness(HarnessId);
    impl HarnessAccountPort for UnusedHarness {
        fn harness_id(&self) -> &HarnessId {
            &self.0
        }
        fn switch_support(&self) -> SwitchSupport {
            SwitchSupport::Official
        }
        fn activate(&self, _: &AccountRecord, _: &[u8]) -> Result<(), String> {
            panic!("pending account must not activate")
        }
    }

    #[test]
    fn failed_secret_write_cleans_only_its_reservation_or_reports_cleanup_failure() {
        for cleanup in [false, true] {
            let record = record("harness");
            let mut service = AccountService::new(
                FailingAccounts {
                    cleanup,
                    ..Default::default()
                },
                UnavailableSecrets,
            );
            let error = service
                .add_authorized(record.clone(), b"temporary")
                .unwrap_err();
            if cleanup {
                assert_eq!(error, ApplicationError::AccountCleanupFailed);
                assert_eq!(
                    service.activate(&record.id, 2, &UnusedHarness(record.harness_id.clone())),
                    Err(ApplicationError::AccountNotAuthorized)
                );
            } else {
                assert!(matches!(error, ApplicationError::SecretStore(_)));
            }
            let (accounts, _) = service.into_parts();
            assert_eq!(
                accounts.get(&record.id).unwrap().map(|r| r.status),
                cleanup.then_some(AccountStatus::PendingAuthorization)
            );
        }
    }

    #[test]
    fn failed_finalization_preserves_secret_and_keeps_account_pending() {
        let record = record("harness");
        let mut service = AccountService::new(
            FailingAccounts {
                finalization: true,
                ..Default::default()
            },
            MemorySecretStore::default(),
        );
        assert!(matches!(
            service.add_authorized(record.clone(), b"temporary"),
            Err(ApplicationError::AccountStore(_))
        ));
        assert_eq!(
            service.activate(&record.id, 2, &UnusedHarness(record.harness_id)),
            Err(ApplicationError::AccountNotAuthorized)
        );
        let (accounts, secrets) = service.into_parts();
        assert_eq!(
            accounts.get(&record.id).unwrap().unwrap().status,
            AccountStatus::PendingAuthorization
        );
        assert!(
            secrets
                .get(ACCOUNT_SECRET_SERVICE, "harness/account")
                .unwrap()
                == b"temporary"
        );
    }
}
