#![cfg(target_os = "linux")]

use nddev_device_sync_adapters_keyring::NativeSecretStore;
use nddev_device_sync_adapters_memory::MemoryAccountStore;
use nddev_device_sync_application::{
    ACCOUNT_SECRET_SERVICE, AccountService, AccountStore, ApplicationError, SecretStore,
};
use nddev_device_sync_domain::{AccountId, AccountRecord, HarnessId, SwitchSupport};
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

fn isolated_record(mode: &str) -> AccountRecord {
    assert_eq!(std::env::var("NDS_KEYRING_TEST_MODE").as_deref(), Ok(mode));
    let id = format!(
        "test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    AccountRecord::new(
        AccountId::new(id).unwrap(),
        HarnessId::new("nds-isolated-test").unwrap(),
        "Temporary acceptance account",
        None,
        1,
        SwitchSupport::Official,
    )
}

struct OwnEntry(String);
impl Drop for OwnEntry {
    fn drop(&mut self) {
        let _ = NativeSecretStore.delete(ACCOUNT_SECRET_SERVICE, &self.0);
    }
}

#[test]
#[ignore = "requires just keyring-check and an isolated Secret Service session"]
fn native_duplicate_preserves_existing_key_and_secret() {
    let record = isolated_record("available");
    let key = format!("{}/{}", record.harness_id.as_str(), record.id.as_str());
    let entry = keyring::Entry::new(ACCOUNT_SECRET_SERVICE, &key).unwrap();
    assert!(matches!(entry.get_secret(), Err(keyring::Error::NoEntry)));
    let _cleanup = OwnEntry(key.clone());
    let mut generated = [0_u8; 64];
    std::fs::File::open("/dev/urandom")
        .unwrap()
        .read_exact(&mut generated)
        .unwrap();
    let mut service = AccountService::new(MemoryAccountStore::default(), NativeSecretStore);
    service
        .add_authorized(record.clone(), &generated[..32])
        .unwrap();
    assert!(matches!(
        service.add_authorized(record.clone(), &generated[32..]),
        Err(ApplicationError::AccountStore(_))
    ));
    let (accounts, mut secrets) = service.into_parts();
    assert_eq!(accounts.get(&record.id).unwrap(), Some(record));
    // This is the original service + harness/account naming, with no fallback lookup.
    assert!(entry.get_secret().unwrap() == generated[..32]);
    assert!(secrets.get(ACCOUNT_SECRET_SERVICE, &key).unwrap() == generated[..32]);
    secrets.delete(ACCOUNT_SECRET_SERVICE, &key).unwrap();
    assert!(matches!(entry.get_secret(), Err(keyring::Error::NoEntry)));
}

#[test]
#[ignore = "requires just keyring-check and an unavailable isolated bus"]
fn unavailable_native_store_removes_pending_reservation() {
    let record = isolated_record("unavailable");
    let mut service = AccountService::new(MemoryAccountStore::default(), NativeSecretStore);
    assert!(matches!(
        service.add_authorized(record.clone(), b"temporary-non-account-secret"),
        Err(ApplicationError::SecretStore(_))
    ));
    let (accounts, _) = service.into_parts();
    assert!(accounts.get(&record.id).unwrap().is_none());
}
