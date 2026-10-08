//! Native credential-store adapter.
//!
//! `keyring` selects the platform store: Keychain on macOS, Secret Service on
//! Linux, and Credential Manager on Windows. The application database stores
//! only the deterministic service/key reference and never the secret bytes.

use keyring::Entry;
use nddev_device_sync_application::SecretStore;

#[derive(Default)]
pub struct NativeSecretStore;

impl SecretStore for NativeSecretStore {
    fn put(&mut self, service: &str, key: &str, secret: &[u8]) -> Result<(), String> {
        Entry::new(service, key)
            .map_err(|error| error.to_string())?
            .set_secret(secret)
            .map_err(|error| error.to_string())
    }

    fn get(&self, service: &str, key: &str) -> Result<Vec<u8>, String> {
        Entry::new(service, key)
            .map_err(|error| error.to_string())?
            .get_secret()
            .map_err(|error| error.to_string())
    }

    fn delete(&mut self, service: &str, key: &str) -> Result<(), String> {
        Entry::new(service, key)
            .map_err(|error| error.to_string())?
            .delete_credential()
            .map_err(|error| error.to_string())
    }
}
