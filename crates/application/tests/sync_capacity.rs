use nddev_device_sync_application::sync::{SyncError, retention_reserve_rows};

#[test]
fn reserve_covers_all_32_active_devices_and_rejects_unbounded_inputs() {
    assert_eq!(retention_reserve_rows(32), Ok(1024));
    assert_eq!(retention_reserve_rows(1), Ok(32));
    assert_eq!(retention_reserve_rows(0), Err(SyncError::Invalid));
    assert_eq!(retention_reserve_rows(u64::MAX), Err(SyncError::Invalid));
    assert_eq!(retention_reserve_rows(257), Err(SyncError::Invalid));
}
