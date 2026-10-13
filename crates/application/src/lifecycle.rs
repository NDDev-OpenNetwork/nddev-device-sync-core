//! Client activity and retry policy. Adapters report lifecycle and own timers,
//! task lifetimes and cancellation; no operating-system background service is
//! implied by permission to run while a client remains visible.
use nddev_device_sync_domain::Platform;
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientLifecycle {
    Detached,
    Resumed,
    Inactive,
    Hidden,
    Paused,
}

impl ClientLifecycle {
    pub fn permits_work(self, platform: Platform) -> bool {
        self == Self::Resumed
            || self == Self::Inactive
                && matches!(
                    platform,
                    Platform::Linux | Platform::Macos | Platform::Windows | Platform::Web
                )
    }
}

#[derive(Clone, Copy)]
pub enum BatchOutcome {
    CaughtUp,
    CatchingUp,
    /// Authenticated inbox observation; pending uploads may still exist.
    InboxHead,
    InboxMore,
    Retryable,
    CapacityExhausted,
    Locked,
}

/// One bounded-delay policy for an identity session's replica. Adapters retain
/// this schedule across focus, resume and view reopening; replacing timers must
/// not clear a persistent upload block. Inbox reads remain eligible under that
/// block and use their own head/backlog evidence. A locked identity terminates this
/// lifetime; adapters revalidate through the identity owner before restart.
#[derive(Default)]
pub struct ReplicaSchedule {
    failures: u8,
    capacity_blocked: bool,
}

impl ReplicaSchedule {
    /// Adapters select inbox-only work while automatic uploads are blocked.
    pub fn is_capacity_blocked(&self) -> bool {
        self.capacity_blocked
    }

    /// Schedule the next batch without granting upload eligibility. Adapters
    /// select inbox-only work while the retained capacity block is set.
    pub fn after(&mut self, outcome: BatchOutcome) -> Option<Duration> {
        match outcome {
            BatchOutcome::CapacityExhausted => {
                self.capacity_blocked = true;
                self.failures = 0;
                Some(Duration::from_secs(15))
            }
            BatchOutcome::Locked => None,
            BatchOutcome::Retryable => {
                self.failures = self.failures.saturating_add(1).min(5);
                Some(Duration::from_secs(1 << self.failures))
            }
            BatchOutcome::CaughtUp
            | BatchOutcome::CatchingUp
            | BatchOutcome::InboxHead
            | BatchOutcome::InboxMore => {
                self.failures = 0;
                Some(match outcome {
                    BatchOutcome::CatchingUp | BatchOutcome::InboxMore => {
                        Duration::from_millis(200)
                    }
                    _ => Duration::from_secs(15),
                })
            }
        }
    }

    /// Clear a capacity block only for an explicit manual retry or a verified
    /// capacity remedy. Ordinary lifecycle or success reports cannot clear it.
    pub fn retry_capacity(&mut self) {
        self.capacity_blocked = false;
        self.failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_focus_loss_does_not_suspend_desktop_or_web_work() {
        for platform in Platform::ALL {
            assert!(ClientLifecycle::Resumed.permits_work(platform));
            assert_eq!(
                ClientLifecycle::Inactive.permits_work(platform),
                !matches!(platform, Platform::Android | Platform::Ios)
            );
            for state in [
                ClientLifecycle::Detached,
                ClientLifecycle::Hidden,
                ClientLifecycle::Paused,
            ] {
                assert!(!state.permits_work(platform));
            }
        }
    }

    #[test]
    fn backoff_is_bounded_success_resets_it_and_identity_lock_stops_work() {
        let mut schedule = ReplicaSchedule::default();
        for seconds in [2, 4, 8, 16, 32, 32, 32] {
            assert_eq!(
                schedule.after(BatchOutcome::Retryable),
                Some(Duration::from_secs(seconds))
            );
        }
        assert_eq!(
            schedule.after(BatchOutcome::CatchingUp),
            Some(Duration::from_millis(200))
        );
        assert_eq!(
            schedule.after(BatchOutcome::Retryable),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            schedule.after(BatchOutcome::CaughtUp),
            Some(Duration::from_secs(15))
        );
        assert_eq!(schedule.after(BatchOutcome::Locked), None);
    }

    #[test]
    fn capacity_blocks_uploads_but_retains_inbox_progress_across_activity() {
        let mut schedule = ReplicaSchedule::default();
        assert_eq!(
            schedule.after(BatchOutcome::Retryable),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            schedule.after(BatchOutcome::CapacityExhausted),
            Some(Duration::from_secs(15))
        );

        for lifecycle in [
            ClientLifecycle::Inactive,
            ClientLifecycle::Resumed,
            ClientLifecycle::Detached,
            ClientLifecycle::Resumed,
        ] {
            // Activity permits another timer without restoring upload authority.
            assert!(schedule.is_capacity_blocked());
            assert!(!(lifecycle.permits_work(Platform::Linux) && !schedule.is_capacity_blocked()));
            // A late full-batch result also cannot clear the block or strand
            // the inbox by terminating the replacement timer.
            assert_eq!(
                schedule.after(BatchOutcome::CaughtUp),
                Some(Duration::from_secs(15))
            );
            assert_eq!(
                schedule.after(BatchOutcome::CatchingUp),
                Some(Duration::from_millis(200))
            );
            assert_eq!(
                schedule.after(BatchOutcome::InboxMore),
                Some(Duration::from_millis(200))
            );
            assert_eq!(
                schedule.after(BatchOutcome::InboxHead),
                Some(Duration::from_secs(15))
            );
            assert!(schedule.is_capacity_blocked());
        }
    }

    #[test]
    fn inbox_errors_back_off_without_restoring_uploads_and_lock_stops() {
        let mut schedule = ReplicaSchedule::default();
        let _ = schedule.after(BatchOutcome::CapacityExhausted);
        for seconds in [2, 4, 8, 16, 32, 32] {
            assert_eq!(
                schedule.after(BatchOutcome::Retryable),
                Some(Duration::from_secs(seconds))
            );
            assert!(schedule.is_capacity_blocked());
        }
        let _ = schedule.after(BatchOutcome::InboxHead);
        assert_eq!(
            schedule.after(BatchOutcome::Retryable),
            Some(Duration::from_secs(2))
        );
        assert_eq!(schedule.after(BatchOutcome::Locked), None);
        assert!(schedule.is_capacity_blocked());
    }

    #[test]
    fn only_explicit_capacity_retry_restores_upload_eligibility() {
        let mut schedule = ReplicaSchedule::default();
        for _ in 0..5 {
            let _ = schedule.after(BatchOutcome::Retryable);
        }
        let _ = schedule.after(BatchOutcome::CapacityExhausted);
        schedule.retry_capacity();
        assert!(!schedule.is_capacity_blocked());
        assert_eq!(
            schedule.after(BatchOutcome::Retryable),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            schedule.after(BatchOutcome::CaughtUp),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            schedule.after(BatchOutcome::CapacityExhausted),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            schedule.after(BatchOutcome::CatchingUp),
            Some(Duration::from_millis(200))
        );
        assert!(schedule.is_capacity_blocked());
    }
}
