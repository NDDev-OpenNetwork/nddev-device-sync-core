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
    Retryable,
    CapacityExhausted,
    Locked,
}

/// One bounded-delay policy for an identity session's replica. Adapters retain
/// this schedule across focus, resume and view reopening; replacing timers must
/// not clear a persistent capacity block. A locked identity terminates this
/// lifetime; adapters revalidate through the identity owner before restart.
#[derive(Default)]
pub struct ReplicaSchedule {
    failures: u8,
    capacity_blocked: bool,
}

impl ReplicaSchedule {
    /// Adapters check the retained session block before starting replacement
    /// work on focus, resume or view reopening.
    pub fn is_capacity_blocked(&self) -> bool {
        self.capacity_blocked
    }

    pub fn after(&mut self, outcome: BatchOutcome) -> Option<Duration> {
        if self.capacity_blocked {
            return None;
        }
        match outcome {
            BatchOutcome::CapacityExhausted => {
                self.capacity_blocked = true;
                None
            }
            BatchOutcome::Locked => None,
            BatchOutcome::Retryable => {
                self.failures = self.failures.saturating_add(1).min(5);
                Some(Duration::from_secs(1 << self.failures))
            }
            BatchOutcome::CaughtUp | BatchOutcome::CatchingUp => {
                self.failures = 0;
                Some(match outcome {
                    BatchOutcome::CatchingUp => Duration::from_millis(200),
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
    fn persistent_capacity_stays_blocked_across_activity_and_outcome_reports() {
        let mut schedule = ReplicaSchedule::default();
        assert_eq!(
            schedule.after(BatchOutcome::Retryable),
            Some(Duration::from_secs(2))
        );
        assert_eq!(schedule.after(BatchOutcome::CapacityExhausted), None);

        for lifecycle in [
            ClientLifecycle::Inactive,
            ClientLifecycle::Resumed,
            ClientLifecycle::Detached,
            ClientLifecycle::Resumed,
        ] {
            // Admission may allow another timer; the retained session schedule
            // still refuses work after focus, resume or reopening a view.
            assert!(schedule.is_capacity_blocked());
            assert!(!(lifecycle.permits_work(Platform::Linux) && !schedule.is_capacity_blocked()));
            for outcome in [
                BatchOutcome::Retryable,
                BatchOutcome::CaughtUp,
                BatchOutcome::CatchingUp,
                BatchOutcome::CapacityExhausted,
                BatchOutcome::Locked,
            ] {
                assert_eq!(schedule.after(outcome), None);
            }
        }
    }

    #[test]
    fn only_explicit_capacity_retry_restarts_the_retained_schedule() {
        let mut schedule = ReplicaSchedule::default();
        for _ in 0..5 {
            let _ = schedule.after(BatchOutcome::Retryable);
        }
        assert_eq!(schedule.after(BatchOutcome::CapacityExhausted), None);
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
        assert_eq!(schedule.after(BatchOutcome::CapacityExhausted), None);
        assert_eq!(schedule.after(BatchOutcome::CatchingUp), None);
    }
}
