//! Client activity and retry policy. Adapters report lifecycle and own timers,
//! task lifetimes and cancellation; no operating-system background service is
//! implied by permission to run while a client remains visible.
use crate::replica::CapacityProbeOutcome;
use nddev_device_sync_domain::Platform;
use nddev_device_sync_domain::sync::history::HistoryVersion;
use std::{sync::Arc, time::Duration};

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
    capacity: Option<CapacityBlock>,
    history: Option<HistoryVersion>,
}
struct CapacityBlock {
    identity: Arc<()>,
    floor: Option<u64>,
    probe_ready: bool,
}
/// Identity of one actual refusal in one policy. Not upload authorization.
#[derive(Clone)]
pub struct CapacityCheck(Arc<()>);

impl ReplicaSchedule {
    /// Adapters select inbox-only work while automatic uploads are blocked.
    pub fn is_capacity_blocked(&self) -> bool {
        self.capacity.is_some()
    }

    /// Authenticated server metadata, never a local cursor or a lifecycle hint.
    /// Recording it alone cannot clear a refusal or schedule an upload.
    pub fn observe_history(&mut self, history: HistoryVersion) -> bool {
        if history.validate().is_err()
            || self
                .history
                .is_some_and(|old| history.head < old.head || history.floor < old.floor)
        {
            return false;
        }
        self.history = Some(history);
        true
    }
    pub fn capacity_check(&self) -> Option<CapacityCheck> {
        self.capacity
            .as_ref()
            .map(|block| CapacityCheck(block.identity.clone()))
    }
    /// A completed current inbox read may request ONE bounded original check
    /// after retention changed. It is not evidence that the original will fit.
    pub fn observe_capacity_inbox(&mut self, check: &CapacityCheck, history: HistoryVersion) {
        if !self.observe_history(history) {
            return;
        }
        if let Some(block) = &mut self.capacity
            && Arc::ptr_eq(&block.identity, &check.0)
        {
            match block.floor {
                Some(floor) if history.floor > floor => block.probe_ready = true,
                None => block.floor = Some(history.floor),
                _ => {}
            }
        }
    }
    pub fn capacity_probe(&self) -> Option<CapacityCheck> {
        self.capacity
            .as_ref()
            .filter(|b| b.probe_ready)
            .map(|b| CapacityCheck(b.identity.clone()))
    }
    /// Caller supplies an actual completed Core probe (or proven empty inbox),
    /// then replaces policy under its existing auth/publication fence. Old work
    /// retains this old policy, so late refusals cannot reblock its replacement.
    pub fn recovered_capacity(
        &self,
        check: &CapacityCheck,
        _outcome: CapacityProbeOutcome,
    ) -> Option<Self> {
        self.capacity
            .as_ref()
            .filter(|b| Arc::ptr_eq(&b.identity, &check.0))?;
        Some(Self {
            history: self.history,
            ..Self::default()
        })
    }

    /// Schedule the next batch without granting upload eligibility. Adapters
    /// select inbox-only work while the retained capacity block is set.
    pub fn after(&mut self, outcome: BatchOutcome) -> Option<Duration> {
        match outcome {
            BatchOutcome::CapacityExhausted => {
                self.capacity = Some(CapacityBlock {
                    identity: Arc::new(()),
                    floor: self.history.map(|h| h.floor),
                    probe_ready: false,
                });
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
                    // A generic late result may only report pending uploads;
                    // only InboxMore proves backlog worth an immediate pull.
                    BatchOutcome::CatchingUp if self.is_capacity_blocked() => {
                        Duration::from_secs(15)
                    }
                    BatchOutcome::CatchingUp | BatchOutcome::InboxMore => {
                        Duration::from_millis(200)
                    }
                    _ => Duration::from_secs(15),
                })
            }
        }
    }

    /// Disperse retry phases without changing the exponential state transition.
    /// Only Retryable varies: 2/4/8/16s +/-1..250ms, and 32s -1..250ms.
    /// Adapters provide entropy; this policy owns the bounded timing arithmetic.
    pub fn after_with_sample(&mut self, outcome: BatchOutcome, sample: u16) -> Option<Duration> {
        let delay = self.after(outcome)?;
        if !matches!(outcome, BatchOutcome::Retryable) {
            return Some(delay);
        }
        let offset = Duration::from_millis(1 + u64::from(sample & 0x7fff) % 250);
        Some(
            if delay == Duration::from_secs(32) || sample & 0x8000 == 0 {
                delay - offset
            } else {
                delay + offset
            },
        )
    }

    /// Clear a capacity block only for an explicit manual retry or a verified
    /// capacity remedy. Ordinary lifecycle or success reports cannot clear it.
    pub fn retry_capacity(&mut self) {
        self.capacity = None;
        self.failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn history(head: u64, floor: u64) -> HistoryVersion {
        HistoryVersion {
            head,
            floor,
            base: floor,
        }
    }

    #[test]
    fn retention_can_enable_one_original_check_but_never_clears_capacity() {
        let mut schedule = ReplicaSchedule::default();
        assert!(schedule.observe_history(history(100, 0)));
        schedule.after(BatchOutcome::CapacityExhausted);
        let check = schedule.capacity_check().unwrap();
        schedule.after(BatchOutcome::InboxHead);
        schedule.observe_capacity_inbox(&check, history(200, 0));
        assert!(schedule.capacity_probe().is_none());
        assert!(schedule.observe_history(history(201, 10)));
        assert!(schedule.capacity_probe().is_none()); // Metadata alone is not a completed read.
        schedule.observe_capacity_inbox(&check, history(201, 10));
        assert!(schedule.capacity_probe().is_some());
        assert!(schedule.is_capacity_blocked());
        for _ in 0..3 {
            schedule.after(BatchOutcome::Retryable);
            assert!(schedule.capacity_probe().is_some()); // Same immutable probe may retry transport.
        }
        schedule.after(BatchOutcome::CapacityExhausted);
        let next = schedule.capacity_check().unwrap();
        schedule.observe_capacity_inbox(&next, history(300, 10));
        assert!(schedule.capacity_probe().is_none()); // Real refusal consumes this floor.
        assert!(
            schedule
                .recovered_capacity(&check, CapacityProbeOutcome::Receipt)
                .is_none()
        );
        schedule.observe_capacity_inbox(&next, history(301, 11));
        assert!(schedule.capacity_probe().is_some());
        let replacement = schedule
            .recovered_capacity(&next, CapacityProbeOutcome::Receipt)
            .unwrap();
        assert!(!replacement.is_capacity_blocked());
        assert!(schedule.is_capacity_blocked()); // Old publishers keep the old policy.
    }

    #[test]
    fn absent_backward_or_foreign_evidence_cannot_restore_uploads() {
        let mut schedule = ReplicaSchedule::default();
        schedule.after(BatchOutcome::CapacityExhausted);
        let check = schedule.capacity_check().unwrap();
        schedule.observe_capacity_inbox(&check, history(100, 50));
        assert!(schedule.capacity_probe().is_none());
        for h in [history(99, 51), history(101, 49), history(40, 50)] {
            assert!(!schedule.observe_history(h));
        }
        assert!(schedule.capacity_probe().is_none());
        let mut other = ReplicaSchedule::default();
        other.after(BatchOutcome::CapacityExhausted);
        assert!(
            other
                .recovered_capacity(&check, CapacityProbeOutcome::NoEligibleWork)
                .is_none()
        );
        other.observe_capacity_inbox(&check, history(200, 60));
        assert!(other.capacity_probe().is_none());
        for outcome in [
            CapacityProbeOutcome::Receipt,
            CapacityProbeOutcome::Unknown,
            CapacityProbeOutcome::NoEligibleWork,
        ] {
            assert!(
                !schedule
                    .recovered_capacity(&check, outcome)
                    .unwrap()
                    .is_capacity_blocked()
            );
        }
    }

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
                Some(Duration::from_secs(15))
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
        assert_eq!(
            schedule.after(BatchOutcome::CapacityExhausted),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            schedule.after(BatchOutcome::CatchingUp),
            Some(Duration::from_secs(15))
        );
        assert!(schedule.is_capacity_blocked());
    }
}

#[cfg(test)]
mod retry_sample_tests {
    use super::*;
    #[test]
    fn all_samples_stay_positive_bounded_and_off_integer_phases() {
        for sample in 0..=u16::MAX {
            let mut schedule = ReplicaSchedule::default();
            for base in [2u64, 4, 8, 16, 32, 32] {
                let delay = schedule
                    .after_with_sample(BatchOutcome::Retryable, sample)
                    .unwrap();
                assert!(delay > Duration::ZERO && delay <= Duration::from_secs(32));
                assert!(delay >= Duration::from_millis(base * 1000 - 250));
                assert!(
                    delay
                        <= Duration::from_millis(if base == 32 {
                            32000
                        } else {
                            base * 1000 + 250
                        })
                );
                assert_ne!(delay.as_millis() % 1000, 0);
            }
        }
    }
    #[test]
    fn state_updates_once_and_other_outcomes_keep_existing_policy() {
        let mut schedule = ReplicaSchedule::default();
        let _ = schedule.after_with_sample(BatchOutcome::Retryable, 0);
        assert_eq!(
            schedule.after(BatchOutcome::Retryable),
            Some(Duration::from_secs(4))
        );
        assert_eq!(
            schedule.after_with_sample(BatchOutcome::CapacityExhausted, u16::MAX),
            Some(Duration::from_secs(15))
        );
        assert!(schedule.is_capacity_blocked());
        assert_eq!(
            schedule.after_with_sample(BatchOutcome::CatchingUp, 0),
            Some(Duration::from_secs(15))
        );
        assert_eq!(
            schedule.after_with_sample(BatchOutcome::InboxMore, 0),
            Some(Duration::from_millis(200))
        );
        assert_eq!(
            schedule.after_with_sample(BatchOutcome::InboxHead, 0),
            Some(Duration::from_secs(15))
        );
        assert!(schedule.is_capacity_blocked());
        assert_eq!(schedule.after_with_sample(BatchOutcome::Locked, 0), None);
        schedule.retry_capacity();
        assert_eq!(
            schedule.after_with_sample(BatchOutcome::CaughtUp, 0),
            Some(Duration::from_secs(15))
        );
        assert!(!schedule.is_capacity_blocked());
    }
}
