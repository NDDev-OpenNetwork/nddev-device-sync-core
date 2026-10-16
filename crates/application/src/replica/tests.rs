use super::*;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    task::{Context, Poll, Waker},
};
#[derive(Clone, Copy)]
struct Saved {
    base: BaseProgress,
    through: u64,
    head: bool,
    required: u64,
}
struct Port {
    mode: Cell<u8>,
    facts: RefCell<WriterFacts>,
    prereads: Cell<usize>,
    pending: Cell<usize>,
    unknown: Cell<bool>,
    append_refused: Cell<bool>,
    blocked: Cell<bool>,
    cursor: Cell<u64>,
    pages: RefCell<VecDeque<ReadOutcome<VerifiedPage<u64>>>>,
    bases: RefCell<VecDeque<ReadOutcome<VerifiedBasePage<()>>>>,
    stage: RefCell<Option<Saved>>,
    log: RefCell<Vec<String>>,
    reads: Cell<usize>,
    fresh: Cell<usize>,
    installs: Cell<usize>,
    required: Cell<u64>,
    capacity_blocked: Cell<bool>,
    discards: Cell<usize>,
}
impl Port {
    fn new() -> Self {
        Self {
            mode: Cell::new(3),
            facts: RefCell::new(WriterFacts {
                confirmed: Some(ConfirmedWriter {
                    mode: WriterMode::V3,
                    key_id: "key".into(),
                    basis: 0,
                }),
                legacy_v2_initialized: false,
            }),
            prereads: Cell::new(0),
            pending: Cell::new(0),
            unknown: Cell::new(false),
            append_refused: Cell::new(false),
            blocked: Cell::new(false),
            cursor: Cell::new(0),
            pages: RefCell::new(VecDeque::new()),
            bases: RefCell::new(VecDeque::new()),
            stage: RefCell::new(None),
            log: RefCell::new(Vec::new()),
            reads: Cell::new(0),
            fresh: Cell::new(0),
            installs: Cell::new(0),
            required: Cell::new(0),
            capacity_blocked: Cell::new(false),
            discards: Cell::new(0),
        }
    }
    fn note(&self, s: &str) {
        self.log.borrow_mut().push(s.into());
    }
}
impl ReplicaPort for Port {
    type Error = SyncError;
    type Pending = usize;
    type Receipt = ();
    type Page = u64;
    async fn negotiate(&self) -> Result<Negotiation, SyncError> {
        match self.mode.get() {
            0 => Err(SyncError::Unavailable),
            1 => Ok(Negotiation::LegacyUnsupported),
            n => Ok(Negotiation::Capabilities(Capabilities {
                reader_versions: [2, 3],
                writer: if n == 3 {
                    WriterMode::V3
                } else {
                    WriterMode::V2
                },
                retention: n == 3,
            })),
        }
    }
    async fn writer_facts(&self) -> Result<WriterFacts, SyncError> {
        Ok(self.facts.borrow().clone())
    }
    async fn prepare_context(
        &self,
        _: ReadMode,
        b: &mut BatchBudget,
    ) -> Result<Preparation, SyncError> {
        for _ in 0..self.prereads.get() {
            if !b.take_read() {
                return Ok(Preparation::ReadBudgetExhausted);
            }
            self.reads.set(self.reads.get() + 1);
        }
        Ok(Preparation::Ready(PreparedContext {
            key_id: "key".into(),
            observed_basis: Some(0),
        }))
    }
    async fn confirm_writer(
        &self,
        expected: &WriterFacts,
        next: ConfirmedWriter,
    ) -> Result<(), SyncError> {
        assert_eq!(&*self.facts.borrow(), expected);
        self.facts.borrow_mut().confirmed = Some(next);
        Ok(())
    }
    async fn claim(&self) -> Result<Vec<usize>, SyncError> {
        self.note("claim");
        Ok(if self.blocked.get() {
            Vec::new()
        } else {
            (0..self.pending.get()).collect()
        })
    }
    async fn claim_one(&self) -> Result<Option<usize>, SyncError> {
        self.note("claim_one");
        Ok((!self.blocked.get() && self.pending.get() > 0).then_some(0))
    }
    async fn append_outcome(&self, _: &usize) -> Result<AppendOutcome<()>, SyncError> {
        self.note("append");
        if self.append_refused.get() {
            return Err(SyncError::CapacityExhausted);
        }
        Ok(if self.unknown.get() {
            AppendOutcome::Unknown(UnknownReason::BasisExpired)
        } else {
            AppendOutcome::Receipt(())
        })
    }
    async fn remember_unknown(&self, _: &usize, _: UnknownReason) -> Result<(), SyncError> {
        self.note("unknown");
        self.blocked.set(true);
        Ok(())
    }
    async fn acknowledge(&self, _: usize, _: ()) -> Result<(), SyncError> {
        self.pending.set(self.pending.get() - 1);
        self.note("ack");
        Ok(())
    }
    async fn cursor(&self) -> Result<u64, SyncError> {
        Ok(self.cursor.get())
    }
    async fn history_outcome(
        &self,
        _: ReadMode,
        after: u64,
        _: usize,
    ) -> Result<ReadOutcome<VerifiedPage<u64>>, SyncError> {
        self.note(&format!("read{after}"));
        self.reads.set(self.reads.get() + 1);
        self.pages
            .borrow_mut()
            .pop_front()
            .ok_or(SyncError::Unavailable)
    }
    async fn ingest(&self, p: u64) -> Result<(), SyncError> {
        self.cursor.set(p);
        self.note("ingest");
        Ok(())
    }
    async fn caught_up(&self, cursor: u64) -> Result<bool, SyncError> {
        self.note("fresh");
        self.fresh.set(self.fresh.get() + 1);
        Ok(cursor == self.cursor.get() && self.pending.get() == 0)
    }
}
impl CheckpointPort for Port {
    type Stage = ();
    type Guard = ();
    type BaseContents = ();
    async fn checkpoint_resume(&self) -> Result<StageResume<(), ()>, SyncError> {
        self.note("resume");
        Ok(match *self.stage.borrow() {
            None => StageResume::Absent,
            Some(s) => StageResume::Active(ActiveStage {
                stage: (),
                guard: (),
                base: s.base,
                through: s.through,
                tail_at_head: s.head,
                install_version: InstallVersion {
                    cursor: self.cursor.get(),
                    local_revision: 0,
                    known_committed_seq: s.required,
                },
            }),
        })
    }
    async fn checkpoint_begin(
        &self,
        base: u64,
        total: usize,
    ) -> Result<ActiveStage<(), ()>, SyncError> {
        self.note("begin");
        let s = Saved {
            base: BaseProgress {
                base,
                total,
                received: 0,
                after_member: 0,
            },
            through: base,
            head: false,
            required: self.required.get(),
        };
        *self.stage.borrow_mut() = Some(s);
        Ok(ActiveStage {
            stage: (),
            guard: (),
            base: s.base,
            through: base,
            tail_at_head: false,
            install_version: InstallVersion {
                cursor: self.cursor.get(),
                local_revision: 0,
                known_committed_seq: s.required,
            },
        })
    }
    async fn checkpoint_page(
        &self,
        _: BaseRead,
    ) -> Result<ReadOutcome<VerifiedBasePage<()>>, SyncError> {
        self.note("base");
        self.reads.set(self.reads.get() + 1);
        self.bases
            .borrow_mut()
            .pop_front()
            .ok_or(SyncError::Unavailable)
    }
    async fn stage_page(&self, _: &(), p: VerifiedBasePage<()>) -> Result<(), SyncError> {
        self.note("stagebase");
        let mut saved = self.stage.borrow_mut();
        let s = saved.as_mut().ok_or(SyncError::Invalid)?;
        s.base = s.base.advance(
            p.base,
            p.expected_members,
            &p.sequences,
            p.next_member,
            p.has_more,
        )?;
        Ok(())
    }
    async fn checkpoint_delta(&self, _: &(), p: VerifiedPage<u64>) -> Result<(), SyncError> {
        self.note("stagetail");
        if self.capacity_blocked.get() {
            return Err(SyncError::CapacityExhausted);
        }
        let mut saved = self.stage.borrow_mut();
        let s = saved.as_mut().ok_or(SyncError::Invalid)?;
        s.through = p.next_after;
        s.head = !p.has_more;
        Ok(())
    }
    async fn checkpoint_discard(&self, _: ()) -> Result<(), SyncError> {
        self.note("discard");
        self.stage.borrow_mut().take();
        self.discards.set(self.discards.get() + 1);
        Ok(())
    }
    async fn install_checkpoint(&self, _: &(), _: ()) -> Result<(), SyncError> {
        self.note("install");
        let s = self.stage.borrow_mut().take().ok_or(SyncError::Invalid)?;
        let version = InstallVersion {
            cursor: self.cursor.get(),
            local_revision: 0,
            known_committed_seq: s.required,
        };
        assert!(install_decision(&(), &(), version, version, s.through, s.base.complete()).is_ok());
        self.cursor.set(s.through);
        self.installs.set(self.installs.get() + 1);
        Ok(())
    }
}
fn complete<T>(f: impl Future<Output = T>) -> T {
    let mut f = Box::pin(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("pure unit port completes immediately"),
    }
}
#[test]
fn capacity_probe_claims_and_handles_only_one_original() {
    for unknown in [false, true] {
        let p = Port::new();
        p.pending.set(16);
        p.unknown.set(unknown);
        let progress = complete(probe_capacity(&p)).unwrap();
        assert_eq!(
            progress.capacity_probe,
            Some(if unknown {
                CapacityProbeOutcome::Unknown
            } else {
                CapacityProbeOutcome::Receipt
            })
        );
        assert_eq!(progress.uploaded, usize::from(!unknown));
        assert_eq!(p.pending.get(), if unknown { 16 } else { 15 });
        assert!(!progress.caught_up && !progress.inbox_at_head);
        let log = p.log.borrow();
        assert_eq!(log.iter().filter(|v| *v == "claim_one").count(), 1);
        assert_eq!(log.iter().filter(|v| *v == "append").count(), 1);
        assert!(!log.iter().any(|v| v == "claim" || v.starts_with("read")));
    }
}
#[test]
fn capacity_probe_refusal_or_preparation_exhaustion_never_claims_recovery() {
    let p = Port::new();
    p.pending.set(16);
    p.append_refused.set(true);
    assert!(matches!(
        complete(probe_capacity(&p)),
        Err(SyncError::CapacityExhausted)
    ));
    assert_eq!(p.pending.get(), 16);
    assert!(!p.log.borrow().iter().any(|v| v == "ack"));
    let p = Port::new();
    let progress = complete(probe_capacity(&p)).unwrap();
    assert_eq!(
        progress.capacity_probe,
        Some(CapacityProbeOutcome::NoEligibleWork)
    );
    assert!(!p.log.borrow().iter().any(|v| v == "append"));
    let p = Port::new();
    p.pending.set(16);
    p.prereads.set(MAX_PULL_PAGES + 1);
    let progress = complete(probe_capacity(&p)).unwrap();
    assert_eq!(progress.capacity_probe, None);
    assert!(!p.log.borrow().iter().any(|v| v.starts_with("claim")));
}
fn hv(floor: u64, head: u64) -> HistoryVersion {
    HistoryVersion {
        floor,
        base: floor,
        head,
    }
}
fn page(
    cursor: u64,
    entries: usize,
    more: bool,
    h: HistoryVersion,
) -> ReadOutcome<VerifiedPage<u64>> {
    ReadOutcome::Page(VerifiedPage {
        contents: cursor,
        next_after: cursor,
        entries,
        has_more: more,
        history: Some(h),
    })
}
fn base(base: u64, seq: Vec<u64>, total: usize, more: bool) -> ReadOutcome<VerifiedBasePage<()>> {
    let next = seq.last().copied().unwrap_or(0);
    ReadOutcome::Page(VerifiedBasePage {
        contents: (),
        base,
        expected_members: total,
        sequences: seq,
        next_member: next,
        has_more: more,
    })
}
#[test]
fn typed_unknown_retains_pending_and_reads_without_reclaiming_terminal_family() {
    let p = Port::new();
    p.pending.set(1);
    p.unknown.set(true);
    p.pages.borrow_mut().push_back(page(0, 0, false, hv(0, 0)));
    let v = complete(reconcile(&p)).unwrap();
    assert_eq!(v.uploaded, 0);
    assert!(v.inbox_at_head && !v.caught_up);
    assert_eq!(p.pending.get(), 1);
    p.pages.borrow_mut().push_back(page(0, 0, false, hv(0, 0)));
    complete(reconcile(&p)).unwrap();
    assert_eq!(
        p.log
            .borrow()
            .iter()
            .filter(|x| x.as_str() == "append")
            .count(),
        1
    );
}
#[test]
fn frozen_base_tail_install_requires_ordinary_delta_before_freshness() {
    let p = Port::new();
    p.required.set(11);
    p.pages.borrow_mut().extend([
        ReadOutcome::Expired(hv(10, 11)),
        page(11, 1, false, hv(10, 11)),
        page(11, 0, false, hv(10, 11)),
    ]);
    p.bases
        .borrow_mut()
        .push_back(base(10, vec![4, 10], 2, false));
    let v = complete(reconcile_inbox(&p)).unwrap();
    assert_eq!((v.cursor, v.received), (11, 3));
    assert!(v.inbox_at_head && v.caught_up);
    let log = p.log.borrow();
    assert!(
        log.iter().position(|x| x == "install").unwrap()
            < log.iter().position(|x| x == "fresh").unwrap()
    );
    assert_eq!(p.reads.get(), 4);
    assert!(!log.iter().any(|x| x == "claim"));
}
#[test]
fn resume_stage_before_claim_and_keep_active_cursor_on_budget_exhaustion() {
    let p = Port::new();
    p.pending.set(1);
    *p.stage.borrow_mut() = Some(Saved {
        base: BaseProgress {
            base: 10,
            total: 1,
            received: 1,
            after_member: 10,
        },
        through: 10,
        head: false,
        required: 25,
    });
    p.prereads.set(2);
    for i in 1..=14 {
        p.pages
            .borrow_mut()
            .push_back(page(10 + i, 1, true, hv(10, 100)));
    }
    let v = complete(reconcile(&p)).unwrap();
    assert_eq!(v.cursor, 0);
    assert!(!v.inbox_at_head && !v.caught_up);
    assert_eq!(p.reads.get(), 16);
    assert_eq!(p.stage.borrow().as_ref().unwrap().through, 24);
    assert!(!p.log.borrow().iter().any(|x| x == "claim"));
    p.prereads.set(0);
    p.pages.borrow_mut().extend([
        page(25, 1, false, hv(10, 25)),
        page(25, 0, false, hv(10, 25)),
    ]);
    let v = complete(reconcile(&p)).unwrap();
    assert_eq!(v.cursor, 25);
    assert!(!v.caught_up);
    assert!(!p.log.borrow().iter().any(|x| x == "claim"));
}
#[test]
fn complete_old_base_valid_tail_survives_floor_change_until_real_gap() {
    let p = Port::new();
    *p.stage.borrow_mut() = Some(Saved {
        base: BaseProgress {
            base: 10,
            total: 0,
            received: 0,
            after_member: 0,
        },
        through: 12,
        head: false,
        required: 100,
    });
    p.pages.borrow_mut().extend([
        page(13, 1, true, hv(11, 100)),
        ReadOutcome::Expired(hv(20, 100)),
    ]);
    p.bases
        .borrow_mut()
        .push_back(ReadOutcome::Expired(hv(21, 100)));
    let v = complete(reconcile(&p)).unwrap();
    assert_eq!(v.cursor, 0);
    assert_eq!(p.discards.get(), 1);
    assert_eq!(p.installs.get(), 0);
    assert_eq!(p.reads.get(), 3);
    assert!(p.log.borrow().iter().any(|x| x == "stagetail"));
    assert!(!p.log.borrow().iter().any(|x| x == "claim"));
}
#[test]
fn complete_base10_through30_partial_installs_with_floor20_then_normal_delta() {
    let p = Port::new();
    *p.stage.borrow_mut() = Some(Saved {
        base: BaseProgress {
            base: 10,
            total: 1,
            received: 1,
            after_member: 10,
        },
        through: 30,
        head: false,
        required: 30,
    });
    p.pages
        .borrow_mut()
        .push_back(page(40, 10, false, hv(20, 40)));
    let v = complete(reconcile(&p)).unwrap();
    assert_eq!(v.cursor, 40);
    assert!(v.inbox_at_head && v.caught_up);
    assert_eq!(p.installs.get(), 1);
    assert_eq!(p.discards.get(), 0);
    assert_eq!(p.reads.get(), 1);
    assert_eq!(
        &p.log.borrow()[..3],
        &[
            "resume".to_string(),
            "install".to_string(),
            "read30".to_string()
        ]
    );
}
#[test]
fn incomplete_old_base_expiry_restarts_once_and_partial_installs_covered_tail() {
    let p = Port::new();
    p.required.set(30);
    *p.stage.borrow_mut() = Some(Saved {
        base: BaseProgress {
            base: 10,
            total: 1,
            received: 0,
            after_member: 0,
        },
        through: 10,
        head: false,
        required: 30,
    });
    p.bases.borrow_mut().extend([
        ReadOutcome::Expired(hv(20, 40)),
        base(20, vec![20], 1, false),
    ]);
    p.pages.borrow_mut().extend([
        page(30, 10, true, hv(20, 40)),
        page(40, 10, false, hv(20, 40)),
    ]);
    let v = complete(reconcile(&p)).unwrap();
    assert_eq!(v.cursor, 40);
    assert!(v.caught_up);
    assert_eq!(p.discards.get(), 1);
    assert_eq!(p.installs.get(), 1);
}
#[test]
fn real_head_validation_rejects_false_no_more_before_ingest() {
    let p = Port::new();
    p.pages.borrow_mut().push_back(page(1, 1, false, hv(0, 2)));
    assert!(matches!(
        complete(reconcile_inbox(&p)),
        Err(SyncError::Invalid)
    ));
    assert_eq!(p.cursor.get(), 0);
    assert_eq!(p.fresh.get(), 0);
}
#[test]
fn discovery_read_budget_is_not_reset_for_normal_delta() {
    let p = Port::new();
    p.prereads.set(2);
    for i in 1..=14 {
        p.pages.borrow_mut().push_back(page(i, 1, true, hv(0, 100)));
    }
    let v = complete(reconcile_inbox(&p)).unwrap();
    assert_eq!((p.reads.get(), v.cursor), (16, 14));
    assert!(!v.inbox_at_head);
}
#[test]
fn transport_failure_never_guesses_legacy_and_confirmed_v3_never_demotes() {
    let p = Port::new();
    p.mode.set(0);
    assert!(matches!(
        complete(reconcile(&p)),
        Err(SyncError::Unavailable)
    ));
    assert!(!p.log.borrow().iter().any(|x| x == "claim"));
    p.mode.set(1);
    assert!(matches!(complete(reconcile(&p)), Err(SyncError::Invalid)));
}
#[test]
fn oversized_claim_is_rejected_before_any_append() {
    let p = Port::new();
    p.pending.set(17);
    assert!(matches!(complete(reconcile(&p)), Err(SyncError::Invalid)));
    assert!(!p.log.borrow().iter().any(|x| x == "append"));
}
#[test]
fn legacy_expiration_never_resets_cursor_or_marks_freshness() {
    let p = Port::new();
    p.mode.set(1);
    *p.facts.borrow_mut() = WriterFacts {
        confirmed: None,
        legacy_v2_initialized: true,
    };
    p.cursor.set(7);
    p.pages.borrow_mut().push_back(ReadOutcome::LegacyExpired);
    assert!(matches!(
        complete(reconcile_inbox(&p)),
        Err(SyncError::Unavailable)
    ));
    assert_eq!(p.cursor.get(), 7);
    assert_eq!(p.fresh.get(), 0);
    assert_eq!(p.installs.get(), 0);
}
#[test]
fn offline_preparation_reuses_known_format_not_server_admission() {
    use nddev_device_sync_domain::DeviceId;
    let operation = || Operation {
        id: "new".into(),
        device: DeviceId::new("device").unwrap(),
        entity_kind: EntityKind::VaultRecord,
        entity_id: "record".into(),
        base_revision: 0,
        idempotency_key: "idem".into(),
        payload: EncryptedPayload {
            key_id: "key".into(),
            nonce: [0; 12],
            ciphertext: vec![0; 16],
        },
    };
    let current = || LocalWriterContext {
        authorized: true,
        actual_key: "key",
        cursor: 0,
        known_committed: 0,
    };
    let old = WriterFacts {
        confirmed: None,
        legacy_v2_initialized: true,
    };
    assert_eq!(
        prepare_offline_operation(
            operation(),
            Lifecycle {
                resolved_through_seq: 0
            },
            &old,
            current()
        )
        .unwrap()
        .version,
        OperationVersion::V2
    );
    assert!(
        prepare_offline_operation(
            operation(),
            Lifecycle {
                resolved_through_seq: 0
            },
            &WriterFacts::default(),
            current()
        )
        .is_err()
    );
    let v3 = WriterFacts {
        confirmed: Some(ConfirmedWriter {
            mode: WriterMode::V3,
            key_id: "key".into(),
            basis: 42,
        }),
        legacy_v2_initialized: true,
    };
    let v = prepare_offline_operation(
        operation(),
        Lifecycle {
            resolved_through_seq: 2,
        },
        &v3,
        LocalWriterContext {
            known_committed: 45,
            ..current()
        },
    )
    .unwrap();
    assert!(matches!(
        v.version,
        OperationVersion::V3 { basis_seq: 45, .. }
    ));
    assert!(v.operation.id.starts_with("v3:45:"));
    assert!(confirm_writer_facts(&v3, WriterMode::V2, "key", 46).is_err());
    assert!(confirm_writer_facts(&v3, WriterMode::V3, "other-key", 46).is_err());
    assert!(
        prepare_offline_operation(
            operation(),
            Lifecycle {
                resolved_through_seq: 0
            },
            &old,
            LocalWriterContext {
                authorized: false,
                ..current()
            }
        )
        .is_err()
    );
}

#[test]
fn complete_old_base_keeps_valid_new_floor_tail_then_partial_installs() {
    let p = Port::new();
    *p.stage.borrow_mut() = Some(Saved {
        base: BaseProgress {
            base: 10,
            total: 1,
            received: 1,
            after_member: 10,
        },
        through: 30,
        head: false,
        required: 40,
    });
    p.pages.borrow_mut().extend([
        page(35, 5, true, hv(20, 50)),
        page(40, 5, true, hv(20, 50)),
        page(50, 10, false, hv(20, 50)),
    ]);
    let v = complete(reconcile_inbox(&p)).unwrap();
    assert_eq!(v.cursor, 50);
    assert!(v.caught_up);
    assert_eq!(p.discards.get(), 0);
    assert_eq!(p.installs.get(), 1);
    assert_eq!(p.reads.get(), 3);
}
#[test]
fn recovery_restart_after_partial_install_still_uses_global_single_bound() {
    let p = Port::new();
    *p.stage.borrow_mut() = Some(Saved {
        base: BaseProgress {
            base: 10,
            total: 1,
            received: 1,
            after_member: 10,
        },
        through: 30,
        head: false,
        required: 30,
    });
    p.pages
        .borrow_mut()
        .push_back(ReadOutcome::Expired(hv(40, 50)));
    p.bases
        .borrow_mut()
        .push_back(ReadOutcome::Expired(hv(41, 50)));
    let v = complete(reconcile(&p)).unwrap();
    assert_eq!(v.cursor, 30);
    assert!(!v.inbox_at_head && !v.caught_up);
    assert_eq!(p.installs.get(), 1);
    assert_eq!(p.reads.get(), 2);
    assert!(!p.log.borrow().iter().any(|x| x == "claim"));
}
#[test]
fn stage_capacity_is_typed_failure_without_generic_busy_or_restarts() {
    let p = Port::new();
    p.capacity_blocked.set(true);
    *p.stage.borrow_mut() = Some(Saved {
        base: BaseProgress {
            base: 10,
            total: 1,
            received: 1,
            after_member: 10,
        },
        through: 30,
        head: false,
        required: 40,
    });
    p.pages
        .borrow_mut()
        .push_back(page(35, 5, true, hv(20, 50)));
    assert!(matches!(
        complete(reconcile(&p)),
        Err(SyncError::CapacityExhausted)
    ));
    assert_eq!(p.stage.borrow().as_ref().unwrap().through, 30);
    assert_eq!(p.discards.get(), 0);
    assert_eq!(p.installs.get(), 0);
    assert_eq!(p.fresh.get(), 0);
}
#[test]
fn through_below_new_floor_requires_restart_instead_of_partial_gap_install() {
    let p = Port::new();
    p.required.set(40);
    *p.stage.borrow_mut() = Some(Saved {
        base: BaseProgress {
            base: 10,
            total: 1,
            received: 1,
            after_member: 10,
        },
        through: 15,
        head: false,
        required: 40,
    });
    p.pages.borrow_mut().extend([
        ReadOutcome::Expired(hv(20, 50)),
        page(50, 30, false, hv(20, 50)),
        page(50, 0, false, hv(20, 50)),
    ]);
    p.bases.borrow_mut().push_back(base(20, vec![20], 1, false));
    let v = complete(reconcile(&p)).unwrap();
    assert_eq!(v.cursor, 50);
    assert!(v.caught_up);
    assert_eq!(p.discards.get(), 1);
    assert_eq!(p.installs.get(), 1);
}

#[test]
fn confirmed_v3_rejects_missing_capabilities_without_reads_or_uploads() {
    for mode in [1, 2] {
        let p = Port::new();
        p.mode.set(mode);
        p.facts.borrow_mut().legacy_v2_initialized = true;
        p.pending.set(2);
        p.prereads.set(3);
        assert!(matches!(complete(reconcile(&p)), Err(SyncError::Invalid)));
        assert_eq!(p.reads.get(), 0);
        assert_eq!(p.pending.get(), 2);
        assert_eq!(p.installs.get(), 0);
        assert!(p.log.borrow().is_empty());
        assert_eq!(
            p.facts.borrow().confirmed.as_ref().unwrap().mode,
            WriterMode::V3
        );
    }
}
