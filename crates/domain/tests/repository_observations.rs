//! Pure synthetic domain histories. Not provider/crypto/store acceptance.
use nddev_device_sync_domain::modules::ModuleError;
use nddev_device_sync_domain::{
    DeviceId,
    repositories::catalog::{observations::*, *},
    state::{Snapshot, State},
    sync::{
        Decision, EncryptedPayload, EntityKind, MAX_PLAIN_BYTES, MAX_REVISION, Operation, Receipt,
        history::{Lifecycle, VersionedOperation},
    },
};
fn context(scan: &str) -> ObservationContext {
    ObservationContext {
        principal: GithubAccountId::new(1).unwrap(),
        selection: CredentialSelection::new("credential".into(), 1, None).unwrap(),
        scan_id: scan.into(),
    }
}

#[test]
fn stored_observation_ids_roundtrip_without_aliases_or_scope_ambiguity() {
    for key in [
        ObservationKey::Owner(GithubAccountId::new(u64::MAX).unwrap()),
        ObservationKey::Repository(RepositoryId::new(19).unwrap()),
        ObservationKey::Scope {
            principal: GithubAccountId::new(7).unwrap(),
            record_ref: "credential:with:colons".into(),
        },
    ] {
        assert_eq!(ObservationKey::parse(&key.entity_id()).unwrap(), key);
    }
    for id in [
        "github:repo:0",
        "github:repo:01",
        "github:repo:+1",
        "github:owner:18446744073709551616",
        "gitlab:repo:1",
        "github:scope:1:01:x",
        "github:scope:1:2:x",
        "github:scope:01:1:x",
        "github:scope:1:0:",
        "github:scope:1:3:a/b",
        "github:owner:1:extra",
    ] {
        assert!(ObservationKey::parse(id).is_err(), "{id}");
    }
    assert!(ObservationKey::parse(&format!("github:scope:1:1024:{}", "x".repeat(1024))).is_err());
}
fn repo(id: u64, owner: u64, name: &str, scan: &str) -> RepositoryObservation {
    RepositoryObservation {
        source: ObservationSource {
            context: context(scan),
            page: Some(1),
        },
        data: ObservationData::Repository {
            repository: RepositoryFact {
                id: RepositoryId::new(id).unwrap(),
                owner_id: GithubAccountId::new(owner).unwrap(),
                name: name.into(),
                visibility: RepositoryVisibility::Private,
                archived: false,
                default_branch: Some("main".into()),
            },
        },
    }
}
fn version(rev: u64) -> TargetVersion {
    TargetVersion {
        revision: rev,
        next_base: rev,
        pending_id: None,
        conflicted: false,
    }
}
fn target(v: &RepositoryObservation, rev: u64) -> ObservedTarget {
    ObservedTarget {
        key: v.key(),
        version: version(rev),
        value: Some(v.clone()),
        history_cursor: 20,
    }
}
fn capture(v: RepositoryObservation, rev: u64) -> Candidate {
    Capture::before_read(v.key(), version(rev))
        .unwrap()
        .confirm(v)
        .unwrap()
}
fn operation(c: &Candidate, id: &str) -> VersionedOperation {
    VersionedOperation::qualify(
        Operation {
            id: id.into(),
            device: DeviceId::new("device").unwrap(),
            entity_kind: EntityKind::RepositoryState,
            entity_id: c.observation().key().entity_id(),
            base_revision: c.expected().next_base,
            idempotency_key: id.into(),
            payload: EncryptedPayload {
                key_id: "key".into(),
                nonce: [0; 12],
                ciphertext: vec![0; 16],
            },
        },
        0,
        Lifecycle {
            resolved_through_seq: 0,
        },
    )
    .unwrap()
}
#[test]
fn ids_codec_scope_keys_and_snapshot_binding_are_validated() {
    assert!(serde_json::from_str::<RepositoryId>("0").is_err());
    assert!(serde_json::from_str::<GithubAccountId>("0").is_err());
    for id in [1, u64::MAX] {
        let value = RepositoryId::new(id).unwrap();
        assert_eq!(
            serde_json::from_str::<RepositoryId>(&serde_json::to_string(&value).unwrap()).unwrap(),
            value
        );
    }
    let value = repo(9, 2, "name", "scan");
    let snapshot = Snapshot {
        schema_version: 2,
        observed_at_ms: 1,
        data: State::Repository {
            observation: value.clone(),
        },
    };
    assert!(
        snapshot
            .validate(
                &DeviceId::new("device").unwrap(),
                EntityKind::RepositoryState,
                &value.key().entity_id()
            )
            .is_ok()
    );
    assert!(
        snapshot
            .validate(
                &DeviceId::new("device").unwrap(),
                EntityKind::AccountState,
                &value.key().entity_id()
            )
            .is_err()
    );
    assert!(
        snapshot
            .validate(
                &DeviceId::new("device").unwrap(),
                EntityKind::RepositoryState,
                "github:repo:10"
            )
            .is_err()
    );
    let a = ObservationKey::Scope {
        principal: GithubAccountId::new(1).unwrap(),
        record_ref: "2:x".into(),
    };
    let b = ObservationKey::Scope {
        principal: GithubAccountId::new(12).unwrap(),
        record_ref: "x".into(),
    };
    assert_ne!(a.entity_id(), b.entity_id());
    let mut invalid = value;
    invalid.source.context.selection =
        serde_json::from_str(r#"{"record_ref":"../bad","revision":0,"pending_id":null}"#).unwrap();
    assert!(invalid.validate().is_err());
}
#[test]
fn material_equality_excludes_times_sources_but_not_ids_or_facts() {
    let a = repo(9, 2, "same", "a");
    let mut b = repo(9, 2, "same", "b");
    b.source.context.principal = GithubAccountId::new(3).unwrap();
    b.source.page = Some(64);
    assert!(a.material_eq(&b));
    assert_ne!(a, b);
    let s1 = Snapshot {
        schema_version: 2,
        observed_at_ms: 10,
        data: State::Repository {
            observation: a.clone(),
        },
    };
    let s2 = Snapshot {
        schema_version: 2,
        observed_at_ms: 20,
        data: State::Repository {
            observation: b.clone(),
        },
    };
    assert!(s1.material_eq(&s2));
    assert!(!a.material_eq(&repo(10, 2, "same", "a")));
    assert!(!a.material_eq(&repo(9, 3, "same", "a")));
    assert!(!a.material_eq(&repo(9, 2, "renamed", "a")));
    let PublicationDecision::Noop = capture(b.clone(), 0)
        .decide(&target(&a, 8), Some(&b.source.context))
        .unwrap()
    else {
        panic!("same material value is not a new write")
    };
}
#[test]
fn stale_provider_result_cannot_be_stamped_with_new_target_revision() {
    let old = repo(9, 2, "old", "old-scan");
    let newer = repo(9, 3, "newer", "other-scan");
    let candidate = capture(old.clone(), 0);
    assert!(matches!(
        candidate
            .clone()
            .decide(&target(&newer, 1), Some(&old.source.context))
            .unwrap(),
        PublicationDecision::ReRead
    ));
    let mut forged_rebase = operation(&candidate, "operation");
    forged_rebase.operation.base_revision = 1;
    assert!(candidate.bind_dispatched(forged_rebase, 100).is_err());
    assert!(matches!(
        capture(old.clone(), 0)
            .decide(&target(&old, 0), None)
            .unwrap(),
        PublicationDecision::SourceChanged
    ));
    let mut changed = context("old-scan");
    changed.selection = CredentialSelection::new("credential".into(), 2, None).unwrap();
    assert!(matches!(
        capture(old.clone(), 0)
            .decide(&target(&old, 0), Some(&changed))
            .unwrap(),
        PublicationDecision::SourceChanged
    ));
}
#[test]
fn lost_and_late_receipts_preserve_original_operation_and_newer_current() {
    let observation = repo(9, 2, "first", "scan");
    let candidate = capture(observation, 0);
    let op = operation(&candidate, "original");
    let original = op.clone();
    let dispatched = candidate.bind_dispatched(op, 100).unwrap();
    for _ in 0..10 {
        assert!(matches!(
            dispatched.settle(None, 0).unwrap(),
            ReceiptAction::ReplayOriginal
        ));
        assert!(dispatched.operation() == &original);
    }
    let receipt = Receipt {
        operation_id: "v3:0:original".into(),
        server_seq: 1,
        decision: Decision::Apply { revision: 1 },
    };
    assert!(matches!(
        dispatched.settle(Some(&receipt), 3).unwrap(),
        ReceiptAction::Applied {
            revision: 1,
            preserve_current: true,
            ..
        }
    ));
    let wrong = Receipt {
        operation_id: "other".into(),
        server_seq: 1,
        decision: Decision::Apply { revision: 1 },
    };
    assert!(dispatched.settle(Some(&wrong), 0).is_err());
    assert!(matches!(
        dispatched.settle(Some(&receipt), 0).unwrap(),
        ReceiptAction::Applied {
            revision: 1,
            preserve_current: false,
            ..
        }
    ));
}
#[test]
fn conflict_requires_catchup_then_fresh_input_not_old_rebase() {
    let old = repo(9, 2, "old", "old-scan");
    let current = repo(9, 3, "winner", "winner");
    let c = capture(old.clone(), 0);
    let op = operation(&c, "loser");
    let d = c.bind_dispatched(op, 100).unwrap();
    let r = Receipt {
        operation_id: "v3:0:loser".into(),
        server_seq: 10,
        decision: Decision::Conflict {
            base_revision: 0,
            current_revision: 1,
        },
    };
    let ReceiptAction::Conflict(k) = d.settle(Some(&r), 0).unwrap() else {
        panic!()
    };
    let mut late = target(&current, 1);
    late.history_cursor = 9;
    assert!(matches!(k.review(&late).unwrap(), ConflictAction::CatchUp));
    let ReceiptAction::Conflict(k) = d.settle(Some(&r), 1).unwrap() else {
        panic!()
    };
    let ConflictAction::FreshRead(read) = k.review(&target(&current, 1)).unwrap() else {
        panic!()
    };
    assert!(read.confirm(old.clone()).is_err());
    let ReceiptAction::Conflict(k) = d.settle(Some(&r), 1).unwrap() else {
        panic!()
    };
    let ConflictAction::FreshRead(read) = k.review(&target(&current, 1)).unwrap() else {
        panic!()
    };
    let fresh = repo(9, 4, "actually-rechecked", "fresh-scan");
    let candidate = read.confirm(fresh.clone()).unwrap();
    let ResolutionDecision::Write { candidate, guard } = candidate
        .decide(&target(&current, 1), Some(&fresh.source.context))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(candidate.expected().revision, 1);
    assert!(guard.matches(&target(&current, 1)));
    let mut moved = target(&current, 1);
    moved.history_cursor += 1;
    assert!(!guard.matches(&moved));
    let mut wrong_key = target(&current, 1);
    wrong_key.key = ObservationKey::Repository(RepositoryId::new(99).unwrap());
    assert!(!guard.matches(&wrong_key));
}
#[test]
fn equal_conflict_still_requires_a_current_guard_for_explicit_resolution() {
    let value = repo(9, 2, "same", "scan");
    let c = capture(value.clone(), 0);
    let op = operation(&c, "loser");
    let d = c.bind_dispatched(op, 100).unwrap();
    let r = Receipt {
        operation_id: "v3:0:loser".into(),
        server_seq: 10,
        decision: Decision::Conflict {
            base_revision: 0,
            current_revision: 1,
        },
    };
    let ReceiptAction::Conflict(k) = d.settle(Some(&r), 1).unwrap() else {
        panic!()
    };
    let ConflictAction::Equivalent(guard) = k.review(&target(&value, 1)).unwrap() else {
        panic!()
    };
    assert!(guard.matches(&target(&value, 1)));
    assert_eq!(guard.through_seq, 10);
    let mut changed = target(&value, 1);
    changed.version.pending_id = Some("successor".into());
    assert!(!guard.matches(&changed));
}
#[test]
fn max_field_payloads_fit_actual_existing_plain_cap_without_inner_lifecycle() {
    let mut v = repo(u64::MAX, u64::MAX, &"\"".repeat(400), &"s".repeat(128));
    v.source.context.selection =
        CredentialSelection::new("c".repeat(128), MAX_REVISION, Some("p".repeat(128))).unwrap();
    if let ObservationData::Repository { repository } = &mut v.data {
        repository.default_branch = Some("\\".repeat(1024));
    }
    let snapshot = Snapshot {
        schema_version: 2,
        observed_at_ms: MAX_REVISION,
        data: State::Repository { observation: v },
    };
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    assert!(bytes.len() <= MAX_PLAIN_BYTES);
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(!text.contains("basis"));
    assert!(!text.contains("resolved_through"));
    let decoded: Snapshot = serde_json::from_slice(&bytes).unwrap();
    assert!(
        decoded
            .validate(
                &DeviceId::new("device").unwrap(),
                EntityKind::RepositoryState,
                &format!("github:repo:{}", u64::MAX)
            )
            .is_ok()
    );
    println!("max_repository_snapshot_bytes={}", bytes.len());
}
#[test]
fn rename_transfer_recycled_names_and_boundary_counterexamples() {
    let mut stored = repo(9, 2, "initial", "initial");
    let mut rev = 1;
    for n in 0..100 {
        let fresh = repo(9, 2 + n % 4, &format!("name-{n}"), &format!("scan-{n}"));
        let before = target(&stored, rev);
        let decision = capture(fresh.clone(), rev)
            .decide(&before, Some(&fresh.source.context))
            .unwrap();
        let PublicationDecision::Write(c) = decision else {
            panic!()
        };
        assert_eq!(c.observation().key(), stored.key());
        stored = c.observation().clone();
        rev += 1;
        assert!(matches!(
            capture(fresh.clone(), 0)
                .decide(&target(&stored, rev), Some(&fresh.source.context))
                .unwrap(),
            PublicationDecision::Noop
        ));
    }
    let recycled = repo(
        10,
        2,
        if let ObservationData::Repository { repository } = &stored.data {
            &repository.name
        } else {
            panic!()
        },
        "recycled",
    );
    assert_ne!(stored.key(), recycled.key());
    assert!(!stored.material_eq(&recycled));
    let mut bad = repo(9, 2, &"x".repeat(401), "boundary");
    assert!(bad.validate().is_err());
    if let ObservationData::Repository { repository } = &mut bad.data {
        repository.name = "ok".into();
        repository.default_branch = Some("x".repeat(1025));
    }
    assert!(bad.validate().is_err());
    let mut wrong = version(4);
    wrong.next_base = 3;
    assert!(wrong.validate().is_err());
    let mut scope = RepositoryObservation {
        source: ObservationSource {
            context: context("scope"),
            page: None,
        },
        data: ObservationData::ScopeScan {
            scan: ScopeScan {
                outcome: TraversalOutcome::Complete,
                pages: 64,
                repositories: 1600,
                last_complete: None,
            },
        },
    };
    assert!(scope.validate().is_err());
    if let ObservationData::ScopeScan { scan } = &mut scope.data {
        scan.last_complete = Some(CompleteTraversal {
            pages: 64,
            repositories: 1600,
            observed_at_ms: 1,
            scan_id: "scope".into(),
        });
    }
    assert!(scope.validate().is_ok());
}
#[test]
fn fresh_resolution_still_cannot_override_a_newer_result_or_pending_successor() {
    let old = repo(9, 2, "old", "old");
    let winner = repo(9, 3, "winner", "winner");
    let c = capture(old, 0);
    let op = operation(&c, "loser");
    let d = c.bind_dispatched(op, 100).unwrap();
    let r = Receipt {
        operation_id: "v3:0:loser".into(),
        server_seq: 10,
        decision: Decision::Conflict {
            base_revision: 0,
            current_revision: 1,
        },
    };
    let ReceiptAction::Conflict(k) = d.settle(Some(&r), 1).unwrap() else {
        panic!()
    };
    let ConflictAction::FreshRead(read) = k.review(&target(&winner, 1)).unwrap() else {
        panic!()
    };
    let fresh = repo(9, 4, "fresh", "fresh");
    let candidate = read.confirm(fresh.clone()).unwrap();
    let newer = target(&repo(9, 5, "even-newer", "later"), 2);
    assert!(matches!(
        candidate
            .decide(&newer, Some(&fresh.source.context))
            .unwrap(),
        ResolutionDecision::ReRead
    ));
}
#[test]
fn owner_scope_actual_codec_boundaries_and_unchanged_complete_times() {
    let source = ObservationSource {
        context: ObservationContext {
            principal: GithubAccountId::new(u64::MAX).unwrap(),
            selection: CredentialSelection::new(
                "c".repeat(128),
                MAX_REVISION,
                Some("p".repeat(128)),
            )
            .unwrap(),
            scan_id: "s".repeat(128),
        },
        page: Some(64),
    };
    let owner = RepositoryObservation {
        source: source.clone(),
        data: ObservationData::Owner {
            owner: GithubOwner {
                id: GithubAccountId::new(u64::MAX).unwrap(),
                kind: GithubOwnerKind::Organization,
                login: "\"".repeat(256),
            },
        },
    };
    let first = ScopeScan {
        outcome: TraversalOutcome::Complete,
        pages: 64,
        repositories: 1600,
        last_complete: Some(CompleteTraversal {
            pages: 64,
            repositories: 1600,
            observed_at_ms: 10,
            scan_id: "before".into(),
        }),
    };
    let mut second = first.clone();
    second.last_complete.as_mut().unwrap().observed_at_ms = 99;
    second.last_complete.as_mut().unwrap().scan_id = "after".into();
    let a = RepositoryObservation {
        source: source.clone(),
        data: ObservationData::ScopeScan { scan: first },
    };
    let b = RepositoryObservation {
        source: ObservationSource {
            context: ObservationContext {
                scan_id: "after".into(),
                ..source.context.clone()
            },
            page: None,
        },
        data: ObservationData::ScopeScan { scan: second },
    };
    assert!(a.material_eq(&b));
    let mut max_scope = a;
    if let ObservationData::ScopeScan { scan } = &mut max_scope.data {
        scan.outcome = TraversalOutcome::Failed(ModuleError::UnsupportedPlatform);
        let last = scan.last_complete.as_mut().unwrap();
        last.observed_at_ms = MAX_REVISION;
        last.scan_id = "q".repeat(128);
    }
    for (name, value) in [("owner", owner), ("scope", max_scope)] {
        let snap = Snapshot {
            schema_version: 2,
            observed_at_ms: MAX_REVISION,
            data: State::Repository {
                observation: value.clone(),
            },
        };
        let encoded = serde_json::to_vec(&snap).unwrap();
        assert!(encoded.len() <= MAX_PLAIN_BYTES);
        let decoded: Snapshot = serde_json::from_slice(&encoded).unwrap();
        assert!(
            decoded
                .validate(
                    &DeviceId::new("device").unwrap(),
                    EntityKind::RepositoryState,
                    &value.key().entity_id()
                )
                .is_ok()
        );
        println!("max_{name}_snapshot_bytes={}", encoded.len());
    }
}

#[test]
fn equal_scope_counts_under_a_replacement_credential_require_a_new_observation() {
    let old = RepositoryObservation {
        source: ObservationSource {
            context: context("before"),
            page: None,
        },
        data: ObservationData::ScopeScan {
            scan: ScopeScan {
                outcome: TraversalOutcome::Complete,
                pages: 1,
                repositories: 1,
                last_complete: Some(CompleteTraversal {
                    pages: 1,
                    repositories: 1,
                    observed_at_ms: 10,
                    scan_id: "before".into(),
                }),
            },
        },
    };
    let mut fresh = old.clone();
    fresh.source.context.selection =
        CredentialSelection::new("credential".into(), 2, None).unwrap();
    fresh.source.context.scan_id = "after".into();
    assert_eq!(old.key(), fresh.key());
    assert!(!old.material_eq(&fresh));
    assert!(matches!(
        capture(fresh.clone(), 1)
            .decide(&target(&old, 1), Some(&fresh.source.context))
            .unwrap(),
        PublicationDecision::Write(_)
    ));
    let fact = repo(1, 1, "same-fact", "before");
    let mut other_source = fact.clone();
    other_source.source.context = fresh.source.context;
    assert!(fact.material_eq(&other_source));
}

#[test]
fn retained_conflict_restores_without_fabricating_the_old_local_capture() {
    let old = repo(9, 2, "old", "old-scan");
    let candidate = Capture::before_read(
        old.key(),
        TargetVersion {
            revision: 3,
            next_base: 5,
            pending_id: Some("old-predecessor".into()),
            conflicted: false,
        },
    )
    .unwrap()
    .confirm(old.clone())
    .unwrap();
    let original = operation(&candidate, "retained");
    let receipt = Receipt {
        operation_id: original.operation.id.clone(),
        server_seq: 10,
        decision: Decision::Conflict {
            base_revision: 5,
            current_revision: 7,
        },
    };
    drop(candidate);
    let decoded: RepositoryObservation =
        serde_json::from_slice(&serde_json::to_vec(&old).unwrap()).unwrap();
    let restored = KnownConflict::restore(decoded, &original, 100, &receipt).unwrap();
    let winner = repo(9, 3, "winner", "winner-scan");
    let current = target(&winner, 7);
    let read = restored.fresh_read(&current).unwrap().unwrap();
    assert!(read.confirm(old.clone()).is_err());
    let fresh = repo(9, 4, "fresh-provider-value", "fresh-scan");
    let read = KnownConflict::restore(old.clone(), &original, 100, &receipt)
        .unwrap()
        .fresh_read(&current)
        .unwrap()
        .unwrap();
    let ResolutionDecision::Write { candidate, guard } = read
        .confirm(fresh.clone())
        .unwrap()
        .decide(&current, Some(&fresh.source.context))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(candidate.expected(), &current.version);
    assert_eq!(guard.through_seq, 10);
    assert!(guard.matches(&current));
    let mut behind = current;
    behind.history_cursor = 9;
    assert!(
        KnownConflict::restore(old.clone(), &original, 100, &receipt)
            .unwrap()
            .fresh_read(&behind)
            .unwrap()
            .is_none()
    );
    let wrong_receipt = Receipt {
        operation_id: "different-original".into(),
        server_seq: 10,
        decision: Decision::Conflict {
            base_revision: 5,
            current_revision: 7,
        },
    };
    assert!(KnownConflict::restore(old.clone(), &original, 100, &wrong_receipt).is_err());
    let applied = Receipt {
        operation_id: original.operation.id.clone(),
        server_seq: 10,
        decision: Decision::Apply { revision: 6 },
    };
    assert!(KnownConflict::restore(old.clone(), &original, 100, &applied).is_err());
    assert!(
        KnownConflict::restore(repo(10, 2, "other", "old-scan"), &original, 100, &receipt).is_err()
    );
    let legacy = VersionedOperation {
        operation: original.operation,
        version: nddev_device_sync_domain::sync::history::OperationVersion::V2,
    };
    assert!(KnownConflict::restore(old, &legacy, 100, &receipt).is_err());
}

#[test]
fn a_retained_equal_receipt_can_require_fresh_evidence_for_its_whole_family() {
    let old = repo(9, 2, "same", "old-scan");
    let original = operation(&capture(old.clone(), 0), "equal");
    let receipt = Receipt {
        operation_id: original.operation.id.clone(),
        server_seq: 10,
        decision: Decision::Conflict {
            base_revision: 0,
            current_revision: 1,
        },
    };
    let mut current = target(&old, 1);
    current.version.conflicted = true;
    current.version.pending_id = Some("blocked-successor".into());
    let read = KnownConflict::restore(old.clone(), &original, 100, &receipt)
        .unwrap()
        .fresh_read(&current)
        .unwrap()
        .unwrap();
    assert!(read.confirm(old.clone()).is_err());
    let fresh = repo(9, 2, "same", "fresh-scan");
    let read = KnownConflict::restore(old, &original, 100, &receipt)
        .unwrap()
        .fresh_read(&current)
        .unwrap()
        .unwrap();
    let ResolutionDecision::Equivalent(guard) = read
        .confirm(fresh.clone())
        .unwrap()
        .decide(&current, Some(&fresh.source.context))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        guard.version.pending_id.as_deref(),
        Some("blocked-successor")
    );
    current.version.pending_id = Some("later-intent".into());
    assert!(!guard.matches(&current));
}

#[test]
fn a_pending_original_behind_the_committed_head_is_preserved_without_rebasing_it() {
    let old = repo(9, 2, "pending", "old-scan");
    let original = operation(&capture(old.clone(), 0), "old-original");
    let receipt = Receipt {
        operation_id: original.operation.id.clone(),
        server_seq: 10,
        decision: Decision::Conflict {
            base_revision: 0,
            current_revision: 1,
        },
    };
    let mut current = target(&repo(9, 3, "committed", "peer-scan"), 1);
    current.version.next_base = 0;
    current.version.pending_id = Some("unsent-local-intent".into());
    current.version.conflicted = true;
    current.version.validate().unwrap();
    let read = KnownConflict::restore(old, &original, 100, &receipt)
        .unwrap()
        .fresh_read(&current)
        .unwrap()
        .unwrap();
    let fresh = repo(9, 4, "provider-confirmed", "fresh-scan");
    let ResolutionDecision::Write { candidate, guard } = read
        .confirm(fresh.clone())
        .unwrap()
        .decide(&current, Some(&fresh.source.context))
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(candidate.expected().next_base, 0);
    assert_eq!(guard.resolution_base(), 1);
    assert_eq!(original.operation.base_revision, 0);
    assert!(guard.matches(&current));
    current.version.pending_id = None;
    assert!(current.version.validate().is_err());
}

#[test]
fn restored_and_live_receipts_must_follow_the_original_admission_basis() {
    let value = repo(9, 2, "value", "scan");
    let candidate = capture(value.clone(), 0);
    let mut inner = operation(&candidate, "template").operation;
    inner.id = "later-basis".into();
    inner.idempotency_key = "later-basis".into();
    let original = VersionedOperation::qualify(
        inner,
        5,
        Lifecycle {
            resolved_through_seq: 0,
        },
    )
    .unwrap();
    let dispatched = candidate.bind_dispatched(original.clone(), 100).unwrap();
    for sequence in [4, 5] {
        let conflict = Receipt {
            operation_id: original.operation.id.clone(),
            server_seq: sequence,
            decision: Decision::Conflict {
                base_revision: 0,
                current_revision: 1,
            },
        };
        assert!(KnownConflict::restore(value.clone(), &original, 100, &conflict).is_err());
        assert!(dispatched.settle(Some(&conflict), 1).is_err());
        let applied = Receipt {
            operation_id: original.operation.id.clone(),
            server_seq: sequence,
            decision: Decision::Apply { revision: 1 },
        };
        assert!(dispatched.settle(Some(&applied), 1).is_err());
    }
    let actual = Receipt {
        operation_id: original.operation.id.clone(),
        server_seq: 6,
        decision: Decision::Conflict {
            base_revision: 0,
            current_revision: 1,
        },
    };
    assert!(KnownConflict::restore(value, &original, 100, &actual).is_ok());
    assert!(matches!(
        dispatched.settle(Some(&actual), 1).unwrap(),
        ReceiptAction::Conflict(_)
    ));
}
