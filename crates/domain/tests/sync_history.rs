use nddev_device_sync_domain::{
    DeviceId,
    sync::history::*,
    sync::*,
    vault::{Record, Record3},
};
fn operation() -> Operation {
    Operation {
        id: "id".into(),
        device: DeviceId::new("device").unwrap(),
        entity_kind: EntityKind::VaultRecord,
        entity_id: "record".into(),
        base_revision: 0,
        idempotency_key: "key".into(),
        payload: EncryptedPayload {
            key_id: "payload-key".into(),
            nonce: [0; 12],
            ciphertext: vec![0; 16],
        },
    }
}
fn row(seq: u64, entity: &'static str, revision: Option<u64>, r: u64) -> RetainedMeta<'static> {
    RetainedMeta {
        sequence: seq,
        kind: EntityKind::VaultRecord,
        entity,
        decision: revision.map_or(
            Decision::Conflict {
                base_revision: 0,
                current_revision: 1,
            },
            |revision| Decision::Apply { revision },
        ),
        version: OperationVersion::V3 {
            basis_seq: seq - 1,
            lifecycle: Lifecycle {
                resolved_through_seq: r,
            },
        },
        request_bytes: 500,
        result_bytes: 150,
    }
}
fn history(head: u64) -> HistoryVersion {
    HistoryVersion {
        head,
        floor: 0,
        base: 0,
    }
}
#[test]
fn pressure_keeps_the_earliest_suffix_with_room_for_a_bounded_wave() {
    let rows = (1..=8)
        .map(|n| row(n, "shared", Some(n), 0))
        .collect::<Vec<_>>();
    let caps = RetentionCaps {
        rows: 8,
        ..RetentionCaps::default()
    };
    let next = row(9, "shared", Some(9), 0);
    let plan = append_retention_plan(&rows, next, history(8), caps, 2).unwrap();
    assert_eq!(plan.base, 4);
    assert_eq!(plan.keep, (4..=9).collect::<Vec<_>>());
    assert_eq!(plan.members, vec![4]);
    assert_eq!(plan.entities, 1);
    let published = HistoryVersion {
        head: 9,
        floor: plan.base,
        base: plan.base,
    };
    assert_eq!(
        admission(Lookup::Missing, next.version, published, false).unwrap(),
        Admission::New
    );
    assert_eq!(
        admission(Lookup::ExactOriginal, rows[3].version, published, false).unwrap(),
        Admission::ReplayOriginal
    );
    assert!(
        plan.base
            <= match next.version {
                OperationVersion::V3 { basis_seq, .. } => basis_seq,
                _ => unreachable!(),
            }
    );
}

#[test]
fn pressured_resolver_preserves_older_receipts_when_the_head_cut_is_unnecessary() {
    let mut rows = (1..=8)
        .map(|n| row(n, "shared", Some(n), 0))
        .collect::<Vec<_>>();
    rows.push(RetainedMeta {
        decision: Decision::Conflict {
            base_revision: 0,
            current_revision: 8,
        },
        ..row(9, "shared", None, 0)
    });
    let caps = RetentionCaps {
        rows: 9,
        ..RetentionCaps::default()
    };
    let resolver = row(10, "shared", Some(9), 9);
    let plan = append_retention_plan(&rows, resolver, history(9), caps, 2).unwrap();
    assert_eq!(plan.base, 4);
    assert_eq!(plan.keep, (4..=10).collect::<Vec<_>>());
    assert!(plan.keep.contains(&9)); // Exact conflict replay is still possible.
    assert!(matches!(
        append_retention_plan(&rows, row(10, "shared", Some(9), 8), history(9), caps, 2),
        Err(SyncError::Invalid)
    ));
    let failed = RetainedMeta {
        decision: Decision::Conflict {
            base_revision: 0,
            current_revision: 8,
        },
        ..resolver
    };
    assert!(matches!(
        append_retention_plan(&rows, failed, history(9), caps, 2),
        Err(SyncError::KeyConflict)
    ));
    assert!(matches!(
        append_retention_plan(
            &rows,
            RetainedMeta {
                version: row(10, "shared", None, 0).version,
                ..failed
            },
            history(9),
            caps,
            2
        ),
        Err(SyncError::CapacityExhausted)
    ));
}

#[test]
fn pressure_reserve_never_blocks_the_only_available_resolution() {
    let rows = [
        row(1, "a", Some(1), 0),
        row(2, "a", None, 0),
        row(3, "b", Some(1), 0),
        row(4, "c", Some(1), 0),
        row(5, "d", Some(1), 0),
        row(6, "e", Some(1), 0),
        row(7, "f", Some(1), 0),
        row(8, "g", Some(1), 0),
    ];
    let plan = append_retention_plan(
        &rows,
        row(9, "a", Some(2), 2),
        history(8),
        RetentionCaps {
            rows: 8,
            ..RetentionCaps::default()
        },
        2,
    )
    .unwrap();
    assert_eq!(plan.base, 9);
    assert_eq!(plan.keep, (3..=9).collect::<Vec<_>>());
    assert_eq!(plan.entities, 7);
}

#[test]
fn pressure_reserves_encoded_bytes_without_relaxing_the_hard_budget() {
    let full = |n| RetainedMeta {
        request_bytes: MAX_OPERATION_BYTES as u32,
        result_bytes: MAX_RESULT_BYTES as u32,
        ..row(n, "shared", Some(n), 0)
    };
    let rows = (1..=8).map(full).collect::<Vec<_>>();
    let cost = full(1).cost();
    let plan = append_retention_plan(
        &rows,
        full(9),
        history(8),
        RetentionCaps {
            bytes: 8 * cost,
            ..RetentionCaps::default()
        },
        1,
    )
    .unwrap();
    assert_eq!(plan.base, 3);
    assert_eq!(plan.bytes, 7 * cost);
    assert_eq!(plan.keep, (3..=9).collect::<Vec<_>>());
}
#[test]
fn v2_exact_aad_and_v3_metadata_before_encryption_share_one_validator() {
    let mut op = operation();
    op.payload.ciphertext.clear();
    let old = VersionedOperation {
        operation: op.clone(),
        version: OperationVersion::V2,
    };
    let scope = AadScope {
        origin: "https://example.invalid/",
        tenant: "tenant",
        user: "owner",
    };
    let expected=br#"["NDS-RECORD-V2","https://example.invalid/","tenant","owner","device","vault_record","record","id",0,"payload-key"]"#;
    assert_eq!(
        serde_json::to_vec(&old.aad(scope, "payload-key").unwrap()).unwrap(),
        expected
    );
    assert!(old.validate(100).is_err());
    let fresh = VersionedOperation::qualify(
        op,
        2,
        Lifecycle {
            resolved_through_seq: 2,
        },
    )
    .unwrap();
    assert!(fresh.aad(scope, "payload-key").is_ok());
    assert!(fresh.validate(100).is_err());
    let new_expected=br#"["NDS-RECORD-V3",3,"https://example.invalid/","tenant","owner","device","vault_record","record","v3:2:id",0,"payload-key","v3:2:key",2,{"resolved_through_seq":2}]"#;
    assert_eq!(
        serde_json::to_vec(&fresh.aad(scope, "payload-key").unwrap()).unwrap(),
        new_expected
    );
}
#[test]
fn admission_exact_original_is_before_expired_basis_or_capacity_and_never_manufactures_effect() {
    let h = HistoryVersion {
        head: 7,
        floor: 7,
        base: 7,
    };
    let old = OperationVersion::V3 {
        basis_seq: 0,
        lifecycle: Lifecycle {
            resolved_through_seq: 0,
        },
    };
    assert_eq!(
        admission(Lookup::ExactOriginal, old, h, false).unwrap(),
        Admission::ReplayOriginal
    );
    assert_eq!(
        admission(Lookup::Missing, old, h, false).unwrap(),
        Admission::Unknown(UnknownOutcome::BasisExpired)
    );
    assert_eq!(
        admission(Lookup::Missing, OperationVersion::V2, h, false).unwrap(),
        Admission::Unknown(UnknownOutcome::LegacyMissing)
    );
    assert_eq!(
        admission(Lookup::Collision, old, h, false),
        Err(SyncError::Idempotency)
    );
}
#[test]
fn qualified_basis_is_immutable_and_legacy_ids_are_not_reinterpreted() {
    for b in 0..=16 {
        for other in 0..=16 {
            let mut v = VersionedOperation::qualify(
                operation(),
                b,
                Lifecycle {
                    resolved_through_seq: 0,
                },
            )
            .unwrap();
            v.version = OperationVersion::V3 {
                basis_seq: other,
                lifecycle: Lifecycle {
                    resolved_through_seq: 0,
                },
            };
            assert_eq!(v.validate(100).is_ok(), b == other);
        }
    }
    let mut o = operation();
    o.id = "v3:999:legacy".into();
    let mut v = VersionedOperation {
        operation: o,
        version: OperationVersion::V2,
    };
    assert!(v.validate(100).is_ok());
    v.operation.entity_kind = EntityKind::RepositoryState;
    assert!(v.validate(100).is_err());
}
#[test]
fn retained_original_and_unresolved_rows_remain_mandatory_at_capacity() {
    let rows = [
        row(1, "a", Some(1), 0),
        row(2, "a", None, 0),
        row(3, "b", Some(1), 0),
        row(4, "b", None, 0),
    ];
    assert_eq!(
        retention_plan(
            &rows,
            None,
            history(4),
            4,
            RetentionCaps {
                rows: 3,
                ..RetentionCaps::default()
            }
        )
        .err(),
        Some(SyncError::CapacityExhausted)
    );
    let plan = retention_plan(&rows, None, history(4), 4, RetentionCaps::default()).unwrap();
    assert_eq!(plan.keep, vec![1, 2, 3, 4]);
}
#[test]
fn atomic_full_owner_final_cost_proves_progress_and_keeps_uncovered_rows() {
    let mut count = 0;
    for conflicts in 1..=16 {
        for covered in 1..=conflicts {
            for foreign in 0..=3 {
                let mut rows = vec![row(1, "a", Some(1), 0)];
                for n in 0..conflicts {
                    rows.push(row(n + 2, "a", None, 0));
                }
                let ids = ["b", "c", "d"];
                for id in ids.iter().take(foreign) {
                    rows.push(row(rows.len() as u64 + 1, id, Some(1), 0));
                    rows.push(row(rows.len() as u64 + 1, id, None, 0));
                }
                let h = history(rows.len() as u64);
                let caps = RetentionCaps {
                    rows: rows.len() as u64,
                    bytes: rows.iter().map(|r| r.cost()).sum(),
                    entities: 4096,
                };
                let resolver = row(h.head + 1, "a", Some(2), covered + 1);
                let witness = (2..=covered + 1).collect::<Vec<_>>();
                let p = atomic_resolution(&rows, resolver, &witness, h, h, caps).unwrap();
                assert_eq!(p.base, h.head + 1);
                assert_eq!(p.keep.len(), rows.len() - covered as usize);
                for r in &rows {
                    assert_eq!(
                        p.keep.contains(&r.sequence),
                        r.sequence != 1 && !witness.contains(&r.sequence)
                    );
                }
                assert!(p.bytes <= caps.bytes);
                assert_eq!(p.members, p.keep);
                count += 1;
            }
        }
    }
    assert_eq!(count, 544);
    println!("CANONICAL_ATOMIC_META_CASES={count}");
}
#[test]
fn failed_cas_bad_proof_new_floor_and_shortfall_produce_no_mutation_plan() {
    let rows = [
        row(1, "a", Some(1), 0),
        row(2, "a", None, 0),
        row(3, "a", None, 0),
    ];
    let original = rows;
    let h = history(3);
    let resolver = row(4, "a", Some(2), 3);
    assert_eq!(
        atomic_resolution(&rows, resolver, &[3], h, h, RetentionCaps::default()).err(),
        Some(SyncError::Invalid)
    );
    assert_eq!(
        atomic_resolution(&rows, resolver, &[2, 3, 3], h, h, RetentionCaps::default()).err(),
        Some(SyncError::Invalid)
    );
    let mut conflict = resolver;
    conflict.decision = Decision::Conflict {
        base_revision: 0,
        current_revision: 1,
    };
    assert_eq!(
        atomic_resolution(&rows, conflict, &[2, 3], h, h, RetentionCaps::default()).err(),
        Some(SyncError::KeyConflict)
    );
    let mut stale = h;
    stale.base = 1;
    assert!(
        atomic_resolution(&rows, resolver, &[2, 3], stale, h, RetentionCaps::default()).is_err()
    );
    assert!(
        atomic_resolution(
            &rows,
            resolver,
            &[2, 3],
            h,
            h,
            RetentionCaps {
                bytes: resolver.cost() - 1,
                ..RetentionCaps::default()
            }
        )
        .is_err()
    );
    assert!(
        retention_plan(
            &rows,
            Some(resolver),
            history(4),
            5,
            RetentionCaps::default()
        )
        .is_err()
    );
    assert!(
        rows.iter()
            .zip(original)
            .all(|(a, b)| a.sequence == b.sequence && a.cost() == b.cost())
    );
}
#[test]
fn sparse_base_and_contiguous_suffix_are_different_contracts() {
    let rows = [
        row(1, "a", Some(1), 0),
        row(2, "a", None, 0),
        row(3, "a", Some(2), 2),
        row(4, "b", Some(1), 0),
    ];
    let p = retention_plan(&rows, None, history(4), 3, RetentionCaps::default()).unwrap();
    assert_eq!(p.members, vec![3]);
    assert_eq!(p.keep, vec![3, 4]);
    let sparse = [rows[2], rows[3]];
    let h = HistoryVersion {
        head: 4,
        floor: 3,
        base: 3,
    };
    assert!(retention_plan(&sparse, None, h, 3, RetentionCaps::default()).is_ok());
    assert!(retention_plan(&sparse, None, history(4), 3, RetentionCaps::default()).is_err());
}
#[test]
fn same_cap_entity_tombstones_are_not_freed_by_history_cleanup() {
    let rows = [row(1, "a", Some(1), 0), row(2, "b", Some(1), 0)];
    assert_eq!(
        retention_plan(
            &rows,
            None,
            history(2),
            2,
            RetentionCaps {
                entities: 1,
                ..RetentionCaps::default()
            }
        )
        .err(),
        Some(SyncError::CapacityExhausted)
    );
}
#[test]
fn install_covers_direct_ack_horizon_and_retains_existing_fence_guard() {
    let before = InstallVersion {
        cursor: 2,
        local_revision: 8,
        known_committed_seq: 7,
    };
    let guard = ("existing-account-fence", "key-id", "original-scope");
    assert!(install_decision(&guard, &guard, before, before, 6, true).is_err());
    assert!(install_decision(&guard, &guard, before, before, 7, true).is_ok());
    assert!(
        install_decision(
            &guard,
            &("changed-fence", "key-id", "original-scope"),
            before,
            before,
            7,
            true
        )
        .is_err()
    );
    let mut changed = before;
    changed.local_revision += 1;
    assert!(install_decision(&guard, &guard, before, changed, 7, true).is_err());
    assert!(install_decision(&guard, &guard, before, before, 7, false).is_err());
    let current = row(7, "a", Some(3), 2);
    assert_eq!(
        applied_projection(current, row(4, "a", Some(2), 0)),
        Ok(AppliedProjection::IgnoreEarlier)
    );
    assert_eq!(
        applied_projection(current, current),
        Ok(AppliedProjection::VerifySameOriginal)
    );
    assert!(applied_projection(current, row(6, "a", Some(4), 2)).is_err());
    assert!(applied_projection(current, row(8, "a", Some(4), 1)).is_err());
}
#[test]
fn record3_has_no_inner_watermark_and_legacy_records_still_validate() {
    let bytes = r#"{"version":3,"deleted":false,"title":"Owned","username":"","secret":"value"}"#;
    let record: Record3 = serde_json::from_str(bytes).unwrap();
    record.validate().unwrap();
    assert!(
        serde_json::from_str::<Record3>(
            &bytes.replace("\"version\":3", "\"version\":3,\"resolved_through_seq\":0")
        )
        .is_err()
    );
    let legacy: Record =
        serde_json::from_str(&bytes.replace("\"version\":3", "\"version\":2")).unwrap();
    legacy.validate().unwrap();
    let unsupported: Record = serde_json::from_str(bytes).unwrap();
    assert!(unsupported.validate().is_err());
}

#[test]
fn max_metadata_owner_is_full_at_both_real_logical_caps_without_body_copies() {
    let mut rows = Vec::with_capacity(MAX_OPERATIONS as usize);
    for n in 1..=MAX_OPERATIONS {
        let mut r = row(n, "a", if n == 1 { Some(1) } else { None }, 0);
        r.request_bytes = 8117;
        r.result_bytes = 150;
        rows.push(r);
    }
    let bytes: u64 = rows.iter().map(|r| r.cost()).sum();
    assert_eq!(bytes, MAX_STORED_BYTES);
    let h = history(MAX_OPERATIONS);
    let mut resolver = row(MAX_OPERATIONS + 1, "a", Some(2), MAX_OPERATIONS);
    resolver.request_bytes = 8117;
    resolver.result_bytes = 150;
    let witness = (2..=MAX_OPERATIONS).collect::<Vec<_>>();
    let result =
        atomic_resolution(&rows, resolver, &witness, h, h, RetentionCaps::default()).unwrap();
    assert_eq!(result.keep, vec![MAX_OPERATIONS + 1]);
    assert_eq!(result.bytes, 16384);
    println!(
        "MAX_METADATA_ROWS={} LOGICAL_BYTES={} ROW_META_BYTES={}",
        rows.len(),
        bytes,
        std::mem::size_of::<RetainedMeta<'_>>()
    );
    // Sizes are trusted metadata from an adapter, not a PG/full-ciphertext gate.
}

#[test]
fn sparse_progress_does_not_satisfy_contiguous_delta_or_install_incomplete_base() {
    let start = BaseProgress {
        base: 10,
        total: 3,
        received: 0,
        after_member: 0,
    };
    let first = start.advance(10, 3, &[2, 5], 5, true).unwrap();
    assert!(!first.complete());
    let finished = first.advance(10, 3, &[10], 10, false).unwrap();
    assert!(finished.complete());
    for (token, seqs, next, more) in [
        (11, vec![10], 10, false),
        (10, vec![5, 10], 10, false),
        (10, vec![], 5, false),
        (10, vec![10], 9, false),
        (10, vec![10], 10, true),
    ] {
        assert!(first.advance(token, 3, &seqs, next, more).is_err());
        assert_eq!(first.received, 2);
    }
    assert!(delta_progress(0, &[2, 5, 10], 10, false).is_err());
    assert!(delta_progress(10, &[11, 12], 12, false).is_ok());
    assert!(delta_progress(10, &[11, 13], 13, false).is_err());
}

#[test]
fn review_f1_suffix_applied_cannot_regress_r_at_any_cut() {
    let original = [row(3, "a", Some(2), 2)];
    let incoming = row(4, "a", Some(3), 0);
    let before = HistoryVersion {
        head: 3,
        floor: 3,
        base: 3,
    };
    assert_eq!(
        admission(Lookup::Missing, incoming.version, before, false).unwrap(),
        Admission::New
    );
    let current = HistoryVersion { head: 4, ..before };
    for cut in [3, 4] {
        assert_eq!(
            retention_plan(
                &original,
                Some(incoming),
                current,
                cut,
                RetentionCaps::default()
            )
            .err(),
            Some(SyncError::Invalid)
        );
        assert_eq!(
            retention_plan(
                &[original[0], incoming],
                None,
                current,
                cut,
                RetentionCaps::default()
            )
            .err(),
            Some(SyncError::Invalid)
        );
    }
    let carried = row(4, "a", Some(3), 2);
    assert_eq!(
        retention_plan(
            &original,
            Some(carried),
            current,
            3,
            RetentionCaps::default()
        )
        .unwrap()
        .keep,
        vec![3, 4]
    );
    assert_eq!(
        retention_plan(
            &original,
            Some(carried),
            current,
            4,
            RetentionCaps::default()
        )
        .unwrap()
        .keep,
        vec![4]
    );
    let suffix = [
        original[0],
        row(4, "a", Some(3), 3),
        row(5, "a", Some(4), 2),
    ];
    assert!(
        retention_plan(
            &suffix,
            None,
            HistoryVersion { head: 5, ..before },
            3,
            RetentionCaps::default()
        )
        .is_err()
    );
}

#[test]
fn review_f2_meaningful_resolution_is_exactly_derived_from_known_conflicts() {
    let one = [row(1, "a", Some(1), 0)];
    let h = history(1);
    assert_eq!(
        atomic_resolution(
            &one,
            row(2, "a", Some(2), 1),
            &[],
            h,
            h,
            RetentionCaps::default()
        )
        .err(),
        Some(SyncError::Invalid)
    );
    let rows = [one[0], row(2, "a", None, 0), row(3, "b", Some(1), 0)];
    let h = history(3);
    assert_eq!(
        atomic_resolution(
            &rows,
            row(4, "a", Some(2), 3),
            &[2],
            h,
            h,
            RetentionCaps::default()
        )
        .err(),
        Some(SyncError::Invalid)
    );
    let exact = atomic_resolution(
        &rows,
        row(4, "a", Some(2), 2),
        &[2],
        h,
        h,
        RetentionCaps::default(),
    )
    .unwrap();
    assert_eq!(exact.keep, vec![3, 4]);
    assert_eq!(exact.base, 4);
}

#[test]
fn review_f3_original_utf8_byte_caps_are_inherited_and_exact() {
    for (request, result, valid) in [
        (MAX_OPERATION_BYTES, MAX_RESULT_BYTES, true),
        (MAX_OPERATION_BYTES + 1, MAX_RESULT_BYTES, false),
        (MAX_OPERATION_BYTES, MAX_RESULT_BYTES + 1, false),
        (0, MAX_RESULT_BYTES, false),
        (MAX_OPERATION_BYTES, 0, false),
    ] {
        assert_eq!(validate_original_lengths(request, result).is_ok(), valid);
        let mut metadata = row(1, "a", Some(1), 0);
        metadata.request_bytes = request as u32;
        metadata.result_bytes = result as u32;
        assert_eq!(
            retention_plan(&[metadata], None, history(1), 1, RetentionCaps::default()).is_ok(),
            valid
        );
    }
    let at_cap = "é".repeat(MAX_RESULT_BYTES / 2);
    let over_cap = format!("{at_cap}x");
    assert_eq!(at_cap.len(), MAX_RESULT_BYTES);
    assert_eq!(over_cap.len(), MAX_RESULT_BYTES + 1);
    assert!(over_cap.chars().count() < MAX_RESULT_BYTES);
    assert!(validate_original_lengths(1, at_cap.len()).is_ok());
    assert!(validate_original_lengths(1, over_cap.len()).is_err());
}

#[test]
fn explicit_resolution_uses_only_observed_conflicts_and_carries_committed_authority() {
    let previous = Lifecycle {
        resolved_through_seq: 4,
    };
    assert_eq!(
        resolution_lifecycle(previous, &[7, 5], 100)
            .unwrap()
            .resolved_through_seq,
        7
    );
    assert_eq!(resolution_lifecycle(previous, &[], 100).unwrap(), previous);
    assert_eq!(
        resolution_lifecycle(previous, &[2, 3], 100).unwrap(),
        previous
    );
    for witnesses in [&[0][..], &[101][..], &[5, 5][..]] {
        assert_eq!(
            resolution_lifecycle(previous, witnesses, 100),
            Err(SyncError::Invalid)
        );
    }
    assert_eq!(
        resolution_lifecycle(previous, &[5], 3),
        Err(SyncError::Invalid)
    );
    assert_eq!(
        resolution_lifecycle(previous, &[], MAX_REVISION + 1),
        Err(SyncError::Invalid)
    );
    assert_eq!(
        resolution_lifecycle(previous, &vec![5; MAX_OPERATIONS as usize + 1], 100),
        Err(SyncError::Invalid)
    );
}

#[test]
fn authenticated_legacy_decision_carries_only_from_the_same_actual_applied_head() {
    let mut old = VersionedOperation {
        operation: operation(),
        version: OperationVersion::V2,
    };
    old.operation.base_revision = 1;
    let head = AppliedHeadMeta::verified_v2(&old, 100, 2, 101).unwrap();
    let make = |basis, revision| {
        let mut op = operation();
        op.base_revision = revision;
        op.payload.ciphertext.clear();
        VersionedOperation::qualify(
            op,
            basis,
            Lifecycle {
                resolved_through_seq: 0,
            },
        )
        .unwrap()
    };
    let next = head.inherit_legacy_resolution(100, make(102, 2)).unwrap();
    assert_eq!(next.lifecycle().resolved_through_seq, 100);
    assert!(next.operation.payload.ciphertext.is_empty());
    assert!(head.inherit_legacy_resolution(101, make(102, 2)).is_err());
    assert!(head.inherit_legacy_resolution(100, make(100, 2)).is_err());
    assert!(head.inherit_legacy_resolution(100, make(102, 1)).is_err());
    let mut foreign = make(102, 2);
    foreign.operation.entity_id = "other".into();
    assert!(head.inherit_legacy_resolution(100, foreign).is_err());
    let mut encrypted = make(102, 2);
    encrypted.operation.payload.ciphertext = vec![0; 16];
    assert!(head.inherit_legacy_resolution(100, encrypted).is_err());
    let mut resolved = make(102, 2);
    resolved.version = OperationVersion::V3 {
        basis_seq: 102,
        lifecycle: Lifecycle {
            resolved_through_seq: 102,
        },
    };
    assert_eq!(
        head.inherit_legacy_resolution(100, resolved)
            .unwrap()
            .lifecycle()
            .resolved_through_seq,
        102
    );
}

#[test]
fn legacy_carry_under_pressure_keeps_newer_conflicts_and_current_witness_rules() {
    let mut previous = row(101, "a", Some(2), 0);
    previous.version = OperationVersion::V2;
    let mut old_conflict = row(2, "a", None, 0);
    old_conflict.version = OperationVersion::V2;
    let mut later = row(102, "a", None, 0);
    later.decision = Decision::Conflict {
        base_revision: 1,
        current_revision: 2,
    };
    let rows = [old_conflict, row(99, "b", Some(1), 0), previous, later];
    let h = HistoryVersion {
        head: 102,
        floor: 101,
        base: 101,
    };
    let plan = atomic_resolution(
        &rows,
        row(103, "a", Some(3), 100),
        &[2],
        h,
        h,
        RetentionCaps::default(),
    )
    .unwrap();
    assert_eq!(plan.keep, vec![99, 102, 103]);
    let mut unseen_commit = row(103, "a", Some(3), 100);
    unseen_commit.version = OperationVersion::V3 {
        basis_seq: 100,
        lifecycle: Lifecycle {
            resolved_through_seq: 100,
        },
    };
    let mut first = row(1, "a", Some(1), 0);
    first.version = OperationVersion::V2;
    let complete = [first, rows[0], rows[1], previous, later];
    let old_basis = HistoryVersion {
        head: 102,
        floor: 100,
        base: 100,
    };
    assert!(
        atomic_resolution(
            &complete,
            unseen_commit,
            &[2],
            old_basis,
            old_basis,
            RetentionCaps::default()
        )
        .is_err()
    );
    assert!(
        atomic_resolution(
            &rows,
            row(103, "a", Some(3), 101),
            &[2],
            h,
            h,
            RetentionCaps::default()
        )
        .is_err()
    );
    assert!(
        atomic_resolution(
            &rows,
            row(103, "a", Some(3), 102),
            &[2],
            h,
            h,
            RetentionCaps::default()
        )
        .is_err()
    );
    assert!(
        atomic_resolution(
            &rows,
            row(103, "a", Some(3), 100),
            &[],
            h,
            h,
            RetentionCaps::default()
        )
        .is_err()
    );
    let no_old_conflict = [rows[1], previous, later];
    let carried = atomic_resolution(
        &no_old_conflict,
        row(103, "a", Some(3), 100),
        &[],
        h,
        h,
        RetentionCaps::default(),
    )
    .unwrap();
    assert_eq!(carried.keep, vec![99, 102, 103]);
    let mut current = rows;
    current[2].version = OperationVersion::V3 {
        basis_seq: 100,
        lifecycle: Lifecycle {
            resolved_through_seq: 0,
        },
    };
    assert!(
        atomic_resolution(
            &current,
            row(103, "a", Some(3), 100),
            &[2],
            h,
            h,
            RetentionCaps::default()
        )
        .is_err()
    );
}
