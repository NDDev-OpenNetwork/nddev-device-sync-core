use nddev_device_sync_domain::repositories::catalog::{
    observations::{projection::*, *},
    *,
};

fn input(data: ObservationData, at: u64) -> (ObservedTarget, u64) {
    let value = RepositoryObservation {
        source: ObservationSource {
            context: ObservationContext {
                principal: GithubAccountId::new(1).unwrap(),
                selection: CredentialSelection::new("credential".into(), 1, None).unwrap(),
                scan_id: "saved-scan".into(),
            },
            page: Some(1),
        },
        data,
    };
    (
        ObservedTarget {
            key: value.key(),
            version: TargetVersion {
                revision: 3,
                next_base: 3,
                pending_id: None,
                conflicted: false,
            },
            value: Some(value),
            history_cursor: 10,
        },
        at,
    )
}
fn repository(id: u64, owner: u64) -> (ObservedTarget, u64) {
    input(
        ObservationData::Repository {
            repository: RepositoryFact {
                id: RepositoryId::new(id).unwrap(),
                owner_id: GithubAccountId::new(owner).unwrap(),
                name: "project".into(),
                visibility: RepositoryVisibility::Private,
                archived: false,
                default_branch: Some("main".into()),
            },
        },
        100,
    )
}
fn owner(id: u64, kind: GithubOwnerKind) -> (ObservedTarget, u64) {
    input(
        ObservationData::Owner {
            owner: GithubOwner {
                id: GithubAccountId::new(id).unwrap(),
                kind,
                login: "same-observed-name".into(),
            },
        },
        90,
    )
}

#[test]
fn grouping_uses_stable_owner_ids_and_preserves_actual_account_kind_and_revision() {
    let mut pending = repository(u64::MAX, 8);
    pending.0.version.pending_id = Some("pending-edit".into());
    pending.0.version.conflicted = true;
    let groups = saved_page(vec![
        pending,
        owner(8, GithubOwnerKind::Organization),
        repository(2, 7),
        owner(7, GithubOwnerKind::User),
    ])
    .unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0].owner_id.value(), 7);
    assert_eq!(
        groups[0].owner.as_ref().unwrap().owner.kind,
        GithubOwnerKind::User
    );
    assert_eq!(
        groups[1].owner.as_ref().unwrap().owner.kind,
        GithubOwnerKind::Organization
    );
    assert_eq!(groups[1].repositories[0].repository.id.value(), u64::MAX);
    assert_eq!(
        groups[1].repositories[0].version.pending_id.as_deref(),
        Some("pending-edit")
    );
    assert!(groups[1].repositories[0].version.conflicted);
    assert_eq!(groups[1].repositories[0].observed_at_ms, 100);
    assert_eq!(groups[1].owner.as_ref().unwrap().observed_at_ms, 90);
}

#[test]
fn missing_owner_is_visible_without_inventing_a_personal_or_organization_profile() {
    let groups = saved_page(vec![repository(1, 7), repository(2, 7)]).unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].owner_id.value(), 7);
    assert!(groups[0].owner.is_none());
    assert_eq!(groups[0].repositories.len(), 2);
}

#[test]
fn invalid_duplicate_unrelated_and_over_budget_observations_are_refused() {
    assert!(saved_page(vec![repository(1, 7), repository(1, 7)]).is_err());
    assert!(saved_page(vec![repository(1, 7), owner(8, GithubOwnerKind::User)]).is_err());
    let mut wrong = repository(1, 7);
    wrong.0.key = ObservationKey::Repository(RepositoryId::new(2).unwrap());
    assert!(saved_page(vec![wrong]).is_err());
    let mut zero_time = repository(1, 7);
    zero_time.1 = 0;
    assert!(saved_page(vec![zero_time]).is_err());
    assert!(
        saved_page(
            (1..=REPOSITORIES_PER_PAGE as u64 + 1)
                .map(|id| repository(id, 7))
                .collect()
        )
        .is_err()
    );
    assert!(saved_page(vec![]).unwrap().is_empty());
}
