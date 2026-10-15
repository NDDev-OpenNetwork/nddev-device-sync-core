//! Pure synthetic pages/history only. No provider, store or transport success.
use nddev_device_sync_application::repositories::catalog::{
    ReadGithubCatalogPage, observations::*,
};
use nddev_device_sync_domain::{
    modules::ModuleError,
    repositories::catalog::{observations::*, *},
};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    future::Future,
    task::{Context, Poll, Waker},
};
struct PageInputs {
    raw: RefCell<Option<ProviderRepositoryPage>>,
    log: RefCell<Vec<&'static str>>,
    version: Cell<u64>,
    mutate_during_read: bool,
}
impl ReadGithubCatalogPage for PageInputs {
    type Error = ModuleError;
    type Cancellation = ();
    fn read_page(
        &self,
        _: &CatalogPageRequest,
        _: &(),
    ) -> impl Future<Output = Result<ProviderRepositoryPage, ModuleError>> {
        self.log.borrow_mut().push("provider");
        if self.mutate_during_read {
            self.version.set(1);
        }
        std::future::ready(self.raw.borrow_mut().take().ok_or(ModuleError::Unavailable))
    }
}
impl ReadObservationBaselines for PageInputs {
    fn observation_baselines(
        &self,
    ) -> impl Future<Output = Result<Vec<(ObservationKey, TargetVersion)>, ModuleError>> {
        self.log.borrow_mut().push("baseline");
        std::future::ready(Ok(if self.mutate_during_read {
            vec![(
                ObservationKey::Repository(RepositoryId::new(1).unwrap()),
                TargetVersion {
                    revision: self.version.get(),
                    next_base: self.version.get(),
                    pending_id: None,
                    conflicted: false,
                },
            )]
        } else {
            vec![]
        }))
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    let mut f = std::pin::pin!(future);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("pure input must be ready"),
    }
}
fn selection() -> CredentialSelection {
    CredentialSelection::new("credential".into(), 0, None).unwrap()
}
fn raw(start: u64, count: usize, more: bool) -> ProviderRepositoryPage {
    ProviderRepositoryPage {
        principal: GithubOwner {
            id: GithubAccountId::new(1).unwrap(),
            kind: GithubOwnerKind::User,
            login: "user".into(),
        },
        repositories: (start..start + count as u64)
            .map(|id| RepositorySummary {
                id: RepositoryId::new(id).unwrap(),
                owner: GithubOwner {
                    id: GithubAccountId::new(id + 1000).unwrap(),
                    kind: GithubOwnerKind::Organization,
                    login: format!("owner-{id}"),
                },
                name: format!("repo-{id}"),
                visibility: RepositoryVisibility::Private,
                archived: false,
                default_branch: Some("main".into()),
            })
            .collect(),
        observed_at_ms: 1,
        has_more: more,
    }
}
fn prepared_pages() -> Vec<PreparedPage> {
    let mut cursor = None;
    let mut all = Vec::new();
    for n in 0..64 {
        let value = raw(n * 25 + 1, 25, n < 63);
        let input = PageInputs {
            raw: RefCell::new(Some(value)),
            log: RefCell::new(vec![]),
            version: Cell::new(0),
            mutate_during_read: false,
        };
        let prepared = run(observation_page(
            &input,
            selection(),
            cursor.as_ref(),
            "scan".into(),
            &(),
        ))
        .unwrap();
        cursor = prepared.next_cursor();
        all.push(prepared);
    }
    all
}

#[test]
fn observation_scan_returns_its_actual_bound_continuation() {
    let pages = prepared_pages();
    let next = pages[0].next_cursor().unwrap();
    let request = CatalogPageRequest::new(selection(), Some(&next)).unwrap();
    assert_eq!(request.page(), 2);
    assert_eq!(
        request.expected_principal(),
        Some(pages[0].context.principal)
    );
    let changed = CredentialSelection::new("different".into(), 1, None).unwrap();
    assert!(CatalogPageRequest::new(changed, Some(&next)).is_err());
    assert!(pages.last().unwrap().next_cursor().is_none());
}
fn apply(
    page: &PreparedPage,
    state: &mut BTreeMap<ObservationKey, RepositoryObservation>,
) -> usize {
    let mut writes = 0;
    for c in &page.candidates {
        let key = c.observation().key();
        let current = ObservedTarget {
            key: key.clone(),
            version: if state.contains_key(&key) {
                TargetVersion {
                    revision: 1,
                    next_base: 1,
                    pending_id: None,
                    conflicted: false,
                }
            } else {
                TargetVersion::absent()
            },
            value: state.get(&key).cloned(),
            history_cursor: 1,
        };
        match c.clone().decide(&current, Some(&page.context)).unwrap() {
            PublicationDecision::Noop => (),
            PublicationDecision::Write(v) => {
                state.insert(key, v.observation().clone());
                writes += 1;
            }
            _ => panic!("pure initial import needs no synthetic conflict"),
        }
    }
    writes
}
#[test]
fn full1600_eight_permutations_and_duplicate_pages_normalize_without_more_writes() {
    let started = std::time::Instant::now();
    let pages = prepared_pages();
    for seed in 0..8u64 {
        let mut order = (0..64).collect::<Vec<usize>>();
        let mut r = seed + 1;
        for i in (1..order.len()).rev() {
            r = r.wrapping_mul(6364136223846793005).wrapping_add(1);
            order.swap(i, (r as usize) % (i + 1));
        }
        let mut state = BTreeMap::new();
        let mut progress = Traversal::new(pages[0].context.clone()).unwrap();
        let mut writes = 0;
        for &i in &order {
            writes += apply(&pages[i], &mut state);
            progress.accept(&pages[i]).unwrap();
            progress.accept(&pages[i]).unwrap();
            assert_eq!(apply(&pages[i], &mut state), 0);
        }
        assert_eq!(writes, 3201);
        assert_eq!(state.len(), 3201);
        let summary = progress.summary(None, None, 100).unwrap();
        assert!(matches!(summary.outcome, TraversalOutcome::Complete));
        assert_eq!(summary.repositories, 1600);
        assert_eq!(summary.pages, 64);
        for id in 1..=1600 {
            let key = ObservationKey::Repository(RepositoryId::new(id).unwrap());
            let ObservationData::Repository { repository } = &state[&key].data else {
                panic!()
            };
            assert!(state.contains_key(&ObservationKey::Owner(repository.owner_id)));
        }
    }
    println!(
        "pure_full_range:8 permutations,1600 repos,1601 owners,duplicate pages0extra writes,cpu_us={}",
        started.elapsed().as_micros()
    );
}
#[test]
fn baseline_is_taken_before_the_read_and_late_mutation_requires_reread() {
    let input = PageInputs {
        raw: RefCell::new(Some(raw(1, 1, false))),
        log: RefCell::new(vec![]),
        version: Cell::new(0),
        mutate_during_read: true,
    };
    let page = run(observation_page(
        &input,
        selection(),
        None,
        "scan".into(),
        &(),
    ))
    .unwrap();
    assert_eq!(*input.log.borrow(), vec!["baseline", "provider"]);
    let candidate = page
        .candidates
        .iter()
        .find(|v| matches!(v.observation().data, ObservationData::Repository { .. }))
        .unwrap();
    assert_eq!(candidate.expected().revision, 0);
    let mut newer = candidate.observation().clone();
    if let ObservationData::Repository { repository } = &mut newer.data {
        repository.name = "newer".into();
    }
    let now = ObservedTarget {
        key: newer.key(),
        version: TargetVersion {
            revision: 1,
            next_base: 1,
            pending_id: None,
            conflicted: false,
        },
        value: Some(newer),
        history_cursor: 2,
    };
    assert!(matches!(
        candidate.clone().decide(&now, Some(&page.context)).unwrap(),
        PublicationDecision::ReRead
    ));
}
#[test]
fn missing_pages_page_limit_and_source_replacement_never_claim_complete() {
    let pages = prepared_pages();
    let mut progress = Traversal::new(pages[0].context.clone()).unwrap();
    progress.accept(&pages[63]).unwrap();
    assert!(matches!(
        progress.summary(None, None, 10).unwrap().outcome,
        TraversalOutcome::Partial
    ));
    for p in &pages[..63] {
        progress.accept(p).unwrap();
    }
    let prior = progress.summary(None, None, 11).unwrap();
    let mut partial = Traversal::new(pages[0].context.clone()).unwrap();
    partial.accept(&pages[0]).unwrap();
    let prior_observation = RepositoryObservation {
        source: ObservationSource {
            context: pages[0].context.clone(),
            page: None,
        },
        data: ObservationData::ScopeScan {
            scan: prior.clone(),
        },
    };
    let failed = partial
        .summary(Some(ModuleError::Cancelled), Some(&prior_observation), 12)
        .unwrap();
    assert_eq!(failed.last_complete, prior.last_complete);
    assert!(matches!(
        failed.outcome,
        TraversalOutcome::Failed(ModuleError::Cancelled)
    ));
    let mut bad = pages[0].clone();
    bad.repository_ids = vec![RepositoryId::new(99).unwrap()];
    assert!(partial.accept(&bad).is_err());
    bad.context.scan_id = "late-other-scan".into();
    assert!(partial.accept(&bad).is_err());
    let mut limit = Traversal::new(pages[0].context.clone()).unwrap();
    for p in &pages {
        let mut mark = p.clone();
        mark.has_more = true;
        limit.accept(&mark).unwrap();
    }
    assert!(matches!(
        limit.summary(None, None, 13).unwrap().outcome,
        TraversalOutcome::LimitReached
    ));
}
#[test]
fn partial32_window_and_capacity_preserve_old_and_already_verified_facts() {
    let page = prepared_pages().remove(0);
    let mut state = BTreeMap::new();
    apply(&page, &mut state);
    let before = state.clone();
    assert_eq!(stage_count(50, 32, 1024), 0);
    assert_eq!(stage_count(50, 31, 7), 1);
    assert_eq!(stage_count(50, 0, 0), 0);
    assert_eq!(stage_count(50, 0, 1024), 32);
    assert_eq!(state, before); // no delete/reset action exists in the candidate API
    let mut prefix = BTreeMap::new();
    for c in page.candidates.iter().take(32) {
        prefix.insert(c.observation().key(), c.observation().clone());
    }
    let kept = prefix.clone();
    for c in page.candidates.iter().skip(32) {
        let t = ObservedTarget {
            key: c.observation().key(),
            version: TargetVersion::absent(),
            value: None,
            history_cursor: 0,
        };
        assert!(matches!(
            c.clone().decide(&t, None).unwrap(),
            PublicationDecision::SourceChanged
        ));
    }
    assert_eq!(prefix, kept);
}
#[test]
fn prior_complete_is_bound_to_existing_scope_wrapper_not_an_unscoped_scan() {
    let pages = prepared_pages();
    let mut completed = Traversal::new(pages[0].context.clone()).unwrap();
    for page in &pages {
        completed.accept(page).unwrap();
    }
    let prior = completed.summary(None, None, 10).unwrap();
    let wrapper = RepositoryObservation {
        source: ObservationSource {
            context: pages[0].context.clone(),
            page: None,
        },
        data: ObservationData::ScopeScan {
            scan: prior.clone(),
        },
    };
    let mut partial = Traversal::new(pages[0].context.clone()).unwrap();
    partial.accept(&pages[0]).unwrap();
    assert_eq!(
        partial
            .summary(Some(ModuleError::Cancelled), Some(&wrapper), 11)
            .unwrap()
            .last_complete,
        prior.last_complete
    );
    for changed in 0..3 {
        let mut other = wrapper.clone();
        match changed {
            0 => other.source.context.principal = GithubAccountId::new(2).unwrap(),
            1 => {
                other.source.context.selection =
                    CredentialSelection::new("other-ref".into(), 0, None).unwrap()
            }
            _ => {
                other.source.context.selection =
                    CredentialSelection::new("credential".into(), 1, Some("changed-pending".into()))
                        .unwrap()
            }
        };
        assert!(
            partial
                .summary(Some(ModuleError::Cancelled), Some(&other), 11)
                .is_err()
        );
    }
    // A different prior flight in the same exact scope is legitimate history.
    let mut older = wrapper;
    older.source.context.scan_id = "previous-flight".into();
    assert!(partial.summary(None, Some(&older), 11).is_ok());
}
