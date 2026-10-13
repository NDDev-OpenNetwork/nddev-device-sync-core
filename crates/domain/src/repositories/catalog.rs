//! One transient authenticated GitHub page for NdsClient. No secret, wire,
//! persistent registry, filesystem placement or Git mutation authority.
use crate::{modules::ModuleError, sync::MAX_REVISION, valid_identifier};
use std::collections::{BTreeMap, BTreeSet};

pub const REPOSITORIES_PER_PAGE: usize = 25;
pub const MAX_CATALOG_PAGES: u8 = 64;

/// Existing vault revision and pending operation identity, not a second counter.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialSelection {
    record_ref: String,
    revision: u64,
    pending_id: Option<String>,
}
impl CredentialSelection {
    pub fn new(
        record_ref: String,
        revision: u64,
        pending_id: Option<String>,
    ) -> Result<Self, ModuleError> {
        if !valid_identifier(&record_ref)
            || revision > MAX_REVISION
            || pending_id.as_ref().is_some_and(|id| !valid_identifier(id))
        {
            return Err(ModuleError::InvalidInput);
        }
        Ok(Self {
            record_ref,
            revision,
            pending_id,
        })
    }
    pub fn record_ref(&self) -> &str {
        &self.record_ref
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn pending_id(&self) -> Option<&str> {
        self.pending_id.as_deref()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RepositoryId(u64);
impl RepositoryId {
    pub fn new(value: u64) -> Result<Self, ModuleError> {
        if value == 0 {
            return Err(ModuleError::InvalidResponse);
        }
        Ok(Self(value))
    }
    pub fn value(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GithubAccountId(u64);
impl GithubAccountId {
    pub fn new(value: u64) -> Result<Self, ModuleError> {
        if value == 0 {
            return Err(ModuleError::InvalidResponse);
        }
        Ok(Self(value))
    }
    pub fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GithubOwnerKind {
    User,
    Organization,
}
#[derive(Clone, PartialEq, Eq)]
pub struct GithubOwner {
    pub id: GithubAccountId,
    pub kind: GithubOwnerKind,
    pub login: String,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RepositoryVisibility {
    Public,
    Private,
    Internal,
}
#[derive(Clone)]
pub struct RepositorySummary {
    pub id: RepositoryId,
    pub owner: GithubOwner,
    pub name: String,
    pub visibility: RepositoryVisibility,
    pub archived: bool,
    pub default_branch: Option<String>,
}
impl RepositorySummary {
    pub fn full_name(&self) -> String {
        format!("{}/{}", self.owner.login, self.name)
    }
}

/// A cursor only continues the same selected vault version and provider user.
/// It cannot be constructed from a page number, URL or a different credential.
/// The NdsClient adapter also binds use to its existing NDS authorization fence
/// and invalidates old cursor/view lifetimes on session changes. This page
/// contract is not a transferable authorization capability.
#[derive(Clone)]
pub struct CatalogCursor {
    selection: CredentialSelection,
    principal: GithubAccountId,
    page: u8,
}
pub struct CatalogPageRequest {
    selection: CredentialSelection,
    expected_principal: Option<GithubAccountId>,
    page: u8,
}
impl CatalogPageRequest {
    pub fn new(
        selection: CredentialSelection,
        after: Option<&CatalogCursor>,
    ) -> Result<Self, ModuleError> {
        let (expected_principal, page) = match after {
            Some(cursor)
                if cursor.selection == selection
                    && (2..=MAX_CATALOG_PAGES).contains(&cursor.page) =>
            {
                (Some(cursor.principal), cursor.page)
            }
            Some(_) => return Err(ModuleError::InvalidInput),
            None => (None, 1),
        };
        Ok(Self {
            selection,
            expected_principal,
            page,
        })
    }
    pub fn selection(&self) -> &CredentialSelection {
        &self.selection
    }
    pub fn expected_principal(&self) -> Option<GithubAccountId> {
        self.expected_principal
    }
    pub fn page(&self) -> u8 {
        self.page
    }
}

/// Facts from the authorized adapter, not a claimed whole-account snapshot.
pub struct ProviderRepositoryPage {
    pub principal: GithubOwner,
    pub repositories: Vec<RepositorySummary>,
    pub observed_at_ms: u64,
    pub has_more: bool,
}
pub struct RepositoryOwnerGroup {
    pub owner: GithubOwner,
    pub repositories: Vec<RepositorySummary>,
}
pub enum CatalogContinuation {
    More(CatalogCursor),
    /// End reported for this credential's access-scoped listing only. Absence
    /// never deletes a binding or proves that an organization does not exist.
    EndOfAccessScope,
    /// Provider still reports more; the local page budget is incomplete.
    LimitReached,
}
pub struct RepositoryPage {
    pub principal: GithubOwner,
    pub groups: Vec<RepositoryOwnerGroup>,
    pub observed_at_ms: u64,
    pub continuation: CatalogContinuation,
}

fn locator(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !matches!(value, "." | "..")
        && !value
            .chars()
            .any(|ch| ch.is_control() || ch == '/' || ch == '\\')
}
impl ProviderRepositoryPage {
    pub fn into_page(self, request: &CatalogPageRequest) -> Result<RepositoryPage, ModuleError> {
        if self.principal.kind != GithubOwnerKind::User
            || !locator(&self.principal.login, 256)
            || request
                .expected_principal
                .is_some_and(|id| id != self.principal.id)
            || self.repositories.len() > REPOSITORIES_PER_PAGE
            || self.observed_at_ms == 0
            || self.observed_at_ms > MAX_REVISION
        {
            return Err(ModuleError::InvalidResponse);
        }
        let mut ids = BTreeSet::new();
        let mut groups: BTreeMap<GithubAccountId, RepositoryOwnerGroup> = BTreeMap::new();
        for repository in self.repositories {
            if !ids.insert(repository.id)
                || !locator(&repository.owner.login, 256)
                || !locator(&repository.name, 400)
                || repository.default_branch.as_ref().is_some_and(|branch| {
                    branch.is_empty() || branch.len() > 1024 || branch.chars().any(char::is_control)
                })
            {
                return Err(ModuleError::InvalidResponse);
            }
            let group = groups
                .entry(repository.owner.id)
                .or_insert_with(|| RepositoryOwnerGroup {
                    owner: repository.owner.clone(),
                    repositories: Vec::new(),
                });
            if group.owner != repository.owner {
                return Err(ModuleError::InvalidResponse);
            }
            group.repositories.push(repository);
        }
        let continuation = if !self.has_more {
            CatalogContinuation::EndOfAccessScope
        } else if request.page == MAX_CATALOG_PAGES {
            CatalogContinuation::LimitReached
        } else {
            CatalogContinuation::More(CatalogCursor {
                selection: request.selection.clone(),
                principal: self.principal.id,
                page: request.page + 1,
            })
        };
        Ok(RepositoryPage {
            principal: self.principal,
            groups: groups.into_values().collect(),
            observed_at_ms: self.observed_at_ms,
            continuation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn selection(pending: Option<&str>) -> CredentialSelection {
        CredentialSelection::new("credential".into(), 7, pending.map(str::to_owned)).unwrap()
    }
    fn owner(id: u64, kind: GithubOwnerKind, login: &str) -> GithubOwner {
        GithubOwner {
            id: GithubAccountId::new(id).unwrap(),
            kind,
            login: login.into(),
        }
    }
    fn repository(id: u64, owner: GithubOwner, name: &str) -> RepositorySummary {
        RepositorySummary {
            id: RepositoryId::new(id).unwrap(),
            owner,
            name: name.into(),
            visibility: RepositoryVisibility::Private,
            archived: false,
            default_branch: Some("feature/catalog".into()),
        }
    }
    fn raw(repositories: Vec<RepositorySummary>, has_more: bool) -> ProviderRepositoryPage {
        ProviderRepositoryPage {
            principal: owner(1, GithubOwnerKind::User, "user"),
            repositories,
            observed_at_ms: 100,
            has_more,
        }
    }
    #[test]
    fn selection_uses_existing_revision_and_exact_pending_operation_identity() {
        assert!(CredentialSelection::new("".into(), 0, None).is_err());
        assert!(CredentialSelection::new("credential".into(), MAX_REVISION + 1, None).is_err());
        assert!(CredentialSelection::new("credential".into(), 7, Some("".into())).is_err());
        let request = CatalogPageRequest::new(selection(Some("operation-a")), None).unwrap();
        let page = raw(vec![], true).into_page(&request).unwrap();
        let CatalogContinuation::More(cursor) = page.continuation else {
            panic!("next page required")
        };
        assert!(CatalogPageRequest::new(selection(Some("operation-a")), Some(&cursor)).is_ok());
        for pending in [None, Some("operation-b")] {
            assert!(matches!(
                CatalogPageRequest::new(selection(pending), Some(&cursor)),
                Err(ModuleError::InvalidInput)
            ));
        }
        let mut newer = selection(Some("operation-a"));
        newer.revision += 1;
        assert!(CatalogPageRequest::new(newer, Some(&cursor)).is_err());
    }
    #[test]
    fn cursor_is_principal_scoped_and_limit_is_not_provider_end() {
        let mut request = CatalogPageRequest::new(selection(None), None).unwrap();
        for page_number in 1..=MAX_CATALOG_PAGES {
            assert_eq!(request.page(), page_number);
            let page = raw(vec![], true).into_page(&request).unwrap();
            match page.continuation {
                CatalogContinuation::More(cursor) => {
                    assert!(page_number < MAX_CATALOG_PAGES);
                    request = CatalogPageRequest::new(selection(None), Some(&cursor)).unwrap();
                    let mut wrong = raw(vec![], false);
                    wrong.principal.id = GithubAccountId::new(2).unwrap();
                    assert!(matches!(
                        wrong.into_page(&request),
                        Err(ModuleError::InvalidResponse)
                    ));
                }
                CatalogContinuation::LimitReached => assert_eq!(page_number, MAX_CATALOG_PAGES),
                CatalogContinuation::EndOfAccessScope => panic!("budget is not EOF"),
            }
        }
        assert!(matches!(
            raw(vec![], false).into_page(&request).unwrap().continuation,
            CatalogContinuation::EndOfAccessScope
        ));
    }
    #[test]
    fn identity_survives_locator_and_owner_changes_and_groups_use_owner_ids() {
        let user = owner(1, GithubOwnerKind::User, "user");
        let org = owner(2, GithubOwnerKind::Organization, "org");
        let original = repository(10, user.clone(), "old");
        let moved = repository(10, org.clone(), "new");
        let reused = repository(11, user.clone(), "old");
        assert!(original.id == moved.id && original.id != reused.id);
        assert_ne!(original.full_name(), moved.full_name());
        assert_eq!(original.full_name(), reused.full_name());
        let request = CatalogPageRequest::new(selection(None), None).unwrap();
        let page = raw(vec![moved, reused, repository(12, org, "other")], false)
            .into_page(&request)
            .unwrap();
        assert_eq!(page.groups.len(), 2);
        assert_eq!(page.groups[0].owner.id.value(), 1);
        assert_eq!(page.groups[1].repositories.len(), 2);
        // An empty later observation has no registry/deletion operation. The
        // earlier immutable page remains intact; no absence-derived tombstones.
        assert!(
            raw(vec![], false)
                .into_page(&request)
                .unwrap()
                .groups
                .is_empty()
        );
        assert_eq!(page.groups[1].repositories[0].id.value(), 10);
    }
    #[test]
    fn oversized_duplicate_inconsistent_or_invalid_provider_data_is_rejected() {
        let request = CatalogPageRequest::new(selection(None), None).unwrap();
        let user = owner(1, GithubOwnerKind::User, "user");
        let entries = (1..=26)
            .map(|id| repository(id, user.clone(), "name"))
            .collect();
        assert!(raw(entries, false).into_page(&request).is_err());
        assert!(
            raw(
                vec![
                    repository(1, user.clone(), "one"),
                    repository(1, user.clone(), "two")
                ],
                false
            )
            .into_page(&request)
            .is_err()
        );
        let changed = owner(1, GithubOwnerKind::Organization, "org");
        assert!(
            raw(
                vec![
                    repository(1, user.clone(), "one"),
                    repository(2, changed, "two")
                ],
                false
            )
            .into_page(&request)
            .is_err()
        );
        assert!(
            raw(vec![repository(1, user, "../escape")], false)
                .into_page(&request)
                .is_err()
        );
        for time in [0, MAX_REVISION + 1] {
            let mut page = raw(vec![], false);
            page.observed_at_ms = time;
            assert!(page.into_page(&request).is_err());
        }
        let mut invalid = raw(vec![], false);
        invalid.principal.kind = GithubOwnerKind::Organization;
        assert!(invalid.into_page(&request).is_err());
        assert!(RepositoryId::new(0).is_err() && GithubAccountId::new(0).is_err());
        assert_eq!(RepositoryId::new(u64::MAX).unwrap().value(), u64::MAX);
    }
}
