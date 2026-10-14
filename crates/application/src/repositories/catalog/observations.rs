//! Named caller: NdsClient catalog scan. Metadata read precedes provider I/O.
//! Returned candidates do not execute writes, delete facts or reset a catalog.
use super::*;
use nddev_device_sync_domain::repositories::catalog::observations::*;
use std::collections::{BTreeMap, BTreeSet};
/// Existing server heads plus existing Vault whole-outbox bound; not a quota
/// increase or admission-basis declaration. Adapter returns metadata only.
pub const MAX_BASELINES: usize = 5120;
pub const OBSERVATION_WINDOW: usize = 32;
/// The adapter supplies a complete bounded metadata snapshot. A missing key
/// means absent at this pre-I/O read, never a partial lookup after the reply.
pub trait ReadObservationBaselines: ReadGithubCatalogPage {
    fn observation_baselines(
        &self,
    ) -> impl Future<Output = Result<Vec<(ObservationKey, TargetVersion)>, Self::Error>>;
}
pub struct PreparedPage {
    pub context: ObservationContext,
    pub page: u8,
    pub repository_ids: Vec<RepositoryId>,
    pub has_more: bool,
    pub candidates: Vec<Candidate>,
}
pub async fn observation_page<P: ReadObservationBaselines>(
    port: &P,
    selection: CredentialSelection,
    after: Option<&CatalogCursor>,
    scan_id: String,
    cancellation: &P::Cancellation,
) -> Result<PreparedPage, P::Error> {
    let request = CatalogPageRequest::new(selection, after)?;
    if nddev_device_sync_domain::ModuleId::new(&scan_id).is_err() {
        return Err(ModuleError::InvalidInput.into());
    }
    let baselines = port.observation_baselines().await?;
    if baselines.len() > MAX_BASELINES {
        return Err(ModuleError::InvalidResponse.into());
    }
    let mut captures = BTreeMap::new();
    for (key, version) in baselines {
        let capture = Capture::before_read(key.clone(), version)?;
        if captures.insert(key, capture).is_some() {
            return Err(ModuleError::InvalidResponse.into());
        }
    }
    let raw = port.read_page(&request, cancellation).await?;
    let page = raw.into_page(&request)?;
    let context = ObservationContext {
        principal: page.principal.id,
        selection: request.selection().clone(),
        scan_id,
    };
    let source = ObservationSource {
        context: context.clone(),
        page: Some(request.page()),
    };
    let mut facts = BTreeMap::new();
    let mut ids = Vec::new();
    for group in page.groups {
        let owner = RepositoryObservation {
            source: source.clone(),
            data: ObservationData::Owner { owner: group.owner },
        };
        facts.insert(owner.key(), owner);
        for row in group.repositories {
            ids.push(row.id);
            let observation = RepositoryObservation {
                source: source.clone(),
                data: ObservationData::Repository {
                    repository: RepositoryFact::from_summary(&row)?,
                },
            };
            if facts.insert(observation.key(), observation).is_some() {
                return Err(ModuleError::InvalidResponse.into());
            }
        }
    }
    // The later repository-owner response wins over a cached/user profile in
    // the same page; never append a second contradictory owner candidate.
    let principal = RepositoryObservation {
        source,
        data: ObservationData::Owner {
            owner: page.principal,
        },
    };
    facts.entry(principal.key()).or_insert(principal);
    let candidates = facts
        .into_iter()
        .map(|(key, value)| {
            captures
                .remove(&key)
                .unwrap_or(Capture::before_read(key, TargetVersion::absent())?)
                .confirm(value)
        })
        .collect::<Result<Vec<_>, ModuleError>>()?;
    Ok(PreparedPage {
        context,
        page: request.page(),
        repository_ids: ids,
        has_more: !matches!(page.continuation, CatalogContinuation::EndOfAccessScope),
        candidates,
    })
}
/// Transient bounded traversal evidence, not a durable registry or scheduler.
/// Order-independent page receipt does not imply deletion or an atomic snapshot.
pub struct Traversal {
    context: ObservationContext,
    pages: BTreeMap<u8, (Vec<RepositoryId>, bool)>,
    ended: Option<u8>,
}
impl Traversal {
    pub fn new(context: ObservationContext) -> Result<Self, ModuleError> {
        context.validate()?;
        Ok(Self {
            context,
            pages: BTreeMap::new(),
            ended: None,
        })
    }
    pub fn accept(&mut self, page: &PreparedPage) -> Result<(), ModuleError> {
        if page.context != self.context
            || !(1..=MAX_CATALOG_PAGES).contains(&page.page)
            || page.repository_ids.len() > REPOSITORIES_PER_PAGE
        {
            return Err(ModuleError::InvalidInput);
        }
        let mut ids = page.repository_ids.clone();
        ids.sort();
        if ids.windows(2).any(|v| v[0] == v[1]) {
            return Err(ModuleError::InvalidResponse);
        }
        if let Some(old) = self.pages.get(&page.page) {
            if old != &(ids, page.has_more) {
                return Err(ModuleError::InvalidResponse);
            }
            return Ok(());
        }
        if self.ended.is_some_and(|end| page.page > end)
            || !page.has_more && self.pages.keys().any(|p| *p > page.page)
        {
            return Err(ModuleError::InvalidResponse);
        }
        if !page.has_more {
            if self.ended.is_some_and(|p| p != page.page) {
                return Err(ModuleError::InvalidResponse);
            }
            self.ended = Some(page.page);
        }
        self.pages.insert(page.page, (ids, page.has_more));
        Ok(())
    }
    pub fn summary(
        &self,
        outcome: Option<ModuleError>,
        previous: Option<&RepositoryObservation>,
        observed_at_ms: u64,
    ) -> Result<ScopeScan, ModuleError> {
        if observed_at_ms == 0 || observed_at_ms > nddev_device_sync_domain::sync::MAX_REVISION {
            return Err(ModuleError::InvalidInput);
        }
        let previous = match previous {
            Some(value) => {
                value.validate()?;
                let expected = ObservationKey::Scope {
                    principal: self.context.principal,
                    record_ref: self.context.selection.record_ref().into(),
                };
                if value.key() != expected
                    || value.source.context.selection != self.context.selection
                {
                    return Err(ModuleError::InvalidInput);
                }
                let ObservationData::ScopeScan { scan } = &value.data else {
                    return Err(ModuleError::InvalidInput);
                };
                Some(scan)
            }
            None => None,
        };
        let ids = self
            .pages
            .values()
            .flat_map(|p| p.0.iter().copied())
            .collect::<BTreeSet<_>>();
        let complete = self
            .ended
            .is_some_and(|end| (1..=end).all(|p| self.pages.contains_key(&p)));
        let terminal = if let Some(error) = outcome {
            TraversalOutcome::Failed(error)
        } else if complete {
            TraversalOutcome::Complete
        } else if self.pages.len() == usize::from(MAX_CATALOG_PAGES) {
            TraversalOutcome::LimitReached
        } else {
            TraversalOutcome::Partial
        };
        let last_complete = if matches!(terminal, TraversalOutcome::Complete) {
            Some(CompleteTraversal {
                pages: self.pages.len() as u8,
                repositories: ids.len() as u16,
                observed_at_ms,
                scan_id: self.context.scan_id.clone(),
            })
        } else {
            previous.and_then(|s| s.last_complete.clone())
        };
        Ok(ScopeScan {
            outcome: terminal,
            pages: self.pages.len() as u8,
            repositories: ids.len() as u16,
            last_complete,
        })
    }
}
/// Backpressure uses the existing32 publication window and16 upload roots.
pub fn stage_count(ready: usize, own_pending: usize, global_outbox_free: usize) -> usize {
    ready
        .min(OBSERVATION_WINDOW.saturating_sub(own_pending))
        .min(global_outbox_free)
}
