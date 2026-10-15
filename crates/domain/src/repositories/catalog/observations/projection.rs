//! One bounded saved-catalog page for NdsClient. Missing owner observations
//! remain missing; repository facts never invent an owner name or account kind.
use super::*;

pub struct SavedOwner {
    pub owner: GithubOwner,
    pub version: TargetVersion,
    pub observed_at_ms: u64,
}
pub struct SavedRepository {
    pub repository: RepositoryFact,
    pub version: TargetVersion,
    pub observed_at_ms: u64,
}
pub struct SavedRepositoryGroup {
    pub owner_id: GithubAccountId,
    pub owner: Option<SavedOwner>,
    pub repositories: Vec<SavedRepository>,
}

/// Each pair contains the target and its original observation time in milliseconds.
/// Input facts must come from one validated local read revision. These are
/// saved observations, not proof of current provider access or remote freshness.
pub fn saved_page(
    observations: Vec<(ObservedTarget, u64)>,
) -> Result<Vec<SavedRepositoryGroup>, ModuleError> {
    if observations.len() > 2 * REPOSITORIES_PER_PAGE {
        return Err(ModuleError::InvalidResponse);
    }
    let mut owners = BTreeMap::new();
    let mut repositories = BTreeMap::new();
    for (target, observed_at_ms) in observations {
        target.validate()?;
        if observed_at_ms == 0 || observed_at_ms > MAX_REVISION {
            return Err(ModuleError::InvalidResponse);
        }
        let observation = target.value.ok_or(ModuleError::InvalidResponse)?;
        let duplicate = match observation.data {
            ObservationData::Owner { owner } => owners
                .insert(
                    owner.id,
                    SavedOwner {
                        owner,
                        version: target.version,
                        observed_at_ms,
                    },
                )
                .is_some(),
            ObservationData::Repository { repository } => repositories
                .insert(
                    repository.id,
                    SavedRepository {
                        repository,
                        version: target.version,
                        observed_at_ms,
                    },
                )
                .is_some(),
            ObservationData::ScopeScan { .. } => return Err(ModuleError::InvalidResponse),
        };
        if duplicate {
            return Err(ModuleError::InvalidResponse);
        }
    }
    if repositories.len() > REPOSITORIES_PER_PAGE || owners.len() > REPOSITORIES_PER_PAGE {
        return Err(ModuleError::InvalidResponse);
    }
    let mut groups = BTreeMap::<GithubAccountId, SavedRepositoryGroup>::new();
    for repository in repositories.into_values() {
        let id = repository.repository.owner_id;
        groups
            .entry(id)
            .or_insert_with(|| SavedRepositoryGroup {
                owner_id: id,
                owner: owners.remove(&id),
                repositories: Vec::new(),
            })
            .repositories
            .push(repository);
    }
    if !owners.is_empty() {
        return Err(ModuleError::InvalidResponse);
    }
    Ok(groups.into_values().collect())
}
