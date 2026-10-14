# Development workflow

Use the pinned toolchain and the repository's `just` recipes. Keep runtime
credentials, private estate data and live telemetry outside this repository.

`main` and `dev` are permanent branches. Make scoped changes on a working
branch, submit a pull request to `dev`, and promote reviewed changes from
`dev` to `main`. Use Conventional Commits and signed commits. Do not delete
permanent branches or rewrite published history.

The `NDS checks / quality` job runs on GitHub-hosted Ubuntu with read-only
repository permissions and immutable action pins. It checks this repository's
current foundation. A green result is not deployment, release, integration or
cross-platform acceptance. Full release gates remain those in the locked
central standards.

## Standards compatibility

`standarts.lock` selects the immutable central contract for this source. Consumers
update explicit Git revisions and qualify one coherent dependency graph; package
labels alone do not identify the source or establish compatibility.

Domain rules and application ports remain independent of concrete I/O. Accounts
owns sessions and protected credentials; Vault owns encryption and local
durability; Server owns authenticated transactions. Provider runtimes, endpoint
keys, browser storage and Flutter presentation remain in their owning adapters.
Pure Core checks do not qualify those runtime paths or authorize live migration.
