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

The module standards lock remains at `v0.0.1-alpha.7` (`592531d`).
Central `v0.0.1-alpha.8` (`c73a525`) changes assembly catalog metadata only;
the normative `standarts/` files are identical. The older lock is compatible
with the current assembly. Update locks only through the canonical source
release, not through a mutable branch.

## Account safety compatibility

`ModuleId`, `HarnessId` and `AccountId` accept 1..128 ASCII letters, digits,
`.`, `_`, `:` and `-`, identically in constructors and deserialization.
Native account entries keep the existing service and `harness/account` key.
Previously accepted malformed IDs fail validation; their credentials are not
renamed, copied, deleted or looked up through an ambiguous fallback. Such records
need an explicitly reviewed transition before they can be used again.

`AccountStore::insert` atomically reserves an ID in `PendingAuthorization`;
duplicates must leave the existing record unchanged. `mark_authorized` completes
that state only after the secret write. A failed cleanup is explicit and leaves
an unusable pending record; a failed finalization preserves the secret and pending
record. These failures require reconciliation, not automatic credential deletion.

`just keyring-check` exercises the real Linux Secret Service adapter on a separate
D-Bus session with disposable encrypted keyring storage. It does not use the
desktop keyring. It requires `dbus-run-session`, `gnome-keyring-daemon` and `gdbus`.
Ordinary tests cover rules and deterministic in-memory behavior; fault-injection
unit tests are not native adapter acceptance. Other platforms require their own
native acceptance before claiming support.
