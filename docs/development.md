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

The identity slice adopts `v0.0.1-alpha.9`
(`16a477beac6127adf73ef102df74a48451d607f1`). ADR 0003 introduces email OTP
and GitHub PKCE as explicit sign-in bindings for one owner. Product identity
use cases are consumed by the server through an immutable core source pin.

## API boundary

Core candidate `0.0.1-alpha.9` removes the unconsumed harness account service,
its account models and memory/keyring adapters. The domain package changes from
`0.0.1` to `0.0.2`; application changes to `0.0.1-alpha.9`. Consumers update an
explicit Git revision. Active identity/enrollment rules and module descriptors
retain their contracts; published protocol schemas and old Git tags are unchanged.
Product session storage and its native acceptance remain in the accounts module.
Removing this source does not read, rename or delete existing credential entries.
