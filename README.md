# nddev-device-sync-core

Public AGPL-3.0-only Rust core for NDDev OpenNetwork device sync products.
This repository owns pure domain rules and application ports for product
identity, device enrollment and module composition. Native credential adapters
belong to `nddev-device-sync-accounts`. Core contains no concrete I/O, estate
data or production endpoints.

The desktop, mobile, server and agent repositories consume this core through
explicit Git revisions and the protocol repository. The core has no UI dependency and
no knowledge of the private self-hosted estate.

Module descriptors belong to their implementing adapters. The native agent
composes their manifests through the domain graph; core contains no parallel
assembly registry or claims about installed provider capabilities.

`domain::sync::history` owns operation metadata, retained-history bounds and
checkpoint validation. `application::replica::reconcile_history` owns one bounded
upload, inbox and checkpoint recovery batch. `reconcile` and `reconcile_inbox`
use that same path; the inbox-only call does not claim local uploads.
Its `inbox_at_head` observation is separate from full `caught_up`: pending work
still prevents the adapter's atomic freshness mark.
Persisted writer facts describe the negotiated format and observed history;
they never grant authorization or replace an uncertain dispatched operation.
The vault adapter supplies its existing immutable claims, authenticated transport,
payload verification and atomic journal commands. It retains concrete storage,
cryptography, key access and request encoding; core contains no SQL or wire DTOs.
`application::lifecycle` owns visible-client admission and replica backoff. A
desktop/web window losing input focus can continue bounded work; hidden clients
and mobile background restrictions retain their existing boundary. Adapters own
the actual tasks, deadlines and cancellation, and identity remains the existing
accounts boundary.

`repositories::catalog::observations` defines bounded positive repository
observations and prepares candidates from a scoped scan and existing metadata.
It performs no Git or database writes. A partial scan cannot imply absence or
authorize deletion; provider and publication adapters own those I/O boundaries.

Sync pages retain the protocol's 100-item ceiling and the caller's requested
limit. Server adapters must also enforce `MAX_PAGE_BYTES` on the encoded JSON
page (60 KiB), preserving room below the clients' 64 KiB response limit. Only a
contiguous prefix may be returned; byte truncation retains `has_more` and the
last included cursor. Existing servers returning smaller pages remain usable.

`domain::screen` and `application::screen` own finite view-only permissions,
endpoint-binding revisions, frame bounds and the canonical screen-control port.
Native key proof, authenticated transactions, capture permission and transport
belong to adapters. Restored screen metadata alone never authorizes capture;
clients must revalidate their current Accounts lifetime before using it.

## Verification

```sh
just check
```

`just check` requires cargo-nextest 0.9.148, cargo-audit 0.22.2 and cargo-deny
0.20.2, pinned in CI. It checks formatting, locked workspace tests and doctests,
Clippy, known dependency advisories and the reviewed license/source policy.
