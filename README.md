# nddev-device-sync-core

Public AGPL-3.0-only Rust core for NDDev OpenNetwork device sync products.
This repository owns pure domain rules and application ports for product
identity, device enrollment and module composition. Native credential adapters
belong to `nddev-device-sync-accounts`. Core contains no concrete I/O, estate
data or production endpoints.

The desktop, mobile, server and agent repositories consume this core through
pinned releases and the protocol repository. The core has no UI dependency and
no knowledge of the private self-hosted estate.

Module descriptors belong to their implementing adapters. The native agent
composes their manifests through the domain graph; core contains no parallel
assembly registry or claims about installed provider capabilities.

## Verification

```sh
just check
```

`just check` requires cargo-nextest 0.9.148, cargo-audit 0.22.2 and cargo-deny
0.20.2, pinned in CI. It checks formatting, locked workspace tests and doctests,
Clippy, known dependency advisories and the reviewed license/source policy.
