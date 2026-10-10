# nddev-device-sync-core

Public AGPL-3.0-only Rust core for NDDev OpenNetwork device sync products.
This repository owns pure domain rules, application ports, deterministic test
adapters and native credential-store integration. It contains no estate data
or production endpoints.

The desktop, mobile, server and agent repositories consume this core through
pinned releases and the protocol repository. The core has no UI dependency and
no knowledge of the private self-hosted estate.

Module descriptors belong to their implementing adapters. The native agent
composes their manifests through the domain graph; core contains no parallel
assembly registry or claims about installed provider capabilities.

## Verification

```sh
just check
just keyring-check
```

`just check` requires cargo-nextest 0.9.148, cargo-audit 0.22.2 and cargo-deny
0.20.2, pinned in CI. It checks formatting, locked workspace tests and doctests,
Clippy, known dependency advisories and the reviewed license/source policy.
Native Linux credential-store acceptance uses only an isolated Secret Service.
