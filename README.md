# nddev-device-sync-core

Public AGPL-3.0-only Rust core for NDDev OpenNetwork device sync products.
This repository owns pure domain rules, application ports, deterministic test
adapters and native credential-store integration. It contains no estate data
or production endpoints.

The desktop, mobile, server and agent repositories consume this core through
pinned releases and the protocol repository. The core has no UI dependency and
no knowledge of the private self-hosted estate.

## Verification

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

