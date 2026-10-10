set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

fmt-check:
    cargo fmt --all -- --check

test:
    cargo nextest run --locked --workspace --jobs 4
    cargo test --locked --workspace --doc --jobs 4

clippy:
    cargo clippy --locked --workspace --all-targets --jobs 4 -- -D warnings

dependencies-check:
    cargo audit --deny warnings
    cargo deny --locked check licenses sources

check: fmt-check test clippy dependencies-check

keyring-check:
    python3 scripts/check-keyring.py
