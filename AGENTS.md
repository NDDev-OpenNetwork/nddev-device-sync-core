# nddev-device-sync-core working contract

This is a public AGPL-3.0-only module. Keep it OS-neutral at the domain and
application layers. Never add real device inventory, server endpoints,
credentials, estate policy or telemetry evidence.

Changes must remain compatible with the standards release in `standarts.lock`
and must pass formatting, tests and clippy before release.

Apply the central engineering standard: use the smallest correct change,
prefer standard library/native APIs, keep domain/application/adapters separated,
and report observed verification. Do not add speculative abstractions or
unbounded background work.
