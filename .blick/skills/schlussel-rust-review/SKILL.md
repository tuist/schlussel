---
name: schlussel-rust-review
description: Project-specific PR-review rules for the Schlussel Rust workspace. Focuses on formula-driven OAuth behavior, storage and locking semantics, docs sync, and toolchain alignment.
---

# Schlussel Rust Review

This skill is intentionally narrow. Generic Rust style and lint issues are already covered by formatting and CI. Focus on the repo-specific rules below.

For each finding, cite `path:line` and quote the relevant snippet.

## 1. Formula files remain the source of truth

The JSON files in `src/formulas/` are the product contract for providers, methods, and public clients.

### Flag

- A diff that hardcodes provider metadata in Rust while drifting from `src/formulas/*.json`. Severity: high.
- A schema or CLI behavior change that is not reflected in `website/src/skill.md` or `website/src/html.ts`. Severity: medium.

## 2. Token persistence and refresh keys stay compatible

The repo uses `{formula}:{method}:{identity}` storage keys and refresh locks derived from those keys.

### Flag

- A diff that changes key generation or parsing without migration handling and tests. Severity: high.
- A diff that changes refresh locking behavior without tests covering cross-process safety assumptions. Severity: medium.

## 3. Contributor commands stay on the Rust toolchain path

This repo should use `mise exec -- cargo ...` in contributor-facing docs and CI.

### Flag

- A toolchain bump in `mise.toml` without the matching `rust-version` change in `Cargo.toml`, or vice versa. Severity: medium.
- Docs or scripts that tell contributors to use Zig commands after the Rust migration. Severity: medium.

## 4. CLI contract changes need tests or docs updates

The CLI is a user-facing product surface for agents and humans.

### Flag

- A change in `crates/schlussel-cli/src/` that alters commands, JSON output, or error behavior without focused tests or matching docs updates. Severity: medium.

## 5. Keep crate roots small

`lib.rs` and `main.rs` should stay as tables of contents and light dispatch.

### Flag

- A new or expanded crate root that mixes unrelated implementation instead of splitting modules. Severity: low.

## 6. No em dashes in user-facing text

README copy, docs, help text, and review content should avoid em dashes.

### Flag

- New user-facing strings or documentation that introduce an em dash character. Severity: low.
