# Design: OAuth Runtime

Schlussel is a local OAuth runtime for applications that need a reliable way to
authenticate users, store tokens securely, and refresh them safely across
threads and processes.

## Goals

- Provide a reusable OAuth implementation for Zig and C consumers.
- Support Device Code Flow and Authorization Code Flow with PKCE.
- Keep token storage and refresh logic in one disciplined layer.
- Offer a small CLI for inspecting and retrieving stored tokens.

## Non-goals

- Schlussel is not an identity provider.
- Schlussel does not host a remote control plane or registry.
- Schlussel does not replace a platform's consent UI or developer dashboard.

## Core Abstractions

### OAuthConfig

Explicit OAuth configuration, either built manually or through provider
presets, defines endpoints, redirect URIs, scopes, and client credentials.

### OAuthClient

The client executes OAuth flows, exchanges codes, requests device codes, and
refreshes tokens through a single interface.

### Session

Token persistence is abstracted behind `SessionStorage`. Native OS credential
managers are preferred in production, with file and memory backends for local
development and tests.

### Refresh Locking

Refreshes are guarded by in-process and cross-process locks so concurrent
applications do not race and overwrite each other's tokens.

### Callback Server

Authorization Code Flow uses a short-lived local HTTP server to receive the
redirect and validate the returned state.

### FFI Layer

The C interface exposes the same runtime primitives to Swift, Objective-C, and
other languages that can call a C ABI.

## Security Principles

- PKCE is required for OAuth flows.
- HTTPS endpoints are enforced except for localhost callbacks.
- Native credential storage is preferred for secrets.
- Refreshes are serialized when multiple actors share the same token.
