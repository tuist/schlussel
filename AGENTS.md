# Claude Instructions for Schlussel

## Project Overview

Schlussel is a cross-platform OAuth 2.0 library with PKCE and Device Code Flow support, now centered on a Rust workspace. It is designed for command-line applications and agent runtimes, with formula-driven provider definitions, token persistence, and automatic refresh.

## Website Notes

- Keep the example formula snippet in `website/theme/layouts/index.liquid` aligned with the JSON schema and the current contents of `src/formulas/claude.json`.
- Keep the skill page (`website/src/skill.md`) up to date when modifying formula schemas or the CLI interface. This file serves as agent instructions and is accessible at https://schlussel.me/skill.md
- Keep the documentation page (`website/src/html.ts` - `renderDocsPage` function) up to date when modifying the formula schema or CLI interface. The docs page documents the formula specification and CLI commands at https://schlussel.me/docs

## Core Architecture

### Key Modules

1. **PKCE Module** (`crates/schlussel/src/pkce.rs`)
   - Generates cryptographically secure code verifiers and challenges
   - Uses SHA256 for challenge generation
   - Base64 URL-safe encoding without padding

2. **Session Management** (`crates/schlussel/src/session.rs`)
   - Trait-based storage (`SessionStorage`)
   - Three built-in backends: `SecureStorage`, `FileStorage`, `MemoryStorage`
   - File-backed tokens for the CLI and keyring-backed secure storage for library users
   - Stable storage-key format: `{formula}:{method}:{identity}`

3. **OAuth Flow** (`crates/schlussel/src/oauth.rs`)
   - Device Code Flow (RFC 8628) for CLI apps
   - Authorization Code Flow with PKCE
   - Automatic browser opening and callback handling
   - Token refresh with HTTP client
   - Provider presets (GitHub, Google, Microsoft, GitLab, Tuist)

4. **Token Refresher** (`crates/schlussel/src/oauth.rs`)
   - In-process locking (threads)
   - Cross-process locking (file-based)
   - Automatic token refresh (`getValidToken`)
   - Proactive refresh with thresholds

5. **Callback Server** (`crates/schlussel/src/callback.rs`)
   - Local HTTP server for OAuth redirects
   - Random port assignment
   - HTML success/error pages

6. **Cross-Process Locking** (`crates/schlussel/src/lock.rs`)
   - File-based locks
   - RAII lock guards
   - Check-then-refresh pattern

7. **Formulas and Scripts**
   - Bundled provider formulas live in `src/formulas/*.json`
   - Script resolution lives in `crates/schlussel/src/script.rs`
   - The CLI surface lives in `crates/schlussel-cli/src/main.rs`

## Development Guidelines

### Code Style

- Follow Rust standard conventions (`cargo fmt`)
- Keep crate roots small and push implementation into focused modules
- Document public APIs when the usage is not obvious

### Commits

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification for commit messages:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `style:` for formatting changes
- `refactor:` for code refactoring
- `test:` for adding or updating tests
- `chore:` for maintenance tasks

### Testing

- Unit tests live next to the Rust modules they cover
- End-to-end CLI coverage lives under `e2e/` and runs through ShellSpec against a local OAuth server
- Run: `mise exec -- cargo test`
- Run: `shellspec`
- All tests must pass before committing

### Building

- Development: `mise exec -- cargo build --workspace`
- Run tests: `mise exec -- cargo test`
- Format: `mise exec -- cargo fmt`

### CI Requirements

All PRs must pass:
- Cargo tests on Ubuntu, macOS, Windows
- ShellSpec e2e coverage on Ubuntu
- `cargo fmt --check`

## Important Design Decisions

### 1. Security First

- **SecureStorage is the library default recommendation** for hosts that want OS credential managers
- The CLI currently uses `FileStorage` so tokens can be enumerated, filtered, and deleted by key
- Always use PKCE for OAuth flows
- Cross-process locking prevents race conditions

### 2. Device Code Flow Priority

- Primary flow for CLI applications
- Simpler UX than callback server
- Works in headless/remote environments
- Falls back to callback flow when Device Code not supported

### 3. Automatic Token Refresh

- `getValidToken()` eliminates manual expiration checking
- Proactive refresh with configurable thresholds
- Cross-process safe when using file locking

### 4. Provider Presets

- One-line configuration for popular providers
- Reduces errors from manual endpoint configuration
- Self-hosted instance support where applicable

### 5. Storage Abstraction

Three built-in backends:
- **SecureStorage**: Production (OS keychain/credential manager)
- **FileStorage**: Development (JSON files)
- **MemoryStorage**: Testing (in-memory)

### 6. Cross-Process Coordination

- File-based locks at refresh level (not storage level)
- Check-then-refresh pattern to avoid redundant HTTP requests
- RAII lock guards with automatic cleanup

## Common Tasks

### Adding a New Provider Preset

1. Add method to `OAuthConfig` in `crates/schlussel/src/oauth.rs`
2. Add test to verify endpoints
3. Update README.md if it's a major provider

### Adding a New Storage Backend

1. Implement `SessionStorage` in `crates/schlussel/src/session.rs`
2. Add tests
3. Add or update CLI and e2e coverage if the storage is user-visible

## Security Considerations

1. **Secure Storage**: Always recommend `SecureStorage` for production
2. **PKCE Required**: Never allow non-PKCE flows
3. **State Validation**: Always verify state parameter
4. **HTTPS Only**: Validate endpoints use HTTPS (except localhost)
5. **Token Expiration**: Use `getValidToken()` for automatic checking
6. **Cross-Process Safety**: Use file locking when multiple processes might run

## Platform-Specific Notes

### Legacy Zig Sources

- The legacy Zig implementation is still present in the repository as migration reference material.
- New work should target the Rust workspace unless a task explicitly says otherwise.

### Windows
- SecureStorage uses Credential Manager
- File locking uses different error codes

### Linux
- SecureStorage requires libsecret
- XDG Base Directory specification for file paths

## References

- [RFC 7636: PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 6749: OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 8628: Device Code Flow](https://tools.ietf.org/html/rfc8628)
- [RFC 8252: OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
