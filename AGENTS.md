# Claude Instructions for Schlussel

## Project Overview

Schlussel is a cross-platform OAuth 2.0 library with PKCE and Device Code Flow support, written in Zig. It's designed for command-line and desktop applications and provides secure token storage using OS credential managers.

## Documentation Notes

- Keep `README.md` aligned with the current public API and CLI behavior.
- Keep public doc comments in `src/lib.zig`, `src/oauth.zig`, and `include/schlussel.h` accurate when changing interfaces.
- Prefer updating source comments over maintaining parallel hand-written API docs. Generated docs come from `zig build docs`.

## Core Architecture

### Key Modules

1. **PKCE Module** (`src/pkce.zig`)
   - Generates cryptographically secure code verifiers and challenges
   - Uses SHA256 for challenge generation
   - Base64 URL-safe encoding without padding

2. **Session Management** (`src/session.zig`)
   - Interface-based storage (`SessionStorage`)
   - Three built-in backends: `SecureStorage`, `FileStorage`, `MemoryStorage`
   - Thread-safe with mutex protection
   - Domain-based file organization

3. **OAuth Flow** (`src/oauth.zig`)
   - Device Code Flow (RFC 8628)
   - Authorization Code Flow with PKCE
   - Automatic browser opening and callback handling
   - Token refresh with HTTP client
   - Provider presets (GitHub, Google, Microsoft, GitLab, Tuist)

4. **Token Refresher** (`src/oauth.zig`)
   - In-process locking (threads)
   - Cross-process locking (file-based)
   - Automatic token refresh (`getValidToken`)
   - Proactive refresh with thresholds

5. **Callback Server** (`src/callback.zig`)
   - Local HTTP server for OAuth redirects
   - Random port assignment
   - HTML success/error pages

6. **Cross-Process Locking** (`src/lock.zig`)
   - File-based locks
   - RAII lock guards
   - Check-then-refresh pattern

7. **FFI Layer** (`src/ffi.zig`)
   - C-compatible API for Swift/Objective-C
   - Opaque pointers for type safety
   - Error codes instead of error unions

## Development Guidelines

### Code Style

- Follow Zig standard conventions (`zig fmt`)
- Use `const` by default
- Document public APIs with doc comments (`///`)
- Add examples to doc comments when useful

### Commits

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `style:` for formatting changes
- `refactor:` for code refactoring
- `test:` for adding or updating tests
- `chore:` for maintenance tasks

### Testing

- Unit tests inline in modules
- Run: `zig build test`
- All tests must pass before committing
- Add tests for new features
- Use `std.testing.allocator` to detect memory leaks

### Building

- Development: `zig build`
- Run tests: `zig build test`
- Examples: `zig build example-github-device`
- Format: `zig fmt src/`

## Important Design Decisions

### 1. Security First

- **SecureStorage is the default recommendation** for production
- FileStorage has warnings about plaintext storage
- Always use PKCE for OAuth flows
- Cross-process locking prevents refresh races

### 2. Device Code Flow Priority

- Primary flow for CLI applications
- Simpler UX than a callback server in headless environments
- Works in remote and terminal-only setups

### 3. Automatic Token Refresh

- `getValidToken()` eliminates manual expiration checking
- Proactive refresh uses configurable thresholds
- Refreshes are safe across concurrent processes when locking is enabled

### 4. Provider Presets

- One-line configuration for common providers
- Reduces endpoint and redirect configuration mistakes
- Self-hosted instance support where applicable

### 5. Storage Abstraction

Three built-in backends:
- **SecureStorage**: Production (OS keychain/credential manager)
- **FileStorage**: Development and debugging
- **MemoryStorage**: Testing

## Common Tasks

### Adding a New Provider Preset

1. Add a method to `OAuthConfig` in `src/oauth.zig`
2. Add tests to verify endpoints and behavior
3. Update `README.md` if the new preset is part of the public surface

### Adding a New Storage Backend

1. Implement `SessionStorage` in `src/session.zig`
2. Add tests
3. Add an example if the backend needs non-obvious setup

### Adding FFI Functions

1. Add the export to `src/ffi.zig`
2. Update `include/schlussel.h`
3. Test on all supported platforms

## Security Considerations

1. **Secure Storage**: Recommend `SecureStorage` for production
2. **PKCE Required**: Do not allow non-PKCE OAuth flows
3. **State Validation**: Always verify the state parameter
4. **HTTPS Only**: Validate endpoints use HTTPS except localhost callbacks
5. **Token Expiration**: Use `getValidToken()` for automatic checks
6. **Cross-Process Safety**: Use file locking when multiple processes might run

## Platform-Specific Notes

### macOS

- SecureStorage uses Keychain
- XCFramework support for Swift/iOS

### Windows

- SecureStorage uses Credential Manager
- File locking uses different error codes

### Linux

- SecureStorage requires libsecret
- File paths follow the XDG Base Directory specification

## References

- [RFC 7636: PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 6749: OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 8628: Device Code Flow](https://tools.ietf.org/html/rfc8628)
- [RFC 8252: OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
