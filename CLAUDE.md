# Claude Instructions for Schlussel

## Project Overview

Schlussel is a cross-platform OAuth 2.0 library with PKCE (Proof Key for Code Exchange) support, specifically designed for command-line applications. It is written in Zig and provides both a native Zig API and a C-compatible API for use with other programming languages.

## Core Architecture

### Key Components

1. **PKCE Module** (`src/pkce.zig`)
   - Generates cryptographically secure code verifiers and challenges
   - Uses SHA256 for challenge generation
   - Always use base64 URL-safe encoding without padding

2. **Session Management** (`src/session.zig`)
   - Provides pluggable storage via vtable pattern
   - Thread-safe with mutex locks
   - Supports both session state and token persistence

3. **OAuth Flow** (`src/oauth.zig`)
   - Orchestrates the complete OAuth 2.0 authorization code flow
   - Manages session lifecycle
   - Handles token storage and retrieval

4. **Token Refresher** (`src/oauth.zig`)
   - Prevents concurrent token refreshes for the same key
   - Provides waiting mechanism for in-progress refreshes
   - Critical for ensuring token validity across process boundaries

5. **C API** (`src/c_api.zig`)
   - FFI layer for C compatibility
   - Uses opaque pointers for type safety
   - Provides error codes instead of exceptions

## Development Guidelines

### Code Style

- Follow Zig standard library conventions
- Use `const` by default, `var` only when mutation is needed
- Prefer explicit over implicit
- Always use `errdefer` for cleanup in error paths
- Document public APIs with doc comments (`///`)

### Testing

- Write tests inline using `test` blocks
- Integration tests go in `test/integration_test.zig`
- Run tests with: `zig build test`
- Ensure all tests pass before committing

### Building

- Development: `zig build`
- Cross-platform: `mise run build`
- Example: `zig build example`
- Clean build: `rm -rf zig-cache zig-out dist`

## Important Design Decisions

### 1. Thread Safety

All storage operations must be thread-safe. The `MemoryStorage` implementation uses a mutex to protect concurrent access. Custom storage implementations should follow the same pattern.

### 2. Token Refresh Concurrency

The `TokenRefresher` uses a hash map to track in-progress refreshes. When multiple callers request a refresh for the same token:
- The first caller performs the refresh
- Subsequent callers wait for the refresh to complete
- All callers receive the refreshed token

This prevents redundant refresh requests and potential race conditions.

### 3. Process Exit Handling

Token refreshes may be in-progress when a process exits. The `waitForRefresh` method allows callers to block until any in-progress refresh completes, ensuring:
- The refreshed token is persisted to storage
- No partial/invalid tokens are left in storage

### 4. Storage Abstraction

The storage interface is designed to support multiple backends:
- Memory (for testing/simple use cases)
- File-based (JSON, SQLite, etc.)
- OS keychains/credential managers
- Remote storage

When implementing a custom storage backend:
- Implement all vtable methods
- Ensure thread safety
- Handle allocation/deallocation correctly
- Use the allocator passed to `Session.init` and `Token` constructors

## Common Tasks

### Adding New OAuth Endpoints

1. Add configuration fields to `OAuthConfig`
2. Update URL building logic in `oauth.zig`
3. Add corresponding C API fields in `c_api.zig`
4. Update the C header in `include/schlussel.h`
5. Add tests for the new functionality

### Implementing a New Storage Backend

```zig
pub const MyStorage = struct {
    // Your storage state
    mutex: std.Thread.Mutex,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MyStorage {
        return .{
            .mutex = .{},
            .allocator = allocator,
        };
    }

    pub fn storage(self: *MyStorage) session.SessionStorage {
        return .{
            .ptr = self,
            .vtable = &.{
                .saveSession = saveSession,
                .getSession = getSession,
                .deleteSession = deleteSession,
                .saveToken = saveToken,
                .getToken = getToken,
                .deleteToken = deleteToken,
            },
        };
    }

    // Implement all vtable methods...
    fn saveSession(ptr: *anyopaque, state: []const u8, sess: session.Session) !void {
        const self: *MyStorage = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();
        // Implementation
    }
};
```

### Adding HTTP Client for Token Exchange

The current implementation does not include HTTP client code for the actual token exchange. To add this:

1. Add an HTTP client dependency (e.g., `std.http` or a third-party library)
2. Implement `exchangeCodeForToken` in `oauth.zig`
3. Implement `refreshTokenWithEndpoint` in `TokenRefresher`
4. Add TLS certificate validation
5. Add timeout and retry logic

Example structure:

```zig
pub fn exchangeCodeForToken(
    self: *OAuth,
    code: []const u8,
    state: []const u8,
) !TokenResponse {
    // 1. Retrieve session by state
    // 2. Build token request with code and code_verifier
    // 3. Make HTTP POST to token_endpoint
    // 4. Parse response JSON
    // 5. Return TokenResponse
    // 6. Delete session
}
```

## Security Considerations

1. **Always use PKCE**: Never allow fallback to non-PKCE flows
2. **Validate state parameter**: Always verify state matches to prevent CSRF
3. **Secure token storage**: Recommend encrypted storage in documentation
4. **HTTPS enforcement**: Validate that endpoints use HTTPS in production
5. **Token expiration**: Always check `token.isExpired()` before use
6. **Code verifier entropy**: Use cryptographically secure random number generator

## Cross-Platform Considerations

### Platform-Specific Behavior

- File paths: Use Zig's `std.fs.path` for cross-platform path handling
- Line endings: Be consistent with `\n` in code
- Shared library naming: Handled automatically by Zig build system

### Build Targets

The project builds for:
- Linux: x86_64, aarch64
- macOS: x86_64 (Intel), aarch64 (Apple Silicon)
- Windows: x86_64, aarch64

Test on multiple platforms when making changes to:
- File I/O
- Network code (when added)
- Thread synchronization
- Time handling

## Troubleshooting

### Common Build Issues

1. **Missing Zig**: Run `mise install` to install required tools
2. **Build fails on specific target**: Check Zig version compatibility
3. **Tests fail**: Ensure no environment-specific assumptions

### Common Runtime Issues

1. **Memory leaks**: Always pair init/deinit, use errdefer
2. **Segfaults**: Check pointer alignment with @alignCast
3. **Race conditions**: Verify all storage operations use locks

## API Stability

### Stable APIs (do not break without major version bump)

- C API function signatures
- Public Zig struct fields
- Storage vtable interface

### Internal APIs (can change in minor versions)

- Private functions
- Implementation details
- Internal data structures

## Performance Considerations

1. **Allocations**: Minimize allocations in hot paths
2. **Locking**: Keep critical sections as short as possible
3. **Polling**: The refresh wait mechanism uses polling - consider condition variables for production
4. **String operations**: Use `std.mem.eql` instead of loops

## Future Enhancements

Potential areas for improvement:

1. HTTP client integration for complete OAuth flow
2. Condition variables instead of polling in `TokenRefresher`
3. More storage backends (SQLite, OS keychain, etc.)
4. OAuth 2.1 compliance
5. Device flow support (RFC 8628)
6. Better error messages and error context
7. Metrics and logging hooks
8. Token rotation strategies

## References

- [Zig Language Reference](https://ziglang.org/documentation/master/)
- [RFC 7636: PKCE](https://tools.ietf.org/html/rfc7636)
- [RFC 6749: OAuth 2.0](https://tools.ietf.org/html/rfc6749)
- [RFC 8252: OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
