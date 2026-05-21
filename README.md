# Schlussel

Cross-platform OAuth 2.0 library for command-line and desktop applications.

Schlussel handles PKCE, Device Code Flow, callback-based authorization, token
storage, and refresh coordination so applications can integrate OAuth without
rebuilding the plumbing every time.

## Features

- PKCE support compliant with RFC 7636
- Device Code Flow support compliant with RFC 8628
- Authorization Code Flow with a local callback server
- Dynamic client registration support
- Secure token storage through OS credential managers
- Cross-process-safe token refresh locking
- Provider presets for common OAuth platforms

## Build

```bash
zig build
zig build test
zig build docs
```

## Library Usage

```zig
const schlussel = @import("schlussel");

var storage = schlussel.MemoryStorage.init(allocator);
defer storage.deinit();

const config = schlussel.OAuthConfig.github("your-client-id", "repo user");
var client = schlussel.OAuthClient.init(allocator, config, storage.storage());
defer client.deinit();

var token = try client.authorizeDevice();
defer token.deinit();
```

## CLI

The bundled CLI is a small token storage helper.

```bash
# List stored keys
schlussel token list

# Filter by prefix
schlussel token list --key my-app:

# Read a stored token
schlussel token get --key my-app:primary

# Delete a stored token
schlussel token delete --key my-app:primary
```

## Documentation

API documentation is generated locally from source comments:

```bash
zig build docs
```

## Contributing

Run the test suite and format checks before sending changes:

```bash
zig build test
zig fmt --check src/
```

## License

See [LICENSE](LICENSE).
