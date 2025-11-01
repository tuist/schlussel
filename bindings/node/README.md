# @tuist/schlussel

OAuth 2.0 with PKCE for Node.js command-line applications.

## Installation

```bash
npm install @tuist/schlussel
```

## Usage

```javascript
const { OAuthClient, MemoryStorage, TokenRefresher } = require('@tuist/schlussel');

// Create storage
const storage = new MemoryStorage();

// Configure OAuth
const client = new OAuthClient({
  clientId: 'your-client-id',
  authorizationEndpoint: 'https://accounts.example.com/oauth/authorize',
  tokenEndpoint: 'https://accounts.example.com/oauth/token',
  redirectUri: 'http://localhost:8080/callback',
  scope: 'read write'
}, storage);

// Start OAuth flow
const { url, state } = client.startAuthFlow();
console.log('Please open this URL in your browser:');
console.log(url);
console.log('\nState:', state);

// Create token refresher for managing token refresh
const refresher = new TokenRefresher(client);

// Ensure token refresh completes before process exit
process.on('beforeExit', () => {
  refresher.waitForRefresh('my-token-key');

  // Cleanup
  refresher.destroy();
  client.destroy();
  storage.destroy();
});
```

## API Documentation

### `getVersion()`

Get the version of the Schlussel library.

**Returns:** `string` - Version string

### `class MemoryStorage`

In-memory storage for sessions and tokens. Suitable for testing and simple use cases.

#### `constructor()`

Create a new memory storage instance.

#### `destroy()`

Free resources associated with the storage.

### `class OAuthClient`

OAuth 2.0 client with PKCE support.

#### `constructor(config, storage)`

Create a new OAuth client.

**Parameters:**
- `config` (Object) - OAuth configuration
  - `clientId` (string) - OAuth client ID
  - `authorizationEndpoint` (string) - Authorization server URL
  - `tokenEndpoint` (string) - Token endpoint URL
  - `redirectUri` (string) - Redirect URI for callback
  - `scope` (string, optional) - OAuth scope
- `storage` (MemoryStorage) - Storage backend

#### `startAuthFlow()`

Start the OAuth authorization flow.

**Returns:** Object with:
- `url` (string) - Authorization URL to open in browser
- `state` (string) - State parameter for CSRF protection

#### `destroy()`

Free resources associated with the client.

### `class TokenRefresher`

Manages token refresh with concurrency control.

#### `constructor(client)`

Create a new token refresher.

**Parameters:**
- `client` (OAuthClient) - OAuth client instance

#### `waitForRefresh(key)`

Wait for any in-progress token refresh to complete.

**Parameters:**
- `key` (string) - Token key to wait for

#### `destroy()`

Free resources associated with the refresher.

## Platform Support

The library includes native bindings for:
- macOS (Intel and Apple Silicon)
- Linux (x86_64 and ARM64)
- Windows (x86_64 and ARM64)

## License

MIT
