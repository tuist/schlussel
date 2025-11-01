/**
 * @fileoverview Schlussel - OAuth 2.0 with PKCE for Node.js CLIs
 *
 * This module provides a JavaScript wrapper around the native Schlussel library,
 * enabling OAuth 2.0 authorization code flow with PKCE for command-line applications.
 *
 * @example
 * const { OAuthClient, MemoryStorage } = require('@tuist/schlussel');
 *
 * const storage = new MemoryStorage();
 * const client = new OAuthClient({
 *   clientId: 'your-client-id',
 *   authorizationEndpoint: 'https://accounts.example.com/oauth/authorize',
 *   tokenEndpoint: 'https://accounts.example.com/oauth/token',
 *   redirectUri: 'http://localhost:8080/callback',
 *   scope: 'read write'
 * }, storage);
 *
 * const { url, state } = client.startAuthFlow();
 * console.log('Open this URL:', url);
 */

const ref = require('ref-napi');
const Struct = require('ref-struct-di')(ref);
const { lib, types } = require('./lib');

/**
 * Error codes returned by the native library
 * @enum {number}
 */
const ErrorCode = {
  OK: 0,
  OUT_OF_MEMORY: 1,
  INVALID_ARGUMENT: 2,
  NOT_FOUND: 3,
  UNKNOWN: 99
};

/**
 * Get the version of the Schlussel library
 * @returns {string} Version string
 */
function getVersion() {
  return lib.schlussel_version();
}

/**
 * In-memory storage implementation for sessions and tokens
 * This is suitable for testing and simple use cases. For production,
 * consider implementing persistent storage.
 *
 * @class
 * @example
 * const storage = new MemoryStorage();
 * // Storage is automatically cleaned up when garbage collected
 */
class MemoryStorage {
  constructor() {
    this._handle = lib.schlussel_storage_memory_create();
    if (this._handle.isNull()) {
      throw new Error('Failed to create memory storage');
    }
  }

  /**
   * Get the native handle (internal use)
   * @private
   * @returns {object} Native storage handle
   */
  _getHandle() {
    return this._handle;
  }

  /**
   * Destroy the storage and free resources
   */
  destroy() {
    if (this._handle && !this._handle.isNull()) {
      lib.schlussel_storage_destroy(this._handle);
      this._handle = null;
    }
  }
}

/**
 * OAuth 2.0 client configuration
 * @typedef {Object} OAuthConfig
 * @property {string} clientId - OAuth client ID
 * @property {string} authorizationEndpoint - Authorization server URL
 * @property {string} tokenEndpoint - Token endpoint URL
 * @property {string} redirectUri - Redirect URI for OAuth callback
 * @property {string} [scope] - Optional scope parameter
 */

/**
 * Authorization flow result
 * @typedef {Object} AuthFlowResult
 * @property {string} url - Authorization URL to open in browser
 * @property {string} state - State parameter for CSRF protection
 */

/**
 * OAuth 2.0 client with PKCE support
 *
 * Manages the OAuth authorization code flow with PKCE (Proof Key for Code Exchange).
 * PKCE makes the flow secure for public clients like CLI applications.
 *
 * @class
 * @example
 * const client = new OAuthClient({
 *   clientId: 'my-app',
 *   authorizationEndpoint: 'https://auth.example.com/authorize',
 *   tokenEndpoint: 'https://auth.example.com/token',
 *   redirectUri: 'http://localhost:8080/callback',
 *   scope: 'read write'
 * }, storage);
 */
class OAuthClient {
  /**
   * Create a new OAuth client
   * @param {OAuthConfig} config - OAuth configuration
   * @param {MemoryStorage} storage - Storage backend for sessions and tokens
   */
  constructor(config, storage) {
    this._config = config;
    this._storage = storage;

    // Create C struct for config
    const ConfigStruct = Struct({
      client_id: 'string',
      authorization_endpoint: 'string',
      token_endpoint: 'string',
      redirect_uri: 'string',
      scope: 'string'
    });

    const configData = new ConfigStruct({
      client_id: config.clientId,
      authorization_endpoint: config.authorizationEndpoint,
      token_endpoint: config.tokenEndpoint,
      redirect_uri: config.redirectUri,
      scope: config.scope || null
    });

    this._handle = lib.schlussel_oauth_create(configData.ref(), storage._getHandle());
    if (this._handle.isNull()) {
      throw new Error('Failed to create OAuth client');
    }
  }

  /**
   * Start the OAuth authorization flow
   *
   * Generates a PKCE challenge, creates a session, and returns the authorization URL
   * that the user should open in their browser.
   *
   * @returns {AuthFlowResult} Object containing the authorization URL and state
   * @throws {Error} If the flow cannot be started
   *
   * @example
   * const { url, state } = client.startAuthFlow();
   * console.log('Please open this URL in your browser:');
   * console.log(url);
   * console.log('State:', state);
   */
  startAuthFlow() {
    // Create result struct
    const FlowStruct = Struct({
      url: 'string',
      state: 'string'
    });

    const flowResult = new FlowStruct();
    const err = lib.schlussel_oauth_start_flow(this._handle, flowResult.ref());

    if (err !== ErrorCode.OK) {
      throw new Error(`Failed to start OAuth flow: error code ${err}`);
    }

    const result = {
      url: flowResult.url,
      state: flowResult.state
    };

    // Free the C strings
    lib.schlussel_auth_flow_free(flowResult.ref());

    return result;
  }

  /**
   * Get the native handle (internal use)
   * @private
   * @returns {object} Native OAuth client handle
   */
  _getHandle() {
    return this._handle;
  }

  /**
   * Destroy the client and free resources
   */
  destroy() {
    if (this._handle && !this._handle.isNull()) {
      lib.schlussel_oauth_destroy(this._handle);
      this._handle = null;
    }
  }
}

/**
 * Token refresher with concurrency control
 *
 * Manages token refresh operations, ensuring that only one refresh happens
 * at a time for a given token. If multiple processes request a refresh
 * simultaneously, subsequent requests wait for the first to complete.
 *
 * @class
 * @example
 * const refresher = new TokenRefresher(client);
 *
 * // Before process exit, ensure refresh completes
 * process.on('beforeExit', () => {
 *   refresher.waitForRefresh('my-token-key');
 * });
 */
class TokenRefresher {
  /**
   * Create a new token refresher
   * @param {OAuthClient} client - OAuth client to use for refresh operations
   */
  constructor(client) {
    this._client = client;
    this._handle = lib.schlussel_token_refresher_create(client._getHandle());
    if (this._handle.isNull()) {
      throw new Error('Failed to create token refresher');
    }
  }

  /**
   * Wait for any in-progress token refresh to complete
   *
   * This should be called before process exit to ensure that token refresh
   * operations complete and the updated token is persisted to storage.
   * Otherwise, you might end up with an invalid token.
   *
   * @param {string} key - Token key to wait for
   *
   * @example
   * // Ensure token refresh completes before exit
   * process.on('beforeExit', () => {
   *   refresher.waitForRefresh('my-app-token');
   * });
   */
  waitForRefresh(key) {
    lib.schlussel_token_refresher_wait(this._handle, key);
  }

  /**
   * Destroy the refresher and free resources
   */
  destroy() {
    if (this._handle && !this._handle.isNull()) {
      lib.schlussel_token_refresher_destroy(this._handle);
      this._handle = null;
    }
  }
}

module.exports = {
  getVersion,
  MemoryStorage,
  OAuthClient,
  TokenRefresher,
  ErrorCode
};
