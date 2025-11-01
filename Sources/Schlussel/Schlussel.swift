import Foundation
import SchlusselFFI

/// Error codes returned by the native library
public enum SchlusselError: Int32, Error {
    case ok = 0
    case outOfMemory = 1
    case invalidArgument = 2
    case notFound = 3
    case unknown = 99

    public var localizedDescription: String {
        switch self {
        case .ok:
            return "Success"
        case .outOfMemory:
            return "Out of memory"
        case .invalidArgument:
            return "Invalid argument"
        case .notFound:
            return "Not found"
        case .unknown:
            return "Unknown error"
        }
    }
}

/// OAuth 2.0 configuration
public struct OAuthConfig {
    /// OAuth client ID
    public let clientId: String

    /// Authorization server URL
    public let authorizationEndpoint: String

    /// Token endpoint URL
    public let tokenEndpoint: String

    /// Redirect URI for OAuth callback
    public let redirectUri: String

    /// Optional OAuth scope
    public let scope: String?

    public init(
        clientId: String,
        authorizationEndpoint: String,
        tokenEndpoint: String,
        redirectUri: String,
        scope: String? = nil
    ) {
        self.clientId = clientId
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.redirectUri = redirectUri
        self.scope = scope
    }
}

/// Authorization flow result
public struct AuthFlowResult {
    /// Authorization URL to open in browser
    public let url: String

    /// State parameter for CSRF protection
    public let state: String

    public init(url: String, state: String) {
        self.url = url
        self.state = state
    }
}

/// In-memory storage for sessions and tokens
///
/// This is suitable for testing and simple use cases. For production,
/// consider implementing persistent storage.
public class MemoryStorage {
    private var handle: OpaquePointer?

    public init() throws {
        handle = schlussel_storage_memory_create()
        guard handle != nil else {
            throw SchlusselError.outOfMemory
        }
    }

    deinit {
        if let handle = handle {
            schlussel_storage_destroy(handle)
        }
    }

    internal func getHandle() -> OpaquePointer? {
        return handle
    }
}

/// OAuth 2.0 client with PKCE support
///
/// Manages the OAuth authorization code flow with PKCE (Proof Key for Code Exchange).
/// PKCE makes the flow secure for public clients like CLI and mobile applications.
///
/// Example:
/// ```swift
/// let storage = try MemoryStorage()
/// let config = OAuthConfig(
///     clientId: "my-app",
///     authorizationEndpoint: "https://auth.example.com/authorize",
///     tokenEndpoint: "https://auth.example.com/token",
///     redirectUri: "myapp://callback",
///     scope: "read write"
/// )
/// let client = try OAuthClient(config: config, storage: storage)
/// let result = try client.startAuthFlow()
/// print("Open this URL: \(result.url)")
/// ```
public class OAuthClient {
    private var handle: OpaquePointer?
    private let storage: MemoryStorage

    /// Create a new OAuth client
    /// - Parameters:
    ///   - config: OAuth configuration
    ///   - storage: Storage backend for sessions and tokens
    /// - Throws: `SchlusselError` if client creation fails
    public init(config: OAuthConfig, storage: MemoryStorage) throws {
        self.storage = storage

        let cConfig = SchlusselOAuthConfig(
            client_id: strdup(config.clientId),
            authorization_endpoint: strdup(config.authorizationEndpoint),
            token_endpoint: strdup(config.tokenEndpoint),
            redirect_uri: strdup(config.redirectUri),
            scope: config.scope.map { strdup($0) }
        )

        defer {
            free(UnsafeMutableRawPointer(mutating: cConfig.client_id))
            free(UnsafeMutableRawPointer(mutating: cConfig.authorization_endpoint))
            free(UnsafeMutableRawPointer(mutating: cConfig.token_endpoint))
            free(UnsafeMutableRawPointer(mutating: cConfig.redirect_uri))
            if let scope = cConfig.scope {
                free(UnsafeMutableRawPointer(mutating: scope))
            }
        }

        var config = cConfig
        handle = withUnsafePointer(to: &config) { configPtr in
            schlussel_oauth_create(configPtr, storage.getHandle())
        }

        guard handle != nil else {
            throw SchlusselError.outOfMemory
        }
    }

    deinit {
        if let handle = handle {
            schlussel_oauth_destroy(handle)
        }
    }

    /// Start the OAuth authorization flow
    ///
    /// Generates a PKCE challenge, creates a session, and returns the authorization URL
    /// that the user should open in their browser.
    ///
    /// - Returns: Authorization flow result containing URL and state
    /// - Throws: `SchlusselError` if the flow cannot be started
    public func startAuthFlow() throws -> AuthFlowResult {
        var flowResult = SchlusselAuthFlow(url: nil, state: nil)

        let errorCode = withUnsafeMutablePointer(to: &flowResult) { resultPtr in
            schlussel_oauth_start_flow(handle, resultPtr)
        }

        guard errorCode == 0 else {
            throw SchlusselError(rawValue: errorCode) ?? .unknown
        }

        guard let urlPtr = flowResult.url, let statePtr = flowResult.state else {
            throw SchlusselError.unknown
        }

        let url = String(cString: urlPtr)
        let state = String(cString: statePtr)

        // Free the C strings
        withUnsafeMutablePointer(to: &flowResult) { resultPtr in
            schlussel_auth_flow_free(resultPtr)
        }

        return AuthFlowResult(url: url, state: state)
    }

    internal func getHandle() -> OpaquePointer? {
        return handle
    }
}

/// Token refresher with concurrency control
///
/// Manages token refresh operations, ensuring that only one refresh happens
/// at a time for a given token. If multiple processes request a refresh
/// simultaneously, subsequent requests wait for the first to complete.
///
/// Example:
/// ```swift
/// let refresher = try TokenRefresher(client: client)
///
/// // Before app exit, ensure refresh completes
/// defer {
///     refresher.waitForRefresh(key: "my-token-key")
/// }
/// ```
public class TokenRefresher {
    private var handle: OpaquePointer?
    private let client: OAuthClient

    /// Create a new token refresher
    /// - Parameter client: OAuth client to use for refresh operations
    /// - Throws: `SchlusselError` if refresher creation fails
    public init(client: OAuthClient) throws {
        self.client = client

        handle = schlussel_token_refresher_create(client.getHandle())
        guard handle != nil else {
            throw SchlusselError.outOfMemory
        }
    }

    deinit {
        if let handle = handle {
            schlussel_token_refresher_destroy(handle)
        }
    }

    /// Wait for any in-progress token refresh to complete
    ///
    /// This should be called before process exit to ensure that token refresh
    /// operations complete and the updated token is persisted to storage.
    /// Otherwise, you might end up with an invalid token.
    ///
    /// - Parameter key: Token key to wait for
    public func waitForRefresh(key: String) {
        schlussel_token_refresher_wait(handle, key)
    }
}

/// Get the version of the Schlussel library
/// - Returns: Version string
public func getVersion() -> String {
    guard let version = schlussel_version() else {
        return "unknown"
    }
    return String(cString: version)
}
