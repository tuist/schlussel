import Darwin
import Foundation
@_implementationOnly import CSchlussel

public enum SchlusselErrorCode: Int32, Sendable {
    case ok = 0
    case invalidParameter = 1
    case storage = 2
    case http = 3
    case authorizationDenied = 4
    case tokenExpired = 5
    case noRefreshToken = 6
    case invalidState = 7
    case deviceCodeExpired = 8
    case json = 9
    case io = 10
    case server = 11
    case callbackServer = 12
    case configuration = 13
    case lock = 14
    case unsupported = 15
    case outOfMemory = 16
    case connectionFailed = 17
    case timeout = 18
    case authorizationPending = 19
    case slowDown = 20
    case unknown = 99
}

public struct SchlusselAPIError: Error, CustomStringConvertible, Sendable {
    public let code: SchlusselErrorCode
    public let message: String

    public var description: String {
        message
    }
}

public final class Token {
    fileprivate let handle: OpaquePointer

    fileprivate init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        schlussel_token_free(handle)
    }

    public var accessToken: String {
        ownedString(schlussel_token_get_access_token(handle)) ?? ""
    }

    public var refreshToken: String? {
        ownedString(schlussel_token_get_refresh_token(handle))
    }

    public var tokenType: String {
        ownedString(schlussel_token_get_token_type(handle)) ?? ""
    }

    public var scope: String? {
        ownedString(schlussel_token_get_scope(handle))
    }

    public var isExpired: Bool {
        schlussel_token_is_expired(handle) == 1
    }

    public var expiresAt: Date? {
        let timestamp = schlussel_token_get_expires_at(handle)
        guard timestamp != 0 else {
            return nil
        }
        return Date(timeIntervalSince1970: TimeInterval(timestamp))
    }
}

public final class Client {
    private let handle: OpaquePointer

    public init(githubClientID: String, scopes: String? = nil, appName: String) throws {
        let created = try withOptionalCString(scopes) { scopesPointer in
            try githubClientID.withCString { clientIDPointer in
                try appName.withCString { appNamePointer in
                    let handle = schlussel_client_new_github(
                        clientIDPointer,
                        scopesPointer,
                        appNamePointer
                    )
                    return try unwrap(handle)
                }
            }
        }
        handle = created
    }

    public init(googleClientID: String, scopes: String? = nil, appName: String) throws {
        let created = try withOptionalCString(scopes) { scopesPointer in
            try googleClientID.withCString { clientIDPointer in
                try appName.withCString { appNamePointer in
                    let handle = schlussel_client_new_google(
                        clientIDPointer,
                        scopesPointer,
                        appNamePointer
                    )
                    return try unwrap(handle)
                }
            }
        }
        handle = created
    }

    public init(
        clientID: String,
        authorizationEndpoint: String,
        tokenEndpoint: String,
        redirectURI: String,
        scopes: String? = nil,
        deviceAuthorizationEndpoint: String? = nil
    ) throws {
        let created = try withOptionalCString(scopes) { scopesPointer in
            try withOptionalCString(deviceAuthorizationEndpoint) { devicePointer in
                try clientID.withCString { clientIDPointer in
                    try authorizationEndpoint.withCString { authorizationPointer in
                        try tokenEndpoint.withCString { tokenPointer in
                            try redirectURI.withCString { redirectPointer in
                                let handle = schlussel_client_new(
                                    clientIDPointer,
                                    authorizationPointer,
                                    tokenPointer,
                                    redirectPointer,
                                    scopesPointer,
                                    devicePointer
                                )
                                return try unwrap(handle)
                            }
                        }
                    }
                }
            }
        }
        handle = created
    }

    deinit {
        schlussel_client_free(handle)
    }

    public func authorizeDevice() throws -> Token {
        try Token(handle: unwrap(schlussel_authorize_device(handle)))
    }

    public func authorize() throws -> Token {
        try Token(handle: unwrap(schlussel_authorize(handle)))
    }

    public func saveToken(_ token: Token, forKey key: String) throws {
        try key.withCString { keyPointer in
            try throwingStatus(schlussel_save_token(handle, keyPointer, token.handle))
        }
    }

    public func token(forKey key: String) throws -> Token? {
        try key.withCString { keyPointer in
            let tokenHandle = schlussel_get_token(handle, keyPointer)
            if let tokenHandle {
                return Token(handle: tokenHandle)
            } else if schlussel_last_error_code() != 0 {
                throw lastError()
            } else {
                return nil
            }
        }
    }

    public func deleteToken(forKey key: String) throws {
        try key.withCString { keyPointer in
            try throwingStatus(schlussel_delete_token(handle, keyPointer))
        }
    }

    public func refreshToken(_ refreshToken: String) throws -> Token {
        try refreshToken.withCString { tokenPointer in
            try Token(handle: unwrap(schlussel_refresh_token(handle, tokenPointer)))
        }
    }
}

public struct RegistrationMetadata: Sendable {
    public var redirectURIs: [String]
    public var clientName: String?
    public var grantTypes: [String]
    public var responseTypes: [String]
    public var scope: String?
    public var tokenEndpointAuthMethod: String?

    public init(
        redirectURIs: [String],
        clientName: String? = nil,
        grantTypes: [String] = [],
        responseTypes: [String] = [],
        scope: String? = nil,
        tokenEndpointAuthMethod: String? = nil
    ) {
        self.redirectURIs = redirectURIs
        self.clientName = clientName
        self.grantTypes = grantTypes
        self.responseTypes = responseTypes
        self.scope = scope
        self.tokenEndpointAuthMethod = tokenEndpointAuthMethod
    }
}

public final class RegistrationResponse {
    private let handle: OpaquePointer

    fileprivate init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        schlussel_registration_response_free(handle)
    }

    public var clientID: String {
        ownedString(schlussel_registration_response_get_client_id(handle)) ?? ""
    }

    public var clientSecret: String? {
        ownedString(schlussel_registration_response_get_client_secret(handle))
    }

    public var clientIDIssuedAt: Date? {
        date(from: schlussel_registration_response_get_client_id_issued_at(handle))
    }

    public var clientSecretExpiresAt: Date? {
        date(from: schlussel_registration_response_get_client_secret_expires_at(handle))
    }

    public var registrationAccessToken: String? {
        ownedString(schlussel_registration_response_get_registration_access_token(handle))
    }

    public var registrationClientURI: String? {
        ownedString(schlussel_registration_response_get_registration_client_uri(handle))
    }
}

public final class RegistrationClient {
    private let handle: OpaquePointer

    public init(endpoint: String) throws {
        let created = try endpoint.withCString { endpointPointer in
            try unwrap(schlussel_registration_new(endpointPointer))
        }
        handle = created
    }

    deinit {
        schlussel_registration_free(handle)
    }

    public func register(_ metadata: RegistrationMetadata) throws -> RegistrationResponse {
        try registrationCall(token: nil, metadata: metadata) {
            schlussel_register_client(
                handle,
                $0.redirectURIs,
                $0.redirectURICount,
                $0.clientName,
                $0.grantTypes,
                $0.responseTypes,
                $0.scope,
                $0.tokenEndpointAuthMethod
            )
        }
    }

    public func read(registrationAccessToken: String) throws -> RegistrationResponse {
        try registrationAccessToken.withCString { tokenPointer in
            try RegistrationResponse(
                handle: unwrap(schlussel_registration_read(handle, tokenPointer))
            )
        }
    }

    public func update(
        registrationAccessToken: String,
        metadata: RegistrationMetadata
    ) throws -> RegistrationResponse {
        try registrationCall(token: registrationAccessToken, metadata: metadata) { values in
            schlussel_registration_update(
                handle,
                values.token,
                values.redirectURIs,
                values.redirectURICount,
                values.clientName,
                values.grantTypes,
                values.responseTypes,
                values.scope,
                values.tokenEndpointAuthMethod
            )
        }
    }

    public func delete(registrationAccessToken: String) throws {
        try registrationAccessToken.withCString { tokenPointer in
            try throwingStatus(schlussel_registration_delete(handle, tokenPointer))
        }
    }
}

private struct RegistrationCallValues {
    let token: UnsafePointer<CChar>?
    let redirectURIs: UnsafeMutablePointer<UnsafePointer<CChar>?>?
    let redirectURICount: Int
    let clientName: UnsafePointer<CChar>?
    let grantTypes: UnsafePointer<CChar>?
    let responseTypes: UnsafePointer<CChar>?
    let scope: UnsafePointer<CChar>?
    let tokenEndpointAuthMethod: UnsafePointer<CChar>?
}

private func registrationCall(
    token: String?,
    metadata: RegistrationMetadata,
    body: (RegistrationCallValues) throws -> OpaquePointer?
) throws -> RegistrationResponse {
    try withOptionalCString(token) { tokenPointer in
        try withCStringArray(metadata.redirectURIs) { redirectURIPointer, redirectURICount in
            try withOptionalCString(metadata.clientName) { clientNamePointer in
                try withOptionalCString(joined(metadata.grantTypes)) { grantTypesPointer in
                    try withOptionalCString(joined(metadata.responseTypes)) { responseTypesPointer in
                        try withOptionalCString(metadata.scope) { scopePointer in
                            try withOptionalCString(metadata.tokenEndpointAuthMethod) { authMethodPointer in
                                let values = RegistrationCallValues(
                                    token: tokenPointer,
                                    redirectURIs: redirectURIPointer,
                                    redirectURICount: redirectURICount,
                                    clientName: clientNamePointer,
                                    grantTypes: grantTypesPointer,
                                    responseTypes: responseTypesPointer,
                                    scope: scopePointer,
                                    tokenEndpointAuthMethod: authMethodPointer
                                )
                                return try RegistrationResponse(handle: unwrap(body(values)))
                            }
                        }
                    }
                }
            }
        }
    }
}

private func throwingStatus(_ status: CSchlussel.SchlusselError) throws {
    guard status == SCHLUSSEL_OK else {
        throw lastError(fallbackCode: Int32(bitPattern: status.rawValue))
    }
}

private func throwingStatus(_ status: Int32) throws {
    guard status == 0 else {
        throw lastError(fallbackCode: status)
    }
}

private func unwrap<T>(_ value: T?) throws -> T {
    guard let value else {
        throw lastError()
    }
    return value
}

private func lastError(fallbackCode: Int32? = nil) -> SchlusselAPIError {
    let rawCode = fallbackCode ?? schlussel_last_error_code()
    let code = SchlusselErrorCode(rawValue: rawCode) ?? .unknown
    let message = ownedString(schlussel_last_error_message()) ?? "Unknown Schlussel error"
    return SchlusselAPIError(code: code, message: message)
}

private func ownedString(_ pointer: UnsafeMutablePointer<CChar>?) -> String? {
    guard let pointer else {
        return nil
    }
    defer {
        schlussel_string_free(pointer)
    }
    return String(cString: pointer)
}

private func withOptionalCString<T>(
    _ value: String?,
    body: (UnsafePointer<CChar>?) throws -> T
) rethrows -> T {
    if let value {
        return try value.withCString(body)
    } else {
        return try body(nil)
    }
}

private func withCStringArray<T>(
    _ values: [String],
    body: (UnsafeMutablePointer<UnsafePointer<CChar>?>?, Int) throws -> T
) rethrows -> T {
    let duplicated = values.map { strdup($0) }
    defer {
        for pointer in duplicated {
            if let pointer {
                free(pointer)
            }
        }
    }

    var pointers = duplicated.map { pointer in
        pointer.map { UnsafePointer<CChar>($0) }
    }
    return try pointers.withUnsafeMutableBufferPointer { buffer in
        try body(buffer.baseAddress, values.count)
    }
}

private func joined(_ values: [String]) -> String? {
    values.isEmpty ? nil : values.joined(separator: ",")
}

private func date(from timestamp: Int64) -> Date? {
    guard timestamp > 0 else {
        return nil
    }
    return Date(timeIntervalSince1970: TimeInterval(timestamp))
}
