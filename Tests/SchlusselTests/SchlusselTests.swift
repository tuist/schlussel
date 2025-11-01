import XCTest
@testable import Schlussel

final class SchlusselTests: XCTestCase {
    func testVersion() throws {
        let version = getVersion()
        XCTAssertEqual(version, "0.1.0")
    }

    func testMemoryStorageCreation() throws {
        let storage = try MemoryStorage()
        XCTAssertNotNil(storage)
    }

    func testOAuthClientCreation() throws {
        let storage = try MemoryStorage()
        let config = OAuthConfig(
            clientId: "test-client",
            authorizationEndpoint: "https://auth.example.com/authorize",
            tokenEndpoint: "https://auth.example.com/token",
            redirectUri: "http://localhost:8080/callback",
            scope: "read write"
        )

        let client = try OAuthClient(config: config, storage: storage)
        XCTAssertNotNil(client)
    }

    func testStartAuthFlow() throws {
        let storage = try MemoryStorage()
        let config = OAuthConfig(
            clientId: "test-client",
            authorizationEndpoint: "https://auth.example.com/authorize",
            tokenEndpoint: "https://auth.example.com/token",
            redirectUri: "http://localhost:8080/callback",
            scope: "read write"
        )

        let client = try OAuthClient(config: config, storage: storage)
        let result = try client.startAuthFlow()

        XCTAssertFalse(result.url.isEmpty)
        XCTAssertFalse(result.state.isEmpty)
        XCTAssertTrue(result.url.contains("client_id=test-client"))
        XCTAssertTrue(result.url.contains("code_challenge_method=S256"))
        XCTAssertTrue(result.url.contains("response_type=code"))
    }

    func testTokenRefresherCreation() throws {
        let storage = try MemoryStorage()
        let config = OAuthConfig(
            clientId: "test-client",
            authorizationEndpoint: "https://auth.example.com/authorize",
            tokenEndpoint: "https://auth.example.com/token",
            redirectUri: "http://localhost:8080/callback"
        )

        let client = try OAuthClient(config: config, storage: storage)
        let refresher = try TokenRefresher(client: client)

        XCTAssertNotNil(refresher)
    }
}
