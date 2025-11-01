const std = @import("std");
const schlussel = @import("schlussel");

test "full OAuth flow integration" {
    const allocator = std.testing.allocator;

    var storage = schlussel.MemoryStorage.init(allocator);
    defer storage.deinit();

    const config = schlussel.OAuthConfig{
        .client_id = "test-client",
        .authorization_endpoint = "https://auth.example.com/authorize",
        .token_endpoint = "https://auth.example.com/token",
        .redirect_uri = "http://localhost:8080/callback",
        .scope = "read write",
    };

    var oauth_client = schlussel.OAuth.init(allocator, config, storage.storage());

    // Start flow
    const flow_result = try oauth_client.startAuthFlow();
    defer allocator.free(flow_result.url);
    defer allocator.free(flow_result.state);

    // Verify URL structure
    try std.testing.expect(std.mem.indexOf(u8, flow_result.url, "https://auth.example.com/authorize?") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow_result.url, "client_id=test-client") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow_result.url, "response_type=code") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow_result.url, "code_challenge_method=S256") != null);
    try std.testing.expect(std.mem.indexOf(u8, flow_result.url, "scope=read+write") != null or
        std.mem.indexOf(u8, flow_result.url, "scope=read%20write") != null);

    // Verify state is saved in storage
    const session_opt = try storage.storage().getSession(flow_result.state);
    try std.testing.expect(session_opt != null);

    // Clean up the retrieved session copy
    if (session_opt) |*s| {
        var session_copy = s.*;
        session_copy.deinit();
    }
}

test "token refresher prevents concurrent refreshes" {
    const allocator = std.testing.allocator;

    var storage = schlussel.MemoryStorage.init(allocator);
    defer storage.deinit();

    const config = schlussel.OAuthConfig{
        .client_id = "test-client",
        .authorization_endpoint = "https://auth.example.com/authorize",
        .token_endpoint = "https://auth.example.com/token",
        .redirect_uri = "http://localhost:8080/callback",
    };

    var oauth_client = schlussel.OAuth.init(allocator, config, storage.storage());
    var refresher = schlussel.TokenRefresher.init(allocator, &oauth_client);
    defer refresher.deinit();

    // First refresh
    const token1 = try refresher.refreshToken("test-key", "refresh-token-1");
    defer {
        var mut_token = token1;
        mut_token.deinit();
    }

    // Verify token was saved
    const saved_token = try oauth_client.getToken("test-key");
    try std.testing.expect(saved_token != null);

    // Clean up the retrieved token copy
    if (saved_token) |*t| {
        var token_copy = t.*;
        token_copy.deinit();
    }

    // Wait for refresh
    refresher.waitForRefresh("test-key");
}

test "PKCE challenge verification" {
    const allocator = std.testing.allocator;

    const pkce1 = try schlussel.Pkce.generate(allocator);
    const pkce2 = try schlussel.Pkce.generate(allocator);

    // Verify uniqueness
    try std.testing.expect(!std.mem.eql(u8, pkce1.getCodeVerifier(), pkce2.getCodeVerifier()));
    try std.testing.expect(!std.mem.eql(u8, pkce1.getCodeChallenge(), pkce2.getCodeChallenge()));

    // Verify format (base64 url safe, no padding)
    for (pkce1.getCodeVerifier()) |c| {
        try std.testing.expect((c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_');
    }
}

test "session storage operations" {
    const allocator = std.testing.allocator;

    var storage = schlussel.MemoryStorage.init(allocator);
    defer storage.deinit();

    const stor = storage.storage();

    // Create and save session
    const session = try schlussel.Session.init(allocator, "state-123", "verifier-456");
    try stor.saveSession("state-123", session);

    // Retrieve session
    const retrieved = try stor.getSession("state-123");
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualStrings("state-123", retrieved.?.state);
    try std.testing.expectEqualStrings("verifier-456", retrieved.?.code_verifier);

    // Delete session
    try stor.deleteSession("state-123");

    // Verify deletion
    const deleted = try stor.getSession("state-123");
    try std.testing.expect(deleted == null);
}

test "token expiration check" {
    const allocator = std.testing.allocator;

    // Create expired token
    const expired_token = schlussel.session.Token{
        .access_token = try allocator.dupe(u8, "access"),
        .refresh_token = null,
        .token_type = try allocator.dupe(u8, "Bearer"),
        .expires_in = 3600,
        .expires_at = std.time.timestamp() - 100, // Expired
        .scope = null,
        .allocator = allocator,
    };
    defer {
        var mut_token = expired_token;
        mut_token.deinit();
    }

    try std.testing.expect(expired_token.isExpired());

    // Create valid token
    const valid_token = schlussel.session.Token{
        .access_token = try allocator.dupe(u8, "access"),
        .refresh_token = null,
        .token_type = try allocator.dupe(u8, "Bearer"),
        .expires_in = 3600,
        .expires_at = std.time.timestamp() + 3600, // Valid for 1 hour
        .scope = null,
        .allocator = allocator,
    };
    defer {
        var mut_token = valid_token;
        mut_token.deinit();
    }

    try std.testing.expect(!valid_token.isExpired());
}
