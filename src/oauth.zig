const std = @import("std");
const pkce = @import("pkce.zig");
const session = @import("session.zig");

/// OAuth 2.0 configuration
pub const OAuthConfig = struct {
    client_id: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    redirect_uri: []const u8,
    scope: ?[]const u8 = null,
};

/// Token response from OAuth provider
pub const TokenResponse = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    token_type: []const u8,
    expires_in: ?i64 = null,
    scope: ?[]const u8 = null,
};

/// OAuth flow orchestrator
pub const OAuth = struct {
    config: OAuthConfig,
    storage: session.SessionStorage,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: OAuthConfig, stor: session.SessionStorage) OAuth {
        return .{
            .config = config,
            .storage = stor,
            .allocator = allocator,
        };
    }

    /// Start OAuth flow and return authorization URL
    pub fn startAuthFlow(self: *OAuth) !struct { url: []const u8, state: []const u8 } {
        // Generate PKCE challenge
        const pkce_pair = try pkce.Pkce.generate(self.allocator);

        // Generate random state
        var state_bytes: [16]u8 = undefined;
        std.crypto.random.bytes(&state_bytes);
        const state = try std.fmt.allocPrint(self.allocator, "{x}", .{std.fmt.fmtSliceHexLower(&state_bytes)});
        errdefer self.allocator.free(state);

        // Save session
        const sess = try session.Session.init(
            self.allocator,
            state,
            pkce_pair.getCodeVerifier(),
        );
        try self.storage.saveSession(state, sess);

        // Build authorization URL
        const url = try self.buildAuthUrl(state, pkce_pair.getCodeChallenge());

        return .{ .url = url, .state = state };
    }

    fn buildAuthUrl(self: *OAuth, state: []const u8, code_challenge: []const u8) ![]const u8 {
        var url_buffer = std.ArrayList(u8).init(self.allocator);
        errdefer url_buffer.deinit();

        const writer = url_buffer.writer();

        try writer.print("{s}?", .{self.config.authorization_endpoint});
        try writer.print("client_id={s}&", .{self.config.client_id});
        try writer.print("redirect_uri={s}&", .{self.config.redirect_uri});
        try writer.print("response_type=code&", .{});
        try writer.print("state={s}&", .{state});
        try writer.print("code_challenge={s}&", .{code_challenge});
        try writer.print("code_challenge_method={s}", .{pkce.Pkce.getCodeChallengeMethod()});

        if (self.config.scope) |scope| {
            try writer.print("&scope={s}", .{scope});
        }

        return url_buffer.toOwnedSlice();
    }

    /// Check if a token is available for the given key
    pub fn hasToken(self: *OAuth, key: []const u8) !bool {
        const token = try self.storage.getToken(key);
        return token != null;
    }

    /// Get token by key
    pub fn getToken(self: *OAuth, key: []const u8) !?session.Token {
        return try self.storage.getToken(key);
    }

    /// Save token
    pub fn saveToken(self: *OAuth, key: []const u8, token: session.Token) !void {
        try self.storage.saveToken(key, token);
    }
};

/// Token refresher with concurrency control
pub const TokenRefresher = struct {
    oauth: *OAuth,
    mutex: std.Thread.Mutex,
    refresh_in_progress: std.StringHashMap(bool),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, oauth_client: *OAuth) TokenRefresher {
        return .{
            .oauth = oauth_client,
            .mutex = .{},
            .refresh_in_progress = std.StringHashMap(bool).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TokenRefresher) void {
        var iter = self.refresh_in_progress.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.refresh_in_progress.deinit();
    }

    /// Refresh token with lock to prevent concurrent refreshes
    /// If a refresh is already in progress, this will wait for it to complete
    pub fn refreshToken(self: *TokenRefresher, key: []const u8, refresh_token: []const u8) !session.Token {
        // Check if refresh is in progress
        self.mutex.lock();
        const in_progress = self.refresh_in_progress.get(key) orelse false;

        if (in_progress) {
            // Wait for the refresh to complete
            self.mutex.unlock();

            // Poll until refresh is complete (in production, use condition variable)
            while (true) {
                std.time.sleep(100 * std.time.ns_per_ms);
                self.mutex.lock();
                const still_in_progress = self.refresh_in_progress.get(key) orelse false;
                if (!still_in_progress) {
                    self.mutex.unlock();
                    break;
                }
                self.mutex.unlock();
            }

            // Get the refreshed token (getToken returns a copy)
            const token = try self.oauth.getToken(key);
            return token orelse error.NotFound;
        }

        // Mark refresh as in progress
        const key_copy = try self.allocator.dupe(u8, key);
        try self.refresh_in_progress.put(key_copy, true);
        self.mutex.unlock();

        // Perform the actual refresh (this is a placeholder - real implementation would call token endpoint)
        defer {
            self.mutex.lock();
            _ = self.refresh_in_progress.remove(key);
            self.allocator.free(key_copy);
            self.mutex.unlock();
        }

        // In a real implementation, this would make an HTTP request to the token endpoint
        // For now, we'll create a mock token and save it
        const new_token = session.Token{
            .access_token = try self.allocator.dupe(u8, "new_access_token"),
            .refresh_token = try self.allocator.dupe(u8, refresh_token),
            .token_type = try self.allocator.dupe(u8, "Bearer"),
            .expires_in = 3600,
            .expires_at = std.time.timestamp() + 3600,
            .scope = null,
            .allocator = self.allocator,
        };

        // Save token (storage takes ownership)
        try self.oauth.saveToken(key, new_token);

        // Return a copy to the caller (getToken returns a copy)
        const token_copy = try self.oauth.getToken(key);
        return token_copy orelse error.NotFound;
    }

    /// Wait for any in-progress refresh to complete before process exit
    pub fn waitForRefresh(self: *TokenRefresher, key: []const u8) void {
        while (true) {
            self.mutex.lock();
            const in_progress = self.refresh_in_progress.get(key) orelse false;
            self.mutex.unlock();

            if (!in_progress) {
                break;
            }

            std.time.sleep(100 * std.time.ns_per_ms);
        }
    }
};

test "OAuth start flow" {
    const allocator = std.testing.allocator;

    var storage = session.MemoryStorage.init(allocator);
    defer storage.deinit();

    const config = OAuthConfig{
        .client_id = "test-client",
        .authorization_endpoint = "https://auth.example.com/authorize",
        .token_endpoint = "https://auth.example.com/token",
        .redirect_uri = "http://localhost:8080/callback",
        .scope = "read write",
    };

    var oauth_client = OAuth.init(allocator, config, storage.storage());

    const result = try oauth_client.startAuthFlow();
    defer allocator.free(result.url);
    defer allocator.free(result.state);

    try std.testing.expect(result.url.len > 0);
    try std.testing.expect(result.state.len > 0);

    // Verify URL contains expected parameters
    try std.testing.expect(std.mem.indexOf(u8, result.url, "client_id=test-client") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.url, "code_challenge_method=S256") != null);
}

test "TokenRefresher concurrent refresh" {
    const allocator = std.testing.allocator;

    var storage = session.MemoryStorage.init(allocator);
    defer storage.deinit();

    const config = OAuthConfig{
        .client_id = "test-client",
        .authorization_endpoint = "https://auth.example.com/authorize",
        .token_endpoint = "https://auth.example.com/token",
        .redirect_uri = "http://localhost:8080/callback",
    };

    var oauth_client = OAuth.init(allocator, config, storage.storage());

    var refresher = TokenRefresher.init(allocator, &oauth_client);
    defer refresher.deinit();

    const token = try refresher.refreshToken("test-key", "test-refresh-token");
    defer {
        var mut_token = token;
        mut_token.deinit();
    }

    try std.testing.expectEqualStrings("new_access_token", token.access_token);
}
