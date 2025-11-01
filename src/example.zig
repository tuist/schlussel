const std = @import("std");
const schlussel = @import("lib.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    try stdout.print("Schlussel OAuth 2.0 PKCE Example\n", .{});
    try stdout.print("================================\n\n", .{});

    // Create storage
    var storage = schlussel.MemoryStorage.init(allocator);
    defer storage.deinit();

    // Configure OAuth
    const config = schlussel.OAuthConfig{
        .client_id = "example-client-id",
        .authorization_endpoint = "https://accounts.example.com/oauth/authorize",
        .token_endpoint = "https://accounts.example.com/oauth/token",
        .redirect_uri = "http://localhost:8080/callback",
        .scope = "read write",
    };

    // Create OAuth client
    var oauth_client = schlussel.OAuth.init(allocator, config, storage.storage());

    // Start OAuth flow
    try stdout.print("Starting OAuth flow...\n", .{});
    const flow_result = try oauth_client.startAuthFlow();
    defer allocator.free(flow_result.url);
    defer allocator.free(flow_result.state);

    try stdout.print("\nAuthorization URL:\n{s}\n\n", .{flow_result.url});
    try stdout.print("State: {s}\n\n", .{flow_result.state});

    // Demonstrate PKCE
    try stdout.print("PKCE Example:\n", .{});
    const pkce_pair = try schlussel.Pkce.generate(allocator);
    try stdout.print("  Code Verifier: {s}\n", .{pkce_pair.getCodeVerifier()});
    try stdout.print("  Code Challenge: {s}\n", .{pkce_pair.getCodeChallenge()});
    try stdout.print("  Challenge Method: {s}\n\n", .{schlussel.Pkce.getCodeChallengeMethod()});

    // Demonstrate token refresher
    try stdout.print("Token Refresher Example:\n", .{});
    var refresher = schlussel.TokenRefresher.init(allocator, &oauth_client);
    defer refresher.deinit();

    const token = try refresher.refreshToken("example-key", "example-refresh-token");
    defer {
        var mut_token = token;
        mut_token.deinit();
    }

    try stdout.print("  Access Token: {s}\n", .{token.access_token});
    try stdout.print("  Token Type: {s}\n", .{token.token_type});
    if (token.expires_at) |exp| {
        try stdout.print("  Expires At: {d}\n", .{exp});
    }

    try stdout.print("\nWaiting for any in-progress refreshes...\n", .{});
    refresher.waitForRefresh("example-key");

    try stdout.print("Done!\n", .{});
}
