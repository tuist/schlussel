const std = @import("std");
const crypto = std.crypto;
const base64 = std.base64;

/// PKCE (Proof Key for Code Exchange) implementation
/// RFC 7636: https://tools.ietf.org/html/rfc7636
pub const Pkce = struct {
    code_verifier: [43]u8,
    code_challenge: [43]u8,

    /// Generate a new PKCE challenge pair
    pub fn generate(allocator: std.mem.Allocator) !Pkce {
        _ = allocator;

        var pkce: Pkce = undefined;

        // Generate 32 random bytes for code_verifier
        var random_bytes: [32]u8 = undefined;
        crypto.random.bytes(&random_bytes);

        // Base64 URL encode without padding
        const encoder = base64.url_safe_no_pad.Encoder;
        _ = encoder.encode(&pkce.code_verifier, &random_bytes);

        // Create SHA256 hash of code_verifier
        var hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(&pkce.code_verifier, &hash, .{});

        // Base64 URL encode the hash for code_challenge
        _ = encoder.encode(&pkce.code_challenge, &hash);

        return pkce;
    }

    /// Get the code verifier
    pub fn getCodeVerifier(self: *const Pkce) []const u8 {
        return &self.code_verifier;
    }

    /// Get the code challenge
    pub fn getCodeChallenge(self: *const Pkce) []const u8 {
        return &self.code_challenge;
    }

    /// Get the code challenge method (always S256)
    pub fn getCodeChallengeMethod() []const u8 {
        return "S256";
    }
};

test "PKCE generation" {
    const allocator = std.testing.allocator;

    const pkce_pair = try Pkce.generate(allocator);

    // Verify lengths
    try std.testing.expectEqual(43, pkce_pair.code_verifier.len);
    try std.testing.expectEqual(43, pkce_pair.code_challenge.len);

    // Verify they are different
    try std.testing.expect(!std.mem.eql(u8, &pkce_pair.code_verifier, &pkce_pair.code_challenge));
}

test "PKCE generates different values each time" {
    const allocator = std.testing.allocator;

    const pkce1 = try Pkce.generate(allocator);
    const pkce2 = try Pkce.generate(allocator);

    try std.testing.expect(!std.mem.eql(u8, &pkce1.code_verifier, &pkce2.code_verifier));
    try std.testing.expect(!std.mem.eql(u8, &pkce1.code_challenge, &pkce2.code_challenge));
}
