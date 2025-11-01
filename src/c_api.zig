const std = @import("std");
const oauth = @import("oauth.zig");
const session = @import("session.zig");
const pkce = @import("pkce.zig");

// Global allocator for C API (users can override)
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

// Opaque types for C API
pub const SchlusselOAuth = opaque {};
pub const SchlusselStorage = opaque {};
pub const SchlusselTokenRefresher = opaque {};
pub const SchlusselToken = opaque {};

/// Error codes for C API
pub const SchlusselError = enum(c_int) {
    Ok = 0,
    OutOfMemory = 1,
    InvalidArgument = 2,
    NotFound = 3,
    Unknown = 99,
};

/// OAuth configuration for C API
pub const SchlusselOAuthConfig = extern struct {
    client_id: [*:0]const u8,
    authorization_endpoint: [*:0]const u8,
    token_endpoint: [*:0]const u8,
    redirect_uri: [*:0]const u8,
    scope: ?[*:0]const u8,
};

/// Auth flow result
pub const SchlusselAuthFlow = extern struct {
    url: [*:0]u8,
    state: [*:0]u8,
};

/// Token info for C API
pub const SchlusselTokenInfo = extern struct {
    access_token: [*:0]const u8,
    refresh_token: ?[*:0]const u8,
    token_type: [*:0]const u8,
    expires_at: i64,
};

// Storage vtable for C API
pub const SchlusselStorageVTable = extern struct {
    save_session: *const fn (ctx: ?*anyopaque, state: [*:0]const u8, code_verifier: [*:0]const u8) callconv(.C) c_int,
    get_session: *const fn (ctx: ?*anyopaque, state: [*:0]const u8, out_verifier: [*]u8, verifier_len: usize) callconv(.C) c_int,
    delete_session: *const fn (ctx: ?*anyopaque, state: [*:0]const u8) callconv(.C) c_int,
    save_token: *const fn (ctx: ?*anyopaque, key: [*:0]const u8, token: *const SchlusselTokenInfo) callconv(.C) c_int,
    get_token: *const fn (ctx: ?*anyopaque, key: [*:0]const u8, token: *SchlusselTokenInfo) callconv(.C) c_int,
    delete_token: *const fn (ctx: ?*anyopaque, key: [*:0]const u8) callconv(.C) c_int,
};

/// Create a new in-memory storage (for testing)
export fn schlussel_storage_memory_create() ?*SchlusselStorage {
    const storage_ptr = allocator.create(session.MemoryStorage) catch return null;
    storage_ptr.* = session.MemoryStorage.init(allocator);
    return @ptrCast(storage_ptr);
}

/// Destroy storage
export fn schlussel_storage_destroy(storage: ?*SchlusselStorage) void {
    if (storage) |s| {
        const storage_ptr: *session.MemoryStorage = @ptrCast(@alignCast(s));
        storage_ptr.deinit();
        allocator.destroy(storage_ptr);
    }
}

/// Create OAuth client
export fn schlussel_oauth_create(config: *const SchlusselOAuthConfig, storage: *SchlusselStorage) ?*SchlusselOAuth {
    const oauth_config = oauth.OAuthConfig{
        .client_id = std.mem.span(config.client_id),
        .authorization_endpoint = std.mem.span(config.authorization_endpoint),
        .token_endpoint = std.mem.span(config.token_endpoint),
        .redirect_uri = std.mem.span(config.redirect_uri),
        .scope = if (config.scope) |s| std.mem.span(s) else null,
    };

    const storage_ptr: *session.MemoryStorage = @ptrCast(@alignCast(storage));

    const oauth_ptr = allocator.create(oauth.OAuth) catch return null;
    oauth_ptr.* = oauth.OAuth.init(allocator, oauth_config, storage_ptr.storage());

    return @ptrCast(oauth_ptr);
}

/// Destroy OAuth client
export fn schlussel_oauth_destroy(client: ?*SchlusselOAuth) void {
    if (client) |c| {
        const oauth_ptr: *oauth.OAuth = @ptrCast(@alignCast(c));
        allocator.destroy(oauth_ptr);
    }
}

/// Start OAuth flow
export fn schlussel_oauth_start_flow(client: *SchlusselOAuth, result: *SchlusselAuthFlow) SchlusselError {
    const oauth_ptr: *oauth.OAuth = @ptrCast(@alignCast(client));

    const flow_result = oauth_ptr.startAuthFlow() catch |err| {
        return switch (err) {
            error.OutOfMemory => SchlusselError.OutOfMemory,
            else => SchlusselError.Unknown,
        };
    };

    // Convert to null-terminated strings
    const url_z = allocator.dupeZ(u8, flow_result.url) catch {
        allocator.free(flow_result.url);
        allocator.free(flow_result.state);
        return SchlusselError.OutOfMemory;
    };
    allocator.free(flow_result.url);

    const state_z = allocator.dupeZ(u8, flow_result.state) catch {
        allocator.free(url_z);
        allocator.free(flow_result.state);
        return SchlusselError.OutOfMemory;
    };
    allocator.free(flow_result.state);

    result.url = url_z.ptr;
    result.state = state_z.ptr;

    return SchlusselError.Ok;
}

/// Free auth flow result
export fn schlussel_auth_flow_free(result: *SchlusselAuthFlow) void {
    allocator.free(std.mem.span(result.url));
    allocator.free(std.mem.span(result.state));
}

/// Create token refresher
export fn schlussel_token_refresher_create(client: *SchlusselOAuth) ?*SchlusselTokenRefresher {
    const oauth_ptr: *oauth.OAuth = @ptrCast(@alignCast(client));

    const refresher_ptr = allocator.create(oauth.TokenRefresher) catch return null;
    refresher_ptr.* = oauth.TokenRefresher.init(allocator, oauth_ptr);

    return @ptrCast(refresher_ptr);
}

/// Destroy token refresher
export fn schlussel_token_refresher_destroy(refresher: ?*SchlusselTokenRefresher) void {
    if (refresher) |r| {
        const refresher_ptr: *oauth.TokenRefresher = @ptrCast(@alignCast(r));
        refresher_ptr.deinit();
        allocator.destroy(refresher_ptr);
    }
}

/// Wait for refresh to complete
export fn schlussel_token_refresher_wait(refresher: *SchlusselTokenRefresher, key: [*:0]const u8) void {
    const refresher_ptr: *oauth.TokenRefresher = @ptrCast(@alignCast(refresher));
    const key_slice = std.mem.span(key);
    refresher_ptr.waitForRefresh(key_slice);
}

/// Get library version
export fn schlussel_version() [*:0]const u8 {
    return "0.1.0";
}
