const std = @import("std");

/// Session data stored during OAuth flow
pub const Session = struct {
    state: []const u8,
    code_verifier: []const u8,
    created_at: i64,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, state: []const u8, code_verifier: []const u8) !Session {
        const state_copy = try allocator.dupe(u8, state);
        errdefer allocator.free(state_copy);

        const verifier_copy = try allocator.dupe(u8, code_verifier);
        errdefer allocator.free(verifier_copy);

        return Session{
            .state = state_copy,
            .code_verifier = verifier_copy,
            .created_at = std.time.timestamp(),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Session) void {
        self.allocator.free(self.state);
        self.allocator.free(self.code_verifier);
    }
};

/// Token data
pub const Token = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8,
    token_type: []const u8,
    expires_in: ?i64,
    expires_at: ?i64,
    scope: ?[]const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Token) void {
        self.allocator.free(self.access_token);
        if (self.refresh_token) |rt| {
            self.allocator.free(rt);
        }
        self.allocator.free(self.token_type);
        if (self.scope) |s| {
            self.allocator.free(s);
        }
    }

    pub fn isExpired(self: *const Token) bool {
        if (self.expires_at) |exp| {
            return std.time.timestamp() >= exp;
        }
        return false;
    }
};

/// Storage interface for sessions and tokens
pub const SessionStorage = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        saveSession: *const fn (ptr: *anyopaque, state: []const u8, session: Session) anyerror!void,
        getSession: *const fn (ptr: *anyopaque, state: []const u8) anyerror!?Session,
        deleteSession: *const fn (ptr: *anyopaque, state: []const u8) anyerror!void,
        saveToken: *const fn (ptr: *anyopaque, key: []const u8, token: Token) anyerror!void,
        getToken: *const fn (ptr: *anyopaque, key: []const u8) anyerror!?Token,
        deleteToken: *const fn (ptr: *anyopaque, key: []const u8) anyerror!void,
    };

    pub fn saveSession(self: SessionStorage, state: []const u8, sess: Session) !void {
        return self.vtable.saveSession(self.ptr, state, sess);
    }

    pub fn getSession(self: SessionStorage, state: []const u8) !?Session {
        return self.vtable.getSession(self.ptr, state);
    }

    pub fn deleteSession(self: SessionStorage, state: []const u8) !void {
        return self.vtable.deleteSession(self.ptr, state);
    }

    pub fn saveToken(self: SessionStorage, key: []const u8, token: Token) !void {
        return self.vtable.saveToken(self.ptr, key, token);
    }

    pub fn getToken(self: SessionStorage, key: []const u8) !?Token {
        return self.vtable.getToken(self.ptr, key);
    }

    pub fn deleteToken(self: SessionStorage, key: []const u8) !void {
        return self.vtable.deleteToken(self.ptr, key);
    }
};

/// In-memory storage implementation (for testing/simple use cases)
pub const MemoryStorage = struct {
    sessions: std.StringHashMap(Session),
    tokens: std.StringHashMap(Token),
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) MemoryStorage {
        return .{
            .sessions = std.StringHashMap(Session).init(allocator),
            .tokens = std.StringHashMap(Token).init(allocator),
            .allocator = allocator,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *MemoryStorage) void {
        var session_iter = self.sessions.iterator();
        while (session_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var session = entry.value_ptr.*;
            session.deinit();
        }
        self.sessions.deinit();

        var token_iter = self.tokens.iterator();
        while (token_iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            var token = entry.value_ptr.*;
            token.deinit();
        }
        self.tokens.deinit();
    }

    pub fn storage(self: *MemoryStorage) SessionStorage {
        return .{
            .ptr = self,
            .vtable = &.{
                .saveSession = saveSession,
                .getSession = getSession,
                .deleteSession = deleteSession,
                .saveToken = saveToken,
                .getToken = getToken,
                .deleteToken = deleteToken,
            },
        };
    }

    fn saveSession(ptr: *anyopaque, state: []const u8, sess: Session) !void {
        const self: *MemoryStorage = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        const key = try self.allocator.dupe(u8, state);
        try self.sessions.put(key, sess);
    }

    fn getSession(ptr: *anyopaque, state: []const u8) !?Session {
        const self: *MemoryStorage = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        const stored = self.sessions.get(state) orelse return null;

        // Return a copy of the session
        return Session{
            .state = try self.allocator.dupe(u8, stored.state),
            .code_verifier = try self.allocator.dupe(u8, stored.code_verifier),
            .created_at = stored.created_at,
            .allocator = self.allocator,
        };
    }

    fn deleteSession(ptr: *anyopaque, state: []const u8) !void {
        const self: *MemoryStorage = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.sessions.fetchRemove(state)) |kv| {
            self.allocator.free(kv.key);
            var session = kv.value;
            session.deinit();
        }
    }

    fn saveToken(ptr: *anyopaque, key: []const u8, token: Token) !void {
        const self: *MemoryStorage = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        const key_copy = try self.allocator.dupe(u8, key);
        try self.tokens.put(key_copy, token);
    }

    fn getToken(ptr: *anyopaque, key: []const u8) !?Token {
        const self: *MemoryStorage = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        const stored = self.tokens.get(key) orelse return null;

        // Return a copy of the token
        return Token{
            .access_token = try self.allocator.dupe(u8, stored.access_token),
            .refresh_token = if (stored.refresh_token) |rt| try self.allocator.dupe(u8, rt) else null,
            .token_type = try self.allocator.dupe(u8, stored.token_type),
            .expires_in = stored.expires_in,
            .expires_at = stored.expires_at,
            .scope = if (stored.scope) |s| try self.allocator.dupe(u8, s) else null,
            .allocator = self.allocator,
        };
    }

    fn deleteToken(ptr: *anyopaque, key: []const u8) !void {
        const self: *MemoryStorage = @ptrCast(@alignCast(ptr));
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.tokens.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            var token = kv.value;
            token.deinit();
        }
    }
};

test "MemoryStorage session operations" {
    const allocator = std.testing.allocator;
    var storage = MemoryStorage.init(allocator);
    defer storage.deinit();

    const stor = storage.storage();

    const session = try Session.init(allocator, "test-state", "test-verifier");

    try stor.saveSession("test-state", session);

    const retrieved = try stor.getSession("test-state");
    try std.testing.expect(retrieved != null);
    try std.testing.expectEqualStrings("test-state", retrieved.?.state);

    // Clean up the retrieved copy
    var retrieved_copy = retrieved.?;
    retrieved_copy.deinit();

    try stor.deleteSession("test-state");

    const deleted = try stor.getSession("test-state");
    try std.testing.expect(deleted == null);
}
