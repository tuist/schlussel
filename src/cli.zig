//! Command-line interface for Schlussel token storage operations.
//!
//! The CLI no longer drives authentication flows directly. It remains available
//! as a lightweight tool for inspecting and retrieving stored tokens.

const std = @import("std");
const clap = @import("clap");
const Allocator = std.mem.Allocator;

const session = @import("session.zig");

const token_params = clap.parseParamsComptime(
    \\-h, --help                      Display this help and exit.
    \\-k, --key <str>                 Token storage key or prefix.
    \\-j, --json                      Output as JSON.
    \\<str>                           Action (get, list, delete).
    \\
);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;
    var stderr_buf: [4096]u8 = undefined;
    var stderr_writer = std.fs.File.stderr().writer(&stderr_buf);
    const stderr = &stderr_writer.interface;

    defer stdout.flush() catch {};
    defer stderr.flush() catch {};

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printMainUsage(stdout);
        return;
    }

    const command = args[1];
    if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        try printMainUsage(stdout);
        return;
    }

    if (std.mem.eql(u8, command, "token")) {
        try cmdToken(allocator, args[2..], stdout, stderr);
        return;
    }

    try stderr.print("Error: Unknown command '{s}'\n\n", .{command});
    try printMainUsage(stderr);
    return error.UnknownCommand;
}

fn printMainUsage(writer: anytype) !void {
    try writer.writeAll(
        \\Schlussel Token Storage Tool
        \\
        \\USAGE:
        \\    schlussel token <action> [options]
        \\    schlussel help
        \\
        \\COMMANDS:
        \\    token <action>      Token management (get, list, delete)
        \\    help                Show this help message
        \\
        \\EXAMPLES:
        \\    # List all stored tokens
        \\    schlussel token list
        \\
        \\    # List tokens by key prefix
        \\    schlussel token list --key my-app:
        \\
        \\    # Get a stored token
        \\    schlussel token get --key my-app:primary
        \\
        \\    # Delete a stored token
        \\    schlussel token delete --key my-app:primary
        \\
        \\For more help, visit: https://github.com/pepicrft/schlussel
        \\
    );
}

fn cmdToken(allocator: Allocator, args: []const []const u8, stdout: anytype, stderr: anytype) !void {
    var diag: clap.Diagnostic = .{};
    var iter = clap.args.SliceIterator{ .args = args };
    var res = clap.parseEx(clap.Help, &token_params, clap.parsers.default, &iter, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.report(stderr, err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try clap.help(stdout, clap.Help, &token_params, .{});
        return;
    }

    const action = if (res.positionals.len > 0) res.positionals[0] orelse {
        try stderr.print("Error: Missing action (get, list, delete)\n\n", .{});
        try clap.help(stderr, clap.Help, &token_params, .{});
        return error.MissingArguments;
    } else {
        try stderr.print("Error: Missing action (get, list, delete)\n\n", .{});
        try clap.help(stderr, clap.Help, &token_params, .{});
        return error.MissingArguments;
    };

    const key_arg = res.args.key;
    const json_output = res.args.json != 0;

    var storage = try session.FileStorage.init(allocator, "schlussel");
    defer storage.deinit();

    const storage_path = try getTokenStoragePath(allocator);
    defer allocator.free(storage_path);

    if (std.mem.eql(u8, action, "get")) {
        const key = key_arg orelse {
            try stderr.print("Error: --key is required for 'get'\n", .{});
            return error.MissingArguments;
        };

        var token = (try storage.storage().load(allocator, key)) orelse {
            try stderr.print("Error: Token not found for key '{s}'\n", .{key});
            return error.NotFound;
        };
        defer token.deinit();

        try outputToken(stdout, key, token, json_output);
        return;
    }

    if (std.mem.eql(u8, action, "list")) {
        const keys = try listTokenFiles(allocator, storage_path);
        defer {
            for (keys) |key| allocator.free(key);
            allocator.free(keys);
        }

        var filtered: std.ArrayListUnmanaged([]const u8) = .{};
        defer filtered.deinit(allocator);

        for (keys) |key| {
            if (key_arg) |prefix| {
                if (!std.mem.startsWith(u8, key, prefix)) continue;
            }
            try filtered.append(allocator, key);
        }

        if (json_output) {
            try stdout.print("[\n", .{});
            for (filtered.items, 0..) |key, idx| {
                try stdout.print("  {{\"key\": \"{s}\"}}", .{key});
                if (idx + 1 < filtered.items.len) try stdout.print(",", .{});
                try stdout.print("\n", .{});
            }
            try stdout.print("]\n", .{});
        } else if (filtered.items.len == 0) {
            try stdout.print("No tokens found\n", .{});
        } else {
            try stdout.print("Stored tokens:\n", .{});
            for (filtered.items) |key| {
                try stdout.print("  {s}\n", .{key});
            }
        }
        return;
    }

    if (std.mem.eql(u8, action, "delete")) {
        const key = key_arg orelse {
            try stderr.print("Error: --key is required for 'delete'\n", .{});
            return error.MissingArguments;
        };

        try storage.storage().delete(key);
        if (json_output) {
            try stdout.print("{{\"deleted\": \"{s}\"}}\n", .{key});
        } else {
            try stdout.print("Token deleted: {s}\n", .{key});
        }
        return;
    }

    try stderr.print("Error: Unknown action '{s}'. Use: get, list, delete\n", .{action});
    return error.InvalidParameter;
}

fn outputToken(stdout: anytype, key: []const u8, token: session.Token, json_output: bool) !void {
    if (json_output) {
        try stdout.print("{{\n", .{});
        try stdout.print("  \"key\": \"{s}\",\n", .{key});
        try stdout.print("  \"access_token\": \"{s}\",\n", .{token.access_token});
        try stdout.print("  \"token_type\": \"{s}\"", .{token.token_type});
        if (token.refresh_token) |refresh_token| {
            try stdout.print(",\n  \"refresh_token\": \"{s}\"", .{refresh_token});
        }
        if (token.scope) |scope| {
            try stdout.print(",\n  \"scope\": \"{s}\"", .{scope});
        }
        if (token.expires_at) |expires_at| {
            try stdout.print(",\n  \"expires_at\": {d}", .{expires_at});
        }
        if (token.expires_in) |expires_in| {
            try stdout.print(",\n  \"expires_in\": {d}", .{expires_in});
        }
        try stdout.print("\n}}\n", .{});
        return;
    }

    try stdout.print("{s}\n", .{token.access_token});
}

fn listTokenFiles(allocator: Allocator, storage_path: []const u8) ![][]const u8 {
    var keys: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer {
        for (keys.items) |key| allocator.free(key);
        keys.deinit(allocator);
    }

    var dir = std.fs.cwd().openDir(storage_path, .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound) return keys.toOwnedSlice(allocator);
        return err;
    };
    defer dir.close();

    var iter = dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".json")) continue;

        const key = entry.name[0 .. entry.name.len - 5];
        try keys.append(allocator, try allocator.dupe(u8, key));
    }

    return keys.toOwnedSlice(allocator);
}

fn getTokenStoragePath(allocator: Allocator) ![]const u8 {
    const builtin = @import("builtin");

    if (builtin.os.tag == .linux) {
        if (std.process.getEnvVarOwned(allocator, "XDG_DATA_HOME")) |xdg_data| {
            defer allocator.free(xdg_data);
            return std.fmt.allocPrint(allocator, "{s}/schlussel", .{xdg_data});
        } else |_| {}

        if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
            defer allocator.free(home);
            return std.fmt.allocPrint(allocator, "{s}/.local/share/schlussel", .{home});
        } else |_| {}
    } else if (builtin.os.tag == .macos) {
        if (std.process.getEnvVarOwned(allocator, "HOME")) |home| {
            defer allocator.free(home);
            return std.fmt.allocPrint(allocator, "{s}/Library/Application Support/schlussel", .{home});
        } else |_| {}
    } else if (builtin.os.tag == .windows) {
        if (std.process.getEnvVarOwned(allocator, "LOCALAPPDATA")) |local_app_data| {
            defer allocator.free(local_app_data);
            return std.fmt.allocPrint(allocator, "{s}\\schlussel", .{local_app_data});
        } else |_| {}
    }

    return std.fmt.allocPrint(allocator, "/tmp/schlussel", .{});
}
