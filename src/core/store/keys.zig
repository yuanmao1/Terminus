//! CRUD for the `keys` table. Key material (private/public/passphrase) is
//! stored as plain bytes in M1; encryption lands in M4 (DPAPI on Windows).
const std = @import("std");
const Allocator = std.mem.Allocator;
const Store = @import("Store.zig");
const Db = @import("Db.zig");

pub const Key = struct {
    id: i64,
    name: []const u8,
    kind: []const u8,
    has_private: bool,
    has_passphrase: bool,
    created_at: i64,
};

pub const AddOptions = struct {
    name: []const u8,
    kind: []const u8, // 'ed25519' | 'rsa' | 'password'
    private: ?[]const u8 = null,
    public: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
    now: i64,
};

pub const AddError = Db.Error || error{NameTaken};

pub fn add(store: *Store, opts: AddOptions) AddError!i64 {
    var stmt = try store.db.prepare(
        \\INSERT INTO keys (name, kind, private_pem, public_pem, passphrase, created_at)
        \\VALUES (?1, ?2, ?3, ?4, ?5, ?6)
    );
    defer stmt.deinit();
    try stmt.bindText(1, opts.name);
    try stmt.bindText(2, opts.kind);
    if (opts.private) |p| try stmt.bindBlob(3, p) else try stmt.bindNull(3);
    if (opts.public) |p| try stmt.bindBlob(4, p) else try stmt.bindNull(4);
    try stmt.bindOptText(5, opts.passphrase);
    try stmt.bindInt(6, opts.now);
    _ = stmt.step() catch |err| return switch (err) {
        error.Constraint => error.NameTaken,
        else => err,
    };
    return store.db.lastInsertRowId();
}

pub fn list(store: *Store, arena: Allocator) (Db.Error || Allocator.Error)![]Key {
    var out: std.ArrayList(Key) = .empty;
    var stmt = try store.db.prepare(
        \\SELECT id, name, kind, private_pem IS NOT NULL, passphrase IS NOT NULL, created_at
        \\FROM keys ORDER BY name
    );
    defer stmt.deinit();
    while (try stmt.step()) {
        try out.append(arena, .{
            .id = stmt.columnInt(0),
            .name = try arena.dupe(u8, stmt.columnText(1)),
            .kind = try arena.dupe(u8, stmt.columnText(2)),
            .has_private = stmt.columnInt(3) != 0,
            .has_passphrase = stmt.columnInt(4) != 0,
            .created_at = stmt.columnInt(5),
        });
    }
    return out.toOwnedSlice(arena);
}

pub fn idByName(store: *Store, name: []const u8) Db.Error!?i64 {
    var stmt = try store.db.prepare("SELECT id FROM keys WHERE name = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, name);
    if (!try stmt.step()) return null;
    return stmt.columnInt(0);
}

pub const Material = struct {
    kind: []const u8,
    private: ?[]const u8,
    public: ?[]const u8,
    passphrase: ?[]const u8,
};

/// Full key material for authentication. Handle with care; never log.
pub fn material(store: *Store, arena: Allocator, name: []const u8) (Db.Error || Allocator.Error)!?Material {
    var stmt = try store.db.prepare(
        "SELECT kind, private_pem, public_pem, passphrase FROM keys WHERE name = ?1",
    );
    defer stmt.deinit();
    try stmt.bindText(1, name);
    if (!try stmt.step()) return null;
    return .{
        .kind = try arena.dupe(u8, stmt.columnText(0)),
        .private = if (stmt.columnOptText(1)) |v| try arena.dupe(u8, v) else null,
        .public = if (stmt.columnOptText(2)) |v| try arena.dupe(u8, v) else null,
        .passphrase = if (stmt.columnOptText(3)) |v| try arena.dupe(u8, v) else null,
    };
}

/// Returns false if no key with that name existed.
pub fn remove(store: *Store, name: []const u8) Db.Error!bool {
    var stmt = try store.db.prepare("DELETE FROM keys WHERE name = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, name);
    _ = try stmt.step();
    return store.db.changes() > 0;
}

pub const RenameError = Db.Error || error{NameTaken};

/// Returns false if no key with the old name existed. Servers reference
/// keys by id, so they follow automatically.
pub fn rename(store: *Store, old_name: []const u8, new_name: []const u8) RenameError!bool {
    var stmt = try store.db.prepare("UPDATE keys SET name = ?1 WHERE name = ?2");
    defer stmt.deinit();
    try stmt.bindText(1, new_name);
    try stmt.bindText(2, old_name);
    _ = stmt.step() catch |err| return switch (err) {
        error.Constraint => error.NameTaken,
        else => err,
    };
    return store.db.changes() > 0;
}
