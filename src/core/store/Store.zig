//! Local metadata store: one sqlite database holding servers, keys,
//! sessions, and memories. Opening runs pending migrations.
const Store = @This();

pub const Db = @import("Db.zig");
pub const servers = @import("servers.zig");
pub const keys = @import("keys.zig");
pub const sessions = @import("sessions.zig");
pub const memories = @import("memories.zig");
pub const jobs = @import("jobs.zig");
pub const facts = @import("facts.zig");
pub const history = @import("history.zig");
const migrate = @import("migrate.zig");

db: Db,

pub fn open(path: [:0]const u8) Db.Error!Store {
    var db = try Db.open(path);
    errdefer db.close();
    try migrate.apply(&db);
    return .{ .db = db };
}

pub fn close(store: *Store) void {
    store.db.close();
    store.* = undefined;
}

test {
    @import("std").testing.refAllDecls(Store);
}
