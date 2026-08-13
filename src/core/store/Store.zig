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
/// Operation ledger (0.2.0): immutable identity + append-only receipts.
/// `history` stays readable but is no longer an authoritative record.
pub const ids = @import("ids.zig");
pub const op_state = @import("op_state.zig");
pub const operations = @import("operations.zig");
pub const receipts = @import("receipts.zig");
pub const transfers = @import("transfers.zig");
pub const job_attempts = @import("job_attempts.zig");
pub const leases = @import("leases.zig");
pub const plans = @import("plans.zig");
pub const host_pins = @import("host_pins.zig");
pub const policy = @import("policy.zig");
const migrate = @import("migrate.zig");

pub const schema_version = migrate.latest_version;

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
    _ = @import("gates_test.zig");
    @import("std").testing.refAllDecls(Store);
}
