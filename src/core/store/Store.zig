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
/// Public because `openDiagnosed`'s `Refusal` is the only place the numbers
/// behind a refused open exist, and the CLI has to read them to say anything
/// but "cannot open database".
pub const migrate = @import("migrate.zig");

pub const schema_version = migrate.latest_version;

db: Db,

pub const OpenError = Db.Error || migrate.PreApplyError;

/// Opens the store, refusing before it writes anything.
///
/// The gate runs against the database *as found* — see
/// `migrate.checkBeforeApply`. It used to run after `apply`, which meant the
/// probe that exists to stop v11 from destroying pre-v11 checkpoint rows only
/// got to look once they were gone.
pub fn open(path: [:0]const u8) OpenError!Store {
    return openDiagnosed(path, null);
}

/// `open`, with somewhere to put the numbers behind a refusal.
///
/// Zig errors carry no payload and the counts are what an operator acts on, so
/// a caller that can word a message passes a `Refusal` and reads it on error.
/// `null` is not a fallback: the refusal is identical either way, and the error
/// is what stops the open.
///
/// `enableWal` sits between the gate and `apply`, and the order is load-bearing
/// in both directions. It is after the gate because switching journal mode
/// rewrites the file header, and a file we are about to refuse must leave this
/// function exactly as it arrived — see `Db.open`. It is before `apply` because
/// every migration writes, and the concurrency the rest of the program assumes
/// (a reader and a writer coexisting) has to hold from the first DDL onwards.
pub fn openDiagnosed(path: [:0]const u8, refusal: ?*migrate.Refusal) OpenError!Store {
    var db = try Db.open(path);
    errdefer db.close();
    try migrate.checkBeforeApply(&db, refusal);
    try db.enableWal();
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
