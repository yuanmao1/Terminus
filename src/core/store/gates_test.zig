//! The store's release gates, and the map to them.
//!
//! These are not smoke tests. Each one corresponds to a stated rule the
//! operation ledger is built on, and each is mutation-tested: `tools/mutate.py`
//! breaks the rule in the product code and the gate named for it in
//! `tools/mutations.json` has to go red.
//!
//! They were one file of 11,800 lines. Finding a gate meant scrolling, and
//! every slice that added one made that worse, so they are split by subject.
//! This file is the map and the entry point: `Store.zig` imports it, and it
//! imports the rest — which is what puts them in front of the compiler, and so
//! in front of the test runner.
//!
//! * `gates_fixtures.zig` — the scratch store and the seeds the parts share.
//!   One home, deliberately: two copies of a fixture is how two gates start
//!   proving different things while appearing to read the same.
//! * `gates_schema_test.zig` — the store's own shape: migrations, first open,
//!   refusing a database that is not ours or came from a newer binary, and the
//!   three places a Zig list has to equal a list the schema states.
//! * `gates_settlement_test.zig` — who may write a terminal, out of what
//!   evidence, and exactly once; and which reading is allowed to settle which
//!   attempt.
//! * `gates_admissibility_test.zig` — the two capability matrices, transcribed
//!   a second time from the other direction. Independently derived on purpose:
//!   a mirror that imports the table it mirrors proves nothing.
//! * `gates_leases_test.zig` — contention: acquiring, renewing, expiring,
//!   taking over, name reservation, and the one overlap rule the operation
//!   guard shares with it.
//! * `gates_transfer_test.zig` — a transfer's own record: the digest it
//!   declares, the source it identifies, the offsets it confirms, the states it
//!   may reach, and the destination it holds.
//! * `gates_publish_test.zig` — judging a rename nobody watched: what evidence
//!   about a destination may decide a publish, and what it may not.
//! * `gates_recovery_test.zig` — work whose owner died: abandonment, recovery,
//!   hand-over, and the barrier that stops a server being deleted out from
//!   under it.
//! * `gates_jobs_test.zig` — the local `jobs` table's compare-and-swap rules and
//!   the cached terminal written beside the receipt.
//! * `gates_authority_test.zig` — the destructive verbs: `session rm`'s
//!   composite write, and the matrix every destructive path answers the same
//!   way.
//!
//! Zig only runs tests in files it analyses, so a part that is not named below
//! silently stops being a gate. Adding a file here is not optional bookkeeping;
//! it is the thing that makes the file run.
//!
//! `comptime`, not `test {…}`: an anonymous test block is itself a test, and one
//! that exists only to pull in imports would inflate every count this suite is
//! judged by. A container-level `comptime` block is analysed just as eagerly and
//! declares nothing.
comptime {
    _ = @import("gates_fixtures.zig");
    _ = @import("gates_schema_test.zig");
    _ = @import("gates_settlement_test.zig");
    _ = @import("gates_admissibility_test.zig");
    _ = @import("gates_leases_test.zig");
    _ = @import("gates_transfer_test.zig");
    _ = @import("gates_publish_test.zig");
    _ = @import("gates_recovery_test.zig");
    _ = @import("gates_jobs_test.zig");
    _ = @import("gates_authority_test.zig");
}
