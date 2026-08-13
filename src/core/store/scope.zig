//! Mutation scopes, shared by leases and by the unsettled-operation guard.
//!
//! There must be exactly one definition of "these two pieces of work touch
//! the same thing". Two safety barriers with slightly different overlap
//! rules is how a hole appears: the lease layer would refuse a conflicting
//! change while the operation guard waved it through, or the reverse.
const std = @import("std");

pub const Kind = enum {
    /// The whole host.
    server,
    /// One job name.
    job,
    /// A filesystem path and everything under it.
    path,

    pub fn parse(raw: []const u8) error{UnknownScopeKind}!Kind {
        return std.meta.stringToEnum(Kind, raw) orelse error.UnknownScopeKind;
    }

    pub fn text(k: Kind) []const u8 {
        return @tagName(k);
    }
};

pub const Scope = struct {
    kind: Kind,
    /// Empty for a whole-server scope; job name or path otherwise.
    key: []const u8 = "",

    /// The conflict matrix.
    ///
    /// * A `server` scope covers everything on that host, so it overlaps any
    ///   other scope.
    /// * `job` scopes overlap only on the same name.
    /// * `path` scopes overlap when one contains the other — holding
    ///   `/srv/app` must block `/srv/app/dist`, otherwise "do not let two
    ///   sessions modify the same directory" would not hold.
    pub fn overlaps(a: Scope, b: Scope) bool {
        if (a.kind == .server or b.kind == .server) return true;
        if (a.kind != b.kind) return false;
        return switch (a.kind) {
            .server => true,
            .job => std.mem.eql(u8, a.key, b.key),
            .path => pathContains(a.key, b.key) or pathContains(b.key, a.key),
        };
    }
};

/// An operation that never declared what it touches.
///
/// Treated as overlapping everything: work that may still be running and
/// whose blast radius we cannot name has to block a conflicting change.
/// Guessing "probably harmless" here is exactly the kind of assumption that
/// lets two sessions restart the same service.
pub const unknown: Scope = .{ .kind = .server };

/// True when `parent` contains `child` (or they are the same path). Compares
/// at separator boundaries so `/srv/app` does not "contain" `/srv/applied`.
pub fn pathContains(parent: []const u8, child: []const u8) bool {
    const p = std.mem.trimEnd(u8, parent, "/");
    const c = std.mem.trimEnd(u8, child, "/");
    if (p.len == 0) return true; // "/" contains everything
    if (!std.mem.startsWith(u8, c, p)) return false;
    return c.len == p.len or c[p.len] == '/';
}

test "scope overlap matrix" {
    const t = std.testing;
    const server: Scope = .{ .kind = .server };
    const job_a: Scope = .{ .kind = .job, .key = "build" };
    const job_b: Scope = .{ .kind = .job, .key = "deploy" };
    const path_app: Scope = .{ .kind = .path, .key = "/srv/app" };
    const path_dist: Scope = .{ .kind = .path, .key = "/srv/app/dist" };
    const path_other: Scope = .{ .kind = .path, .key = "/srv/applied" };

    // A server scope covers the whole host, in both directions.
    try t.expect(server.overlaps(job_a));
    try t.expect(job_a.overlaps(server));
    try t.expect(server.overlaps(path_app));

    // Different jobs are independent; different kinds do not collide.
    try t.expect(job_a.overlaps(job_a));
    try t.expect(!job_a.overlaps(job_b));
    try t.expect(!job_a.overlaps(path_app));

    // Holding a directory blocks anything inside it, in both directions.
    try t.expect(path_app.overlaps(path_dist));
    try t.expect(path_dist.overlaps(path_app));
    // ...but not a sibling that merely shares a prefix string.
    try t.expect(!path_app.overlaps(path_other));

    // An undeclared scope conflicts with everything.
    try t.expect(unknown.overlaps(path_dist));
    try t.expect(path_dist.overlaps(unknown));
}

test pathContains {
    const t = std.testing;
    try t.expect(pathContains("/srv/app", "/srv/app"));
    try t.expect(pathContains("/srv/app", "/srv/app/dist"));
    try t.expect(pathContains("/srv/app/", "/srv/app/dist"));
    try t.expect(!pathContains("/srv/app", "/srv/applied"));
    try t.expect(!pathContains("/srv/app/dist", "/srv/app"));
    // Root contains everything.
    try t.expect(pathContains("/", "/anything"));
}
