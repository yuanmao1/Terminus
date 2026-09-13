//! The policy contract for native audit mode.
//!
//! An audit request is deliberately *not* an arbitrary command with a local
//! "looks read-only" check.  The host sends a small policy id and the remote
//! helper resolves that id against this same, compiled-in table.  The helper
//! must reject an unknown id, a wrong sudo mode, and any request carrying an
//! argv.  It then starts the fixed argv with an empty environment, a null
//! stdin, and no shell.  That is the boundary which makes an audit read-only;
//! the local parser is only a convenience and is never the authority.
//!
//! This file has no host-only imports so it can be imported by both the CLI and
//! the x86_64-linux-musl helper.  Keep the manifest and wire constants here,
//! rather than copying them into either side.  `supervisor.zig` may wrap these
//! values in its normal execution framing when the helper protocol is wired.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const version: u8 = 1;

/// The only audit subjects this release exposes.  These are subjects, not
/// command names: callers cannot add flags or splice a path into one.
pub const Check = enum(u8) {
    host,
    filesystem,
    processes,
    services,
    containers,
    journal,
    disk_mounts,
    disk_usage,
    disk_containers,

    pub fn parse(name: []const u8) error{UnknownCheck}!Check {
        if (std.mem.eql(u8, name, "host")) return .host;
        if (std.mem.eql(u8, name, "filesystem")) return .filesystem;
        if (std.mem.eql(u8, name, "processes")) return .processes;
        if (std.mem.eql(u8, name, "services")) return .services;
        if (std.mem.eql(u8, name, "containers")) return .containers;
        if (std.mem.eql(u8, name, "journal")) return .journal;
        if (std.mem.eql(u8, name, "disk-mounts")) return .disk_mounts;
        if (std.mem.eql(u8, name, "disk-usage")) return .disk_usage;
        if (std.mem.eql(u8, name, "disk-containers")) return .disk_containers;
        return error.UnknownCheck;
    }

    pub fn text(check: Check) []const u8 {
        return switch (check) {
            .host => "host",
            .filesystem => "filesystem",
            .processes => "processes",
            .services => "services",
            .containers => "containers",
            .journal => "journal",
            .disk_mounts => "disk-mounts",
            .disk_usage => "disk-usage",
            .disk_containers => "disk-containers",
        };
    }
};

/// `forbidden` means the check is never run through sudo.  `required` means
/// the helper must put `sudo -n --` in front of the fixed read-only wrapper;
/// accepting a password prompt would turn an audit into an interactive write
/// channel and is therefore not a fallback.
pub const SudoPolicy = enum(u8) {
    forbidden,
    required,
};

pub const Spec = struct {
    check: Check,
    /// The complete argv, including the non-interactive sudo wrapper when
    /// requested.  It is always a static slice from this module; it never
    /// contains caller-provided words.
    argv: []const []const u8,
    sudo: SudoPolicy,
    /// Every spec is executed as a direct, empty-environment, `/dev/null`
    /// stdin child by the helper.  This field makes that requirement visible
    /// to callers and gives tests a value to assert rather than trusting prose.
    read_only_wrapper: bool,
};

const host_argv = [_][]const u8{ "/usr/bin/uname", "-a" };
const filesystem_argv = [_][]const u8{ "/usr/bin/df", "-P", "/" };
const processes_argv = [_][]const u8{
    "/usr/bin/ps",
    "-eo",
    "pid=,ppid=,user=,stat=,comm=",
};
const services_argv = [_][]const u8{
    "/usr/bin/systemctl",
    "list-units",
    "--type=service",
    "--state=running,failed",
    "--no-pager",
    "--plain",
};
const containers_argv = [_][]const u8{
    "/usr/bin/docker",
    "ps",
    "--all",
    "--no-trunc",
};
const journal_argv = [_][]const u8{
    "/usr/bin/sudo",
    "-n",
    "--",
    "/usr/bin/journalctl",
    "--no-pager",
    "--output=short-iso",
    "-n",
    "200",
};
const disk_mounts_argv = [_][]const u8{
    "/usr/bin/findmnt",
    "--json",
    "--bytes",
    "--output",
    "TARGET,SOURCE,FSTYPE,OPTIONS,SIZE,AVAIL,USE%",
};
const disk_usage_argv = [_][]const u8{
    "/usr/bin/sudo",
    "-n",
    "--",
    "/usr/bin/du",
    "-x",
    "-B1",
    "-d",
    "2",
    "/",
};
const disk_containers_argv = [_][]const u8{
    "/usr/bin/docker",
    "system",
    "df",
    "-v",
};

/// Returns the only argv the helper is allowed to execute for a policy.
///
/// This switch has no `else` by design.  Adding an audit subject must add its
/// exact command here and to the manifest gate below; there is no generic
/// command fallback.
pub fn spec(check: Check, use_sudo: bool) error{ SudoForbidden, SudoRequired }!Spec {
    return switch (check) {
        .host => if (use_sudo) error.SudoForbidden else .{
            .check = check,
            .argv = &host_argv,
            .sudo = .forbidden,
            .read_only_wrapper = true,
        },
        .filesystem => if (use_sudo) error.SudoForbidden else .{
            .check = check,
            .argv = &filesystem_argv,
            .sudo = .forbidden,
            .read_only_wrapper = true,
        },
        .processes => if (use_sudo) error.SudoForbidden else .{
            .check = check,
            .argv = &processes_argv,
            .sudo = .forbidden,
            .read_only_wrapper = true,
        },
        .services => if (use_sudo) error.SudoForbidden else .{
            .check = check,
            .argv = &services_argv,
            .sudo = .forbidden,
            .read_only_wrapper = true,
        },
        .containers => if (use_sudo) error.SudoForbidden else .{
            .check = check,
            .argv = &containers_argv,
            .sudo = .forbidden,
            .read_only_wrapper = true,
        },
        .journal => if (!use_sudo) error.SudoRequired else .{
            .check = check,
            .argv = &journal_argv,
            .sudo = .required,
            .read_only_wrapper = true,
        },
        .disk_mounts => if (use_sudo) error.SudoForbidden else .{
            .check = check,
            .argv = &disk_mounts_argv,
            .sudo = .forbidden,
            .read_only_wrapper = true,
        },
        .disk_usage => if (!use_sudo) error.SudoRequired else .{
            .check = check,
            .argv = &disk_usage_argv,
            .sudo = .required,
            .read_only_wrapper = true,
        },
        .disk_containers => if (use_sudo) error.SudoForbidden else .{
            .check = check,
            .argv = &disk_containers_argv,
            .sudo = .forbidden,
            .read_only_wrapper = true,
        },
    };
}

pub const Request = struct {
    request_id: []const u8,
    check: Check,
    use_sudo: bool,
    deadline_ms: u64,
    grace_ms: u64,
};

pub const RequestError = error{
    UnknownCheck,
    SudoForbidden,
    SudoRequired,
    InvalidVersion,
    InvalidLength,
    ReservedBitsSet,
};

/// A request carries no argv.  The 20-byte body is:
///
///   version:u8, check:u8, sudo:u8, reserved:u8, deadline:u64, grace:u64
///
/// The outer length prefix and kind follow the existing helper framing.  The
/// helper must validate the same `spec` before it forks; it must not reconstruct
/// an argv from any bytes not covered by this format.
pub const wire = struct {
    pub const max_frame: usize = 1 << 20;
    pub const Kind = struct {
        /// host -> helper
        pub const audit_run: u8 = 0x04;
        /// helper -> host: the helper accepted the policy and used this
        /// manifest. The ordinary started/output/exited frames follow it.
        pub const audit_accepted: u8 = 0x86;
        /// helper -> host: request was rejected before a child was started.
        pub const audit_rejected: u8 = 0x87;
    };

    pub const EncodeError = RequestError || Allocator.Error;

    pub fn encodeRequest(arena: Allocator, request: Request) EncodeError![]u8 {
        _ = try spec(request.check, request.use_sudo);
        if (request.request_id.len == 0 or request.request_id.len > 64) return error.InvalidLength;
        const frame = try arena.alloc(u8, 4 + 1 + 5 + request.request_id.len + 16);
        std.mem.writeInt(u32, frame[0..4], @intCast(frame.len - 4), .little);
        frame[4] = Kind.audit_run;
        frame[5] = version;
        frame[6] = @intFromEnum(request.check);
        frame[7] = @intFromBool(request.use_sudo);
        frame[8] = 0;
        frame[9] = @intCast(request.request_id.len);
        @memcpy(frame[10..][0..request.request_id.len], request.request_id);
        const words = frame[10 + request.request_id.len ..];
        std.mem.writeInt(u64, words[0..8], request.deadline_ms, .little);
        std.mem.writeInt(u64, words[8..16], request.grace_ms, .little);
        return frame;
    }

    pub const Accepted = struct {
        check: Check,
        use_sudo: bool,
        manifest: [32]u8,
    };

    /// Encodes the helper's proof that it accepted the closed policy.  The
    /// proof precedes the ordinary started/output/exited frames, and the host
    /// will refuse to call the capability audited unless this exact frame
    /// verifies.
    pub fn encodeAccepted(arena: Allocator, request: Request) EncodeError![]u8 {
        _ = try spec(request.check, request.use_sudo);
        var frame: [4 + 1 + 35]u8 = undefined;
        std.mem.writeInt(u32, frame[0..4], 36, .little);
        frame[4] = Kind.audit_accepted;
        frame[5] = version;
        frame[6] = @intFromEnum(request.check);
        frame[7] = @intFromBool(request.use_sudo);
        const digest = manifestDigest();
        @memcpy(frame[8..40], &digest);
        return arena.dupe(u8, &frame);
    }

    pub fn encodeRejected(arena: Allocator, reason: Rejection) Allocator.Error![]u8 {
        var frame: [4 + 1 + 2]u8 = undefined;
        std.mem.writeInt(u32, frame[0..4], 3, .little);
        frame[4] = Kind.audit_rejected;
        frame[5] = version;
        frame[6] = @intFromEnum(reason);
        return arena.dupe(u8, &frame);
    }

    pub const Rejection = enum(u8) {
        malformed = 1,
        unknown_check = 2,
        sudo_forbidden = 3,
        sudo_required = 4,
        policy_mismatch = 5,
        helper_not_audit_capable = 6,
        _,
    };

    pub const ReplyError = error{
        MissingAcceptance,
        MultipleAcceptances,
        AcceptanceWrongSize,
        UnknownReplyFrame,
        AcceptedPolicyMismatch,
        AcceptedManifestMismatch,
        Rejected,
    } || RequestError || Allocator.Error;

    /// Reads the audit acceptance/rejection control frames from a reply.  The
    /// ordinary supervisor reply frames are intentionally ignored here; the
    /// execution layer continues to decode them with `supervisor.wire.decode`.
    /// This separation makes it impossible for a normal `run` reply to count as
    /// an audit acknowledgement.
    pub fn decodeAcceptance(
        arena: Allocator,
        bytes: []const u8,
        requested: Request,
    ) ReplyError!?Accepted {
        var accepted: ?Accepted = null;
        var at: usize = 0;
        while (at + 4 <= bytes.len) {
            const n = std.mem.readInt(u32, bytes[at..][0..4], .little);
            if (n == 0 or n > max_frame or at + 4 + n > bytes.len) return error.InvalidLength;
            const kind = bytes[at + 4];
            const payload = bytes[at + 5 ..][0 .. n - 1];
            at += 4 + n;
            switch (kind) {
                Kind.audit_accepted => {
                    if (payload.len != 35) return error.AcceptanceWrongSize;
                    if (accepted != null) return error.MultipleAcceptances;
                    if (payload[0] != version) return error.InvalidVersion;
                    const check: Check = std.enums.fromInt(Check, payload[1]) orelse return error.UnknownCheck;
                    const use_sudo = switch (payload[2]) {
                        0 => false,
                        1 => true,
                        else => return error.ReservedBitsSet,
                    };
                    if (check != requested.check or use_sudo != requested.use_sudo)
                        return error.AcceptedPolicyMismatch;
                    _ = try spec(check, use_sudo);
                    var manifest: [32]u8 = undefined;
                    @memcpy(&manifest, payload[3..35]);
                    const want = manifestDigest();
                    if (!std.mem.eql(u8, &manifest, &want))
                        return error.AcceptedManifestMismatch;
                    accepted = .{ .check = check, .use_sudo = use_sudo, .manifest = manifest };
                },
                Kind.audit_rejected => return error.Rejected,
                else => {},
            }
        }
        if (accepted == null) return error.MissingAcceptance;
        _ = arena;
        return accepted;
    }

    /// Removes the audit policy acknowledgement before handing the remaining
    /// started/output/exited frames to the ordinary supervisor decoder.  The
    /// supervisor wire intentionally rejects unknown kinds, so passing the
    /// acknowledgement through would turn every successful native audit into
    /// an indeterminate operation after the remote command had already ended.
    pub fn supervisorReply(arena: Allocator, bytes: []const u8) (RequestError || Allocator.Error)![]const u8 {
        var reply: std.ArrayList(u8) = .empty;
        var at: usize = 0;
        while (at < bytes.len) {
            if (at + 4 > bytes.len) return error.InvalidLength;
            const n = std.mem.readInt(u32, bytes[at..][0..4], .little);
            if (n == 0 or n > max_frame or at + 4 + n > bytes.len) return error.InvalidLength;
            const end = at + 4 + n;
            const kind = bytes[at + 4];
            if (kind != Kind.audit_accepted and kind != Kind.audit_rejected)
                try reply.appendSlice(arena, bytes[at..end]);
            at = end;
        }
        return reply.items;
    }
};

/// The policy manifest is part of the wire trust decision.  A helper that
/// acknowledges an audit request with a different digest is not considered an
/// audit supervisor, even if its executable digest happens to match a stale
/// local fact.  Keep this text canonical and versioned; changing an argv or a
/// sudo rule changes the digest and therefore requires a new helper.
const manifest_text =
    "terminus-audit-policy/1\n" ++
    "host\t/usr/bin/uname\t-a\tsudo=forbidden\treadonly=direct-null-stdin\n" ++
    "filesystem\t/usr/bin/df\t-P\t/\tsudo=forbidden\treadonly=direct-null-stdin\n" ++
    "processes\t/usr/bin/ps\t-eo\tpid=,ppid=,user=,stat=,comm=\tsudo=forbidden\treadonly=direct-null-stdin\n" ++
    "services\t/usr/bin/systemctl\tlist-units\t--type=service\t--state=running,failed\t--no-pager\t--plain\tsudo=forbidden\treadonly=direct-null-stdin\n" ++
    "containers\t/usr/bin/docker\tps\t--all\t--no-trunc\tsudo=forbidden\treadonly=direct-null-stdin\n" ++
    "journal\t/usr/bin/sudo\t-n\t--\t/usr/bin/journalctl\t--no-pager\t--output=short-iso\t-n\t200\tsudo=required\treadonly=direct-null-stdin\n" ++
    "disk-mounts\t/usr/bin/findmnt\t--json\t--bytes\t--output\tTARGET,SOURCE,FSTYPE,OPTIONS,SIZE,AVAIL,USE%\tsudo=forbidden\treadonly=direct-null-stdin\n" ++
    "disk-usage\t/usr/bin/sudo\t-n\t--\t/usr/bin/du\t-x\t-B1\t-d\t2\t/\tsudo=required\treadonly=direct-null-stdin\n" ++
    "disk-containers\t/usr/bin/docker\tsystem\tdf\t-v\tsudo=forbidden\treadonly=direct-null-stdin\n";

pub fn manifestDigest() [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(manifest_text, &out, .{});
    return out;
}

pub fn manifestText() []const u8 {
    return manifest_text;
}

test "audit policy is closed and every subject is a read-only direct wrapper" {
    const t = std.testing;
    const names = [_][]const u8{ "host", "filesystem", "processes", "services", "containers", "journal", "disk-mounts", "disk-usage", "disk-containers" };
    for (names) |name| {
        const check = try Check.parse(name);
        const use_sudo = check == .journal or check == .disk_usage;
        const selected = try spec(check, use_sudo);
        try t.expect(selected.read_only_wrapper);
        try t.expect(selected.argv.len > 0);
        try t.expect(std.mem.indexOfScalar(u8, selected.argv[0], ' ') == null);
        try t.expect(std.mem.indexOfScalar(u8, selected.argv[0], ';') == null);
    }
    try t.expectError(error.UnknownCheck, Check.parse("/bin/sh"));
    try t.expectError(error.UnknownCheck, Check.parse("host --version"));
    try t.expectError(error.SudoForbidden, spec(.host, true));
    try t.expectError(error.SudoRequired, spec(.journal, false));
    try t.expectError(error.SudoRequired, spec(.disk_usage, false));
    const digest = manifestDigest();
    try t.expect(!std.mem.eql(u8, &digest, &([_]u8{0} ** 32)));
}

test "audit request contains policy id only, never caller argv or shell text" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const frame = try wire.encodeRequest(arena_state.allocator(), .{
        .request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF",
        .check = .journal,
        .use_sudo = true,
        .deadline_ms = 5000,
        .grace_ms = 1000,
    });
    try t.expectEqual(@as(usize, 52), frame.len);
    try t.expectEqual(wire.Kind.audit_run, frame[4]);
    try t.expectEqual(@as(u8, @intFromEnum(Check.journal)), frame[6]);
    try t.expectEqual(@as(u8, 1), frame[7]);
    try t.expect(std.mem.indexOf(u8, frame, "/bin/sh") == null);
    try t.expect(std.mem.indexOf(u8, frame, "sudo") == null);
}

test "audit allowlist has no shell or mutating escape hatch" {
    const t = std.testing;
    const checks = std.enums.values(Check);
    for (checks) |check| {
        const selected = spec(check, check == .journal or check == .disk_usage) catch unreachable;
        for (selected.argv) |word| {
            try t.expect(std.mem.indexOfScalar(u8, word, ';') == null);
            try t.expect(std.mem.indexOfScalar(u8, word, '$') == null);
            try t.expect(std.mem.indexOfScalar(u8, word, '`') == null);
            try t.expect(!std.mem.eql(u8, word, "sh"));
            try t.expect(!std.mem.eql(u8, word, "bash"));
            try t.expect(!std.mem.eql(u8, word, "rm"));
            try t.expect(!std.mem.eql(u8, word, "kill"));
            try t.expect(!std.mem.eql(u8, word, "restart"));
            try t.expect(!std.mem.eql(u8, word, "set"));
            try t.expect(!std.mem.eql(u8, word, "apply"));
        }
    }
    try t.expect(std.mem.indexOf(u8, manifestText(), "readonly=direct-null-stdin") != null);
}

test "audit acceptance requires the remote policy manifest, not a local string check" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const request: Request = .{ .request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF", .check = .host, .use_sudo = false, .deadline_ms = 1000, .grace_ms = 100 };

    var good: [4 + 1 + 35]u8 = undefined;
    std.mem.writeInt(u32, good[0..4], 36, .little);
    good[4] = wire.Kind.audit_accepted;
    good[5] = version;
    good[6] = @intFromEnum(Check.host);
    good[7] = 0;
    const digest = manifestDigest();
    @memcpy(good[8..40], &digest);
    try t.expect((try wire.decodeAcceptance(arena, &good, request)) != null);

    const encoded = try wire.encodeAccepted(arena, request);
    try t.expect((try wire.decodeAcceptance(arena, encoded, request)) != null);

    var forged = good;
    forged[8] ^= 1;
    try t.expectError(error.AcceptedManifestMismatch, wire.decodeAcceptance(arena, &forged, request));

    var normal_run = good;
    normal_run[4] = 0x01;
    try t.expectError(error.MissingAcceptance, wire.decodeAcceptance(arena, &normal_run, request));
}

test "audit forbidden sudo and unknown policy ids fail before a child can exist" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try t.expectError(error.SudoForbidden, wire.encodeRequest(arena, .{
        .request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF",
        .check = .filesystem,
        .use_sudo = true,
        .deadline_ms = 1000,
        .grace_ms = 100,
    }));

    var unknown: [52]u8 = undefined;
    std.mem.writeInt(u32, unknown[0..4], 48, .little);
    unknown[4] = wire.Kind.audit_run;
    unknown[5] = version;
    unknown[6] = 250;
    unknown[7] = 0;
    unknown[8] = 0;
    unknown[9] = 26;
    @memcpy(unknown[10..36], "01JQXW8ZK4N0RS7T3VYB2MCDEF");
    @memset(unknown[36..52], 0);
    try t.expectError(error.UnknownCheck, decodeRequest(&unknown));

    const valid = try wire.encodeRequest(arena, .{
        .request_id = "01JQXW8ZK4N0RS7T3VYB2MCDEF",
        .check = .host,
        .use_sudo = false,
        .deadline_ms = 1000,
        .grace_ms = 100,
    });
    const decoded = try decodeRequestBody(valid[4..]);
    try t.expectEqual(Check.host, decoded.check);
}

/// Helper-side request validation.  The helper should call this before forking
/// and before emitting `audit_accepted`; keeping it here gives the helper and
/// host one exact parser without importing any host state.
pub fn decodeRequest(frame: []const u8) RequestError!Request {
    if (frame.len < 26) return error.InvalidLength;
    return decodeRequestBody(frame[4..]);
}

/// The helper's `readFrame` returns the body without the four-byte length
/// prefix.  This is the helper-facing twin of `decodeRequest`, so its caller
/// cannot accidentally parse offsets from the wrong side of the frame.
pub fn decodeRequestBody(body: []const u8) RequestError!Request {
    if (body.len < 22) return error.InvalidLength;
    if (body[0] != wire.Kind.audit_run) return error.InvalidLength;
    if (body[1] != version) return error.InvalidVersion;
    if (body[4] != 0) return error.ReservedBitsSet;
    const id_len: usize = body[5];
    if (id_len == 0 or id_len > 64 or body.len != 22 + id_len) return error.InvalidLength;
    const check = std.enums.fromInt(Check, body[2]) orelse return error.UnknownCheck;
    const use_sudo = switch (body[3]) {
        0 => false,
        1 => true,
        else => return error.ReservedBitsSet,
    };
    _ = try spec(check, use_sudo);
    return .{
        .request_id = body[6..][0..id_len],
        .check = check,
        .use_sudo = use_sudo,
        .deadline_ms = std.mem.readInt(u64, body[6 + id_len ..][0..8], .little),
        .grace_ms = std.mem.readInt(u64, body[14 + id_len ..][0..8], .little),
    };
}
