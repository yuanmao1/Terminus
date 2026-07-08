const std = @import("std");

// All of libssh2 except the crypto backends, which crypto.c #includes
// based on the LIBSSH2_* backend macro.
const libssh2_sources = [_][]const u8{
    "agent.c",
    "agent_win.c",
    "bcrypt_pbkdf.c",
    "blowfish.c",
    "chacha.c",
    "channel.c",
    "cipher-chachapoly.c",
    "comp.c",
    "crypt.c",
    "crypto.c",
    "global.c",
    "hostkey.c",
    "keepalive.c",
    "kex.c",
    "knownhost.c",
    "mac.c",
    "misc.c",
    "packet.c",
    "pem.c",
    "poly1305.c",
    "publickey.c",
    "scp.c",
    "session.c",
    "sftp.c",
    "transport.c",
    "userauth.c",
    "userauth_kbd_packet.c",
    "version.c",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // SQLite: translate-c the amalgamation header into an importable module,
    // and compile sqlite3.c into the library module below.
    const sqlite_h = b.addTranslateC(.{
        .root_source_file = b.path("vendor/sqlite/sqlite3.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // libssh2: same pattern. Backend crypto sources (openssl.c, wincng.c,
    // ...) are pulled in by crypto.c according to the backend macro, so they
    // are not listed here. Windows-first: WinCNG backend (no OpenSSL dep).
    // Pinned to Debug: in release modes translate-c's rendering of mingw
    // winsock inline helpers trips "unused local constant" errors, and the
    // optimize mode of a bindings module has no runtime effect anyway.
    const ssh2_h = b.addTranslateC(.{
        .root_source_file = b.path("vendor/terminus_ssh.h"),
        .target = target,
        .optimize = .Debug,
        .link_libc = true,
    });
    ssh2_h.addIncludePath(b.path("vendor/libssh2/include"));

    const mod = b.addModule("Terminus", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            // Named (not createModule) so ZLS can resolve the imports.
            .{ .name = "sqlite", .module = sqlite_h.addModule("sqlite") },
            .{ .name = "ssh2", .module = ssh2_h.addModule("ssh2") },
        },
    });
    mod.addCSourceFile(.{
        .file = b.path("vendor/sqlite/sqlite3.c"),
        .flags = &.{
            "-DSQLITE_THREADSAFE=1",
            "-DSQLITE_OMIT_LOAD_EXTENSION",
            "-DSQLITE_OMIT_DEPRECATED",
            "-DSQLITE_DQS=0",
        },
    });

    if (target.result.os.tag != .windows) {
        // M5 adds an OpenSSL-backed build for Linux/macOS.
        const fail = b.addFail("Terminus currently builds Windows-only (libssh2 WinCNG backend); Linux/macOS lands in M5");
        b.getInstallStep().dependOn(&fail.step);
        return;
    }
    mod.addIncludePath(b.path("vendor/libssh2/include"));
    mod.addIncludePath(b.path("vendor/libssh2/src"));
    mod.addCSourceFiles(.{
        .root = b.path("vendor/libssh2/src"),
        .files = &libssh2_sources,
        // ECDSA_WINCNG: enables ecdh kex + ECDSA host/user keys (needed by
        // modern servers). Note WinCNG cannot do ed25519 at all — switching
        // to an OpenSSL/wolfSSL backend for that is tracked in PLAN §8.
        .flags = &.{ "-DLIBSSH2_WINCNG", "-DLIBSSH2_ECDSA_WINCNG" },
    });
    mod.linkSystemLibrary("ws2_32", .{});
    mod.linkSystemLibrary("bcrypt", .{});
    mod.linkSystemLibrary("crypt32", .{});
    // Skill text ships inside the binary (`terminus setup`).
    mod.addAnonymousImport("terminus_skill", .{
        .root_source_file = b.path("skill/SKILL.md"),
    });


    const exe = b.addExecutable(.{
        .name = "Terminus",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "Terminus", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
