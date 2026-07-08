//! Schema migrations driven by `PRAGMA user_version`.
//!
//! Each entry in `migrations` moves the schema up one version. New schema
//! changes append an entry; existing entries are frozen forever.
const std = @import("std");
const Db = @import("Db.zig");

const migrations = [_][:0]const u8{
    \\CREATE TABLE keys (
    \\  id          INTEGER PRIMARY KEY,
    \\  name        TEXT NOT NULL UNIQUE,
    \\  kind        TEXT NOT NULL,
    \\  private_pem BLOB,
    \\  public_pem  BLOB,
    \\  passphrase  TEXT,
    \\  created_at  INTEGER NOT NULL
    \\);
    \\CREATE TABLE servers (
    \\  id          INTEGER PRIMARY KEY,
    \\  name        TEXT NOT NULL UNIQUE,
    \\  note        TEXT,
    \\  host        TEXT NOT NULL,
    \\  port        INTEGER NOT NULL DEFAULT 22,
    \\  username    TEXT NOT NULL,
    \\  key_id      INTEGER REFERENCES keys(id),
    \\  created_at  INTEGER NOT NULL,
    \\  updated_at  INTEGER NOT NULL
    \\);
    \\CREATE TABLE sessions (
    \\  id            INTEGER PRIMARY KEY,
    \\  server_id     INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    \\  name          TEXT NOT NULL,
    \\  note          TEXT,
    \\  last_seen_at  INTEGER,
    \\  created_at    INTEGER NOT NULL,
    \\  UNIQUE(server_id, name)
    \\);
    \\CREATE TABLE memories (
    \\  id          INTEGER PRIMARY KEY,
    \\  server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    \\  session_id  INTEGER REFERENCES sessions(id) ON DELETE CASCADE,
    \\  key         TEXT,
    \\  content     TEXT NOT NULL,
    \\  tags        TEXT,
    \\  created_at  INTEGER NOT NULL,
    \\  updated_at  INTEGER NOT NULL
    \\);
    \\CREATE UNIQUE INDEX idx_memories_scope_key
    \\  ON memories(server_id, IFNULL(session_id, 0), key) WHERE key IS NOT NULL;
    ,
    // v2: local read cursor per session (byte offset into the remote
    // pipe-pane log file).
    \\ALTER TABLE sessions ADD COLUMN cursor INTEGER NOT NULL DEFAULT 0;
    ,
    // v3: async jobs (each runs in its own dedicated tmux session named
    // job-<name>) and per-server default working directory.
    \\CREATE TABLE jobs (
    \\  id          INTEGER PRIMARY KEY,
    \\  server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    \\  name        TEXT NOT NULL,
    \\  command     TEXT NOT NULL,
    \\  sentinel    TEXT NOT NULL,
    \\  status      TEXT NOT NULL DEFAULT 'running',
    \\  exit_code   INTEGER,
    \\  read_cursor INTEGER NOT NULL DEFAULT 0,
    \\  created_at  INTEGER NOT NULL,
    \\  finished_at INTEGER,
    \\  UNIQUE(server_id, name)
    \\);
    \\ALTER TABLE servers ADD COLUMN cwd TEXT;
    ,
    // v4: machine-readable facts (key/value for command orchestration,
    // distinct from natural-language memories) and the execution history
    // that backs `terminus history` (audit trail).
    \\CREATE TABLE facts (
    \\  id          INTEGER PRIMARY KEY,
    \\  server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    \\  key         TEXT NOT NULL,
    \\  value       TEXT NOT NULL,
    \\  updated_at  INTEGER NOT NULL,
    \\  UNIQUE(server_id, key)
    \\);
    \\CREATE TABLE history (
    \\  id          INTEGER PRIMARY KEY,
    \\  server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    \\  kind        TEXT NOT NULL,      -- exec | job | push | pull | sync
    \\  detail      TEXT NOT NULL,      -- command line or transfer paths
    \\  cwd         TEXT,
    \\  exit_code   INTEGER,
    \\  transport   TEXT,               -- daemon | direct
    \\  duration_ms INTEGER,
    \\  created_at  INTEGER NOT NULL
    \\);
    ,
};

pub fn apply(db: *Db) Db.Error!void {
    const version = try userVersion(db);
    inline for (migrations, 1..) |sql, target| {
        if (version < target) {
            try db.exec("BEGIN");
            errdefer db.exec("ROLLBACK") catch {};
            try db.exec(sql);
            try db.exec(std.fmt.comptimePrint("PRAGMA user_version = {d}", .{target}));
            try db.exec("COMMIT");
        }
    }
}

fn userVersion(db: *Db) Db.Error!i64 {
    var stmt = try db.prepare("PRAGMA user_version");
    defer stmt.deinit();
    if (!try stmt.step()) return error.Sqlite;
    return stmt.columnInt(0);
}
