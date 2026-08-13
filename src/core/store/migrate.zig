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
    // v5: the immutable operation ledger.
    //
    // Every call that can produce a remote side effect gets a `request_id`
    // here plus an append-only trail in `operation_events`. Job and session
    // names are *aliases*, never identity: they get reused and deleted, so
    // they cannot anchor an audit record.
    //
    // `status` is the last *observed* state. Reconciliation never rewrites
    // it — it records the later-proven truth in `resolved_status` so the
    // ledger preserves "we believed X, then proved Y".
    \\CREATE TABLE operations (
    \\  request_id          TEXT PRIMARY KEY,
    \\  schema_version      INTEGER NOT NULL,
    \\  server_id           INTEGER REFERENCES servers(id) ON DELETE SET NULL,
    \\  server_name         TEXT NOT NULL,
    \\  kind                TEXT NOT NULL,
    \\  scope_kind          TEXT,
    \\  scope_key           TEXT,
    \\  alias               TEXT,
    \\  status              TEXT NOT NULL CHECK (status IN (
    \\                        'created','connecting','submitted','remote_started',
    \\                        'completed','failed','timed_out','cancelled',
    \\                        'indeterminate')),
    \\  resolved_status     TEXT CHECK (resolved_status IS NULL OR resolved_status IN (
    \\                        'completed','failed','timed_out','cancelled')),
    \\  reconciled_at       INTEGER,
    \\  resolution_evidence TEXT,
    \\  argv_redacted       TEXT,
    \\  argv_sha256         TEXT,
    \\  cwd                 TEXT,
    \\  shell               TEXT,
    \\  capability_json     TEXT,
    \\  transport           TEXT,
    \\  created_at          INTEGER NOT NULL,
    \\  updated_at          INTEGER NOT NULL
    \\);
    \\CREATE INDEX idx_operations_server_created ON operations(server_id, created_at DESC);
    \\CREATE INDEX idx_operations_alias ON operations(server_id, alias) WHERE alias IS NOT NULL;
    \\CREATE INDEX idx_operations_unsettled ON operations(server_id, status)
    \\  WHERE status IN ('created','connecting','submitted','remote_started','indeterminate');
    \\CREATE TABLE operation_events (
    \\  id                 INTEGER PRIMARY KEY,
    \\  request_id         TEXT NOT NULL REFERENCES operations(request_id) ON DELETE CASCADE,
    \\  seq                INTEGER NOT NULL,
    \\  schema_version     INTEGER NOT NULL,
    \\  kind               TEXT NOT NULL,
    \\  phase              TEXT,
    \\  status             TEXT,
    \\  is_terminal        INTEGER NOT NULL DEFAULT 0 CHECK (is_terminal IN (0,1)),
    \\  connected          INTEGER,
    \\  remote_started     INTEGER,
    \\  remote_pid         INTEGER,
    \\  remote_pgid        INTEGER,
    \\  remote_start_token TEXT,
    \\  started_at         INTEGER,
    \\  finished_at        INTEGER,
    \\  duration_ms        INTEGER,
    \\  exit_code          INTEGER,
    \\  term_signal        INTEGER,
    \\  timed_out          INTEGER,
    \\  transport_error    TEXT,
    \\  error_code         TEXT,
    \\-- Evidence carried by specific Terminal variants, so a reconciler can
    \\-- see where to look and an auditor can see how a cancel was performed.
    \\  last_observed      TEXT,
    \\  cancel_method      TEXT,
    \\  stdin_bytes        INTEGER,
    \\  stdin_sha256       TEXT,
    \\  stdout_bytes       INTEGER,
    \\  stdout_sha256      TEXT,
    \\  stdout_truncated   INTEGER,
    \\  stdout_digest      TEXT,
    \\  stderr_bytes       INTEGER,
    \\  stderr_sha256      TEXT,
    \\  stderr_truncated   INTEGER,
    \\  stderr_digest      TEXT,
    \\  observed_at        INTEGER NOT NULL,
    \\  source             TEXT NOT NULL,
    \\  correlation_id     TEXT,
    \\  detail_json        TEXT,
    \\  UNIQUE(request_id, seq)
    \\);
    \\-- At most one terminal event per operation, enforced by the database so
    \\-- two racing writers cannot both "finish" the same request. The loser
    \\-- gets error.Constraint and must read the winner's terminal instead of
    \\-- overwriting it.
    \\CREATE UNIQUE INDEX idx_operation_events_terminal
    \\  ON operation_events(request_id) WHERE is_terminal = 1;
    ,
    // v6: resumable transfers and immutable job attempts.
    //
    // `transfer_checkpoints` binds a partial upload to the *identity* of its
    // source, not just a path: resume refuses to continue when the local
    // file changed or the remote partial does not match what we last
    // confirmed. Without that binding a partial from one file can silently
    // become the head of another.
    //
    // `job_attempts` is write-once. The mutable `jobs` row stays as the
    // "current attempt" alias for back-compat; the attempt row is what an
    // audit reads, and it survives `job rm` and same-name reruns.
    \\CREATE TABLE transfer_checkpoints (
    \\  id                    INTEGER PRIMARY KEY,
    \\  request_id            TEXT NOT NULL REFERENCES operations(request_id) ON DELETE CASCADE,
    \\  schema_version        INTEGER NOT NULL,
    \\  direction             TEXT NOT NULL CHECK (direction IN ('push','pull','fetch')),
    \\  local_path            TEXT,
    \\  local_size            INTEGER,
    \\  local_mtime_ns        INTEGER,
    \\  local_sha256          TEXT,
    \\  source_url            TEXT,
    \\  source_etag           TEXT,
    \\  source_last_modified  TEXT,
    \\  source_size           INTEGER,
    \\  remote_path           TEXT NOT NULL,
    \\  remote_partial_path   TEXT NOT NULL,
    \\  remote_partial_len    INTEGER NOT NULL DEFAULT 0,
    \\  remote_partial_sha256 TEXT,
    \\  chunk_size            INTEGER NOT NULL,
    \\  confirmed_offset      INTEGER NOT NULL DEFAULT 0,
    \\  total_bytes           INTEGER,
    \\  expected_sha256       TEXT,
    \\  verified_sha256       TEXT,
    \\  no_clobber            INTEGER NOT NULL DEFAULT 0 CHECK (no_clobber IN (0,1)),
    \\  state                 TEXT NOT NULL,
    \\  failure_reason        TEXT,
    \\  created_at            INTEGER NOT NULL,
    \\  updated_at            INTEGER NOT NULL
    \\);
    \\CREATE INDEX idx_checkpoints_request ON transfer_checkpoints(request_id);
    \\CREATE INDEX idx_checkpoints_resume ON transfer_checkpoints(remote_path, state);
    \\CREATE TABLE job_attempts (
    \\  id                   INTEGER PRIMARY KEY,
    \\  request_id           TEXT NOT NULL UNIQUE REFERENCES operations(request_id) ON DELETE CASCADE,
    \\  schema_version       INTEGER NOT NULL,
    \\  server_id            INTEGER REFERENCES servers(id) ON DELETE SET NULL,
    \\  server_name          TEXT NOT NULL,
    \\  job_name             TEXT NOT NULL,
    \\  attempt_no           INTEGER NOT NULL,
    \\  sentinel             TEXT,
    \\  tmux_session         TEXT,
    \\  cwd                  TEXT,
    \\  interpreter          TEXT,
    \\  shell                TEXT,
    \\  script_body_redacted TEXT,
    \\  script_sha256        TEXT,
    \\  script_bytes         INTEGER,
    \\  options_json         TEXT,
    \\  env_redacted_json    TEXT,
    \\  entry_path           TEXT,
    \\  entry_sha256         TEXT,
    \\  created_at           INTEGER NOT NULL
    \\);
    \\CREATE INDEX idx_job_attempts_lookup ON job_attempts(server_id, job_name, attempt_no DESC);
    \\-- Observation cache, kept OUT of job_attempts so that table stays
    \\-- write-once. The event ledger remains the authority; this is what
    \\-- `job ls` and offline handoff read, always alongside last_probed_at so
    \\-- a stale reading can never be mistaken for a live one.
    \\CREATE TABLE job_probe_state (
    \\  request_id             TEXT PRIMARY KEY REFERENCES operations(request_id) ON DELETE CASCADE,
    \\  probe_cursor           INTEGER NOT NULL DEFAULT 0,
    \\  parser_carry           TEXT,
    \\  latest_progress_json   TEXT,
    \\  latest_business_result TEXT,
    \\  latest_phase           TEXT,
    \\  session_alive          INTEGER,
    \\  last_probed_at         INTEGER,
    \\  updated_at             INTEGER NOT NULL
    \\);
    ,
    // v7: coordination (leases, plans) and the trust root (host pins).
    //
    // Leases are append-only: acquiring never UPDATEs a peer's row, it
    // releases the expired one and inserts a new row, so takeovers leave a
    // chain. The partial unique index makes "one active lease per scope" a
    // database invariant rather than a code convention.
    //
    // `host_pins` exists before any pinning feature is exposed: today
    // Terminus performs NO host-key verification at all, and a "pinned"
    // interface without a real verification chain would be a lie.
    \\CREATE TABLE leases (
    \\  id             INTEGER PRIMARY KEY,
    \\  server_id      INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    \\  scope_kind     TEXT NOT NULL CHECK (scope_kind IN ('server','job','path')),
    \\  scope_key      TEXT NOT NULL,
    \\  owner_token    TEXT NOT NULL,
    \\  owner_label    TEXT,
    \\  note           TEXT,
    \\  request_id     TEXT REFERENCES operations(request_id) ON DELETE SET NULL,
    \\  acquired_at    INTEGER NOT NULL,
    \\  renewed_at     INTEGER NOT NULL,
    \\  expires_at     INTEGER NOT NULL,
    \\  released_at    INTEGER,
    \\  release_reason TEXT CHECK (release_reason IS NULL OR release_reason IN (
    \\                   'released','expired','takeover','force')),
    \\  superseded_by  INTEGER REFERENCES leases(id)
    \\);
    \\CREATE UNIQUE INDEX idx_leases_active
    \\  ON leases(server_id, scope_kind, scope_key) WHERE released_at IS NULL;
    \\CREATE INDEX idx_leases_owner ON leases(owner_token) WHERE released_at IS NULL;
    \\CREATE TABLE plan_runs (
    \\  run_id             TEXT PRIMARY KEY,
    \\  schema_version     INTEGER NOT NULL,
    \\  server_id          INTEGER REFERENCES servers(id) ON DELETE SET NULL,
    \\  server_name        TEXT NOT NULL,
    \\  name               TEXT,
    \\  plan_sha256        TEXT NOT NULL,
    \\  plan_body_redacted TEXT,
    \\  status             TEXT NOT NULL,
    \\  created_at         INTEGER NOT NULL,
    \\  updated_at         INTEGER NOT NULL
    \\);
    \\CREATE TABLE phase_attempts (
    \\  id           INTEGER PRIMARY KEY,
    \\  run_id       TEXT NOT NULL REFERENCES plan_runs(run_id) ON DELETE CASCADE,
    \\  phase_index  INTEGER NOT NULL,
    \\  phase_id     TEXT NOT NULL,
    \\  attempt_no   INTEGER NOT NULL,
    \\  is_mutation  INTEGER NOT NULL DEFAULT 0 CHECK (is_mutation IN (0,1)),
    \\  approved_at  INTEGER,
    \\  approved_by  TEXT,
    \\  request_id   TEXT REFERENCES operations(request_id) ON DELETE SET NULL,
    \\  status       TEXT NOT NULL,
    \\  created_at   INTEGER NOT NULL,
    \\  updated_at   INTEGER NOT NULL,
    \\  UNIQUE(run_id, phase_id, attempt_no)
    \\);
    \\CREATE TABLE host_pins (
    \\  id                 INTEGER PRIMARY KEY,
    \\  host               TEXT NOT NULL,
    \\  port               INTEGER NOT NULL,
    \\  key_type           TEXT NOT NULL,
    \\  fingerprint_sha256 TEXT NOT NULL,
    \\  public_key_b64     TEXT,
    \\  trusted_at         INTEGER NOT NULL,
    \\  trust_source       TEXT NOT NULL CHECK (trust_source IN (
    \\                       'explicit_pin','first_use','rotated','imported')),
    \\  revoked_at         INTEGER,
    \\  revoke_reason      TEXT,
    \\  superseded_by      INTEGER REFERENCES host_pins(id),
    \\  note               TEXT
    \\);
    \\CREATE UNIQUE INDEX idx_host_pins_active
    \\  ON host_pins(host, port, key_type) WHERE revoked_at IS NULL;
    \\-- Declared secret locations, so redaction does not depend on pattern
    \\-- guessing alone. Pattern matching stays as a backstop, never the only
    \\-- line of defence.
    \\CREATE TABLE redaction_rules (
    \\  id           INTEGER PRIMARY KEY,
    \\  rule_kind    TEXT NOT NULL CHECK (rule_kind IN (
    \\                 'env_name','arg_index','header_name','literal')),
    \\  pattern      TEXT NOT NULL,
    \\  server_id    INTEGER REFERENCES servers(id) ON DELETE CASCADE,
    \\  created_at   INTEGER NOT NULL,
    \\  UNIQUE(rule_kind, pattern, server_id)
    \\);
    \\CREATE TABLE retention_rules (
    \\  table_name TEXT PRIMARY KEY,
    \\  keep_days  INTEGER,
    \\  updated_at INTEGER NOT NULL
    \\);
    ,
    // v8: machine-local singletons.
    //
    // A lease owner must be stable across processes: a host-pid string
    // changes every invocation, so an agent could never renew or release its
    // own lease. The token is minted once and reused, which is what makes
    // "same owner renews, different owner conflicts" meaningful.
    \\CREATE TABLE local_identity (
    \\  key        TEXT PRIMARY KEY,
    \\  value      TEXT NOT NULL,
    \\  created_at INTEGER NOT NULL
    \\);
    ,
    // v9: which launch owns a job row.
    //
    // The row is written before the remote is touched, so `UNIQUE(server_id,
    // name)` can pick a winner between two simultaneous launches. That makes
    // it a reservation, and a reservation needs an owner: a launcher that
    // aborts has to be able to release *its* row and nobody else's.
    //
    // Neither the name nor the rowid can serve. The name is what a takeover
    // transfers. The rowid is reused — sqlite hands the next INSERT the id of
    // the row that was just deleted, so an aborted launcher releasing "id 5,
    // still pending" would delete the replacement that inherited id 5 and
    // leave its command running on the host with nothing tracking it.
    //
    // `request_id` is unique by construction and is already the identity the
    // rest of the ledger is keyed on. Nullable because rows written by 0.1.x
    // predate the notion; those are unowned and only a human can clear them.
    \\ALTER TABLE jobs ADD COLUMN owner_request_id TEXT;
    ,
};

/// Number of schema versions this binary knows about.
pub const latest_version = migrations.len;

pub fn apply(db: *Db) Db.Error!void {
    // Fast path: an up-to-date database takes no write lock at all, so the
    // common case (every CLI invocation) never contends with a peer.
    if (try userVersion(db) >= latest_version) return;
    inline for (migrations, 1..) |sql, target| try applyOne(db, sql, target);
}

/// Detects a database built by a *pre-release* revision of a migration.
///
/// Migrations are frozen once shipped, but before 0.2.0 exists the v5+ SQL is
/// still being corrected in place. A database created by an earlier commit of
/// this branch reports the right `user_version` while missing columns that
/// were added afterwards, and the failures that follow are confusing SQL
/// errors far from the cause. Detecting it here turns that into one clear
/// message. Costs a single query on databases at v5 or above.
pub fn checkPreReleaseDrift(db: *Db) (Db.Error || error{PreReleaseSchemaDrift})!void {
    if (try userVersion(db) < 5) return;
    if (!try hasColumn(db, "operation_events", "last_observed"))
        return error.PreReleaseSchemaDrift;
}

fn hasColumn(db: *Db, table: [:0]const u8, column: []const u8) Db.Error!bool {
    // pragma_table_info is a table-valued function, so this needs no string
    // interpolation of the column name.
    var stmt = try db.prepare("SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2");
    defer stmt.deinit();
    try stmt.bindText(1, table);
    try stmt.bindText(2, column);
    return try stmt.step();
}

/// Applies one migration, safe against a second process racing the same
/// upgrade.
///
/// `BEGIN IMMEDIATE` takes the write lock up front. A plain `BEGIN` is
/// *deferred* — it only acquires the lock at the first write, which lets two
/// processes both read a stale `user_version` and then apply the same DDL
/// twice (the second failing with "table already exists", or worse,
/// succeeding partially). With the lock held we re-read the version: if the
/// peer won the race we commit an empty transaction and move on.
///
/// `PRAGMA user_version` participates in the transaction, so a failure
/// anywhere rolls back both the DDL and the version bump.
fn applyOne(db: *Db, sql: [:0]const u8, comptime target: usize) Db.Error!void {
    if (try userVersion(db) >= target) return; // unlocked pre-check
    try db.exec("BEGIN IMMEDIATE");
    errdefer db.exec("ROLLBACK") catch {};
    if (try userVersion(db) < target) {
        try db.exec(sql);
        try db.exec(std.fmt.comptimePrint("PRAGMA user_version = {d}", .{target}));
    }
    try db.exec("COMMIT");
}

/// Test-only: brings a database to exactly version `n` so the upgrade path
/// from every historical version can be exercised.
pub fn applyUpTo(db: *Db, n: usize) Db.Error!void {
    inline for (migrations, 1..) |sql, target| {
        if (target <= n) try applyOne(db, sql, target);
    }
}

/// Test-only: runs one arbitrary statement through the same transactional
/// wrapper the real migrations use, to prove failures roll back cleanly.
pub fn applyRawForTest(db: *Db, sql: [:0]const u8, comptime target: usize) Db.Error!void {
    return applyOne(db, sql, target);
}

pub fn userVersion(db: *Db) Db.Error!i64 {
    var stmt = try db.prepare("PRAGMA user_version");
    defer stmt.deinit();
    if (!try stmt.step()) return error.Sqlite;
    return stmt.columnInt(0);
}
