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
    //
    // That last sentence was wrong, and v12 says why: one token per *machine*
    // makes every session on it the same owner, so "different owner conflicts"
    // could never fire between two agents in one checkout. The table stays —
    // the token is a good audit subject — but nothing decides ownership by it
    // any more. Left as written because migrations are frozen; read it with
    // v12's note.
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
    // v10: whether an attempt claims its scope as a writer.
    //
    // The scope guard blocks a mutation while an overlapping attempt's
    // outcome is unknown. `--read-only` declared "I am not a mutation" — but
    // the flag lived only in memory, so once the attempt was stored the
    // ledger could no longer tell. A read-only exec that then lost its
    // connection blocked every later mutation on that server exactly like a
    // writer: the opposite of what the flag promised, and asymmetric with its
    // own behaviour a minute earlier.
    //
    // Default 1. Every row written before this column existed came from a
    // build with no read-only concept, and reading an unrecorded role as
    // "read-only" would quietly unblock scopes that were being held for a
    // reason.
    \\ALTER TABLE operations ADD COLUMN mutating INTEGER NOT NULL DEFAULT 1;
    ,
    // v11: `transfer_checkpoints` in destination roles instead of push shapes.
    //
    // The v6 table calls the source `local_*` and the staging file
    // `remote_partial_*`. That is true of a push and false of a pull, where
    // the source is remote and the partial is local, and `remote_path NOT
    // NULL` makes a locally-published transfer impossible to even record. So
    // the columns are re-cut by *role*: `dest_side` / `dest_path` for where
    // the artifact is published, `partial_*` for the staging file (always on
    // the destination side), and one exhaustive `source_kind` family for
    // where the bytes came from.
    //
    // Dropped and recreated rather than altered. Every database on the
    // machine was enumerated read-only before this was written: the real
    // store is at v4 and does not have the table, one dev store has it with
    // zero rows, and the only rows anywhere belong to this repo's own test
    // scratch. Nothing is being discarded — but this is drop DDL, so it was
    // established rather than assumed.
    //
    // Two constraints carry weight that code cannot:
    //
    // * `UNIQUE(request_id)`. A request with two checkpoints has two declared
    //   digests, and settling it from a published-file hash would then have
    //   to pick one — turning insertion order into a scope-releasing
    //   decision. `receipts.resolve` refuses that case; this makes it
    //   unreachable.
    // * the partial unique index over the *destination-holding* states. It is
    //   the only guard a locally-published transfer gets: `unsettledInScope`
    //   filters by `server_id`, so two pulls from different servers into one
    //   local path both clear the scope guard, and a fetch has no server at
    //   all. A state holds the destination for as long as an operator has not
    //   said what to do about it, which is every state except the two in which
    //   the path stopped being a claim and became the artifact — `published`
    //   and `completed_unverified`. That covers verifying and publishing, it
    //   covers `indeterminate_publish` (the rename may already have landed, so
    //   the path holds a result awaiting adjudication), and it covers every
    //   `failed_*` state, whose partial stays on disk until something
    //   explicitly supersedes it. See `transfers.State.holdsDestination`, from
    //   which this list is copied and against which a gate compares it.
    \\DROP INDEX IF EXISTS idx_checkpoints_request;
    \\DROP INDEX IF EXISTS idx_checkpoints_resume;
    \\DROP TABLE IF EXISTS transfer_checkpoints;
    \\CREATE TABLE transfer_checkpoints (
    \\  id                INTEGER PRIMARY KEY,
    \\  request_id        TEXT NOT NULL UNIQUE REFERENCES operations(request_id) ON DELETE CASCADE,
    \\  schema_version    INTEGER NOT NULL,
    \\  direction         TEXT NOT NULL CHECK (direction IN ('push','pull','fetch')),
    \\
    \\  dest_side         TEXT NOT NULL CHECK (dest_side = 'local' OR dest_side LIKE 'server:%'),
    \\  dest_path         TEXT NOT NULL,
    \\  partial_path      TEXT NOT NULL,
    \\  partial_len       INTEGER NOT NULL DEFAULT 0,
    \\  partial_sha256    TEXT,
    \\
    \\  source_kind       TEXT NOT NULL CHECK (source_kind IN ('local_file','remote_file','http')),
    \\  source_path       TEXT,
    \\  source_size       INTEGER,
    \\  source_mtime_ns   INTEGER,
    \\  source_sha256     TEXT,
    \\  source_url        TEXT,
    \\  source_etag       TEXT,
    \\  source_last_modified TEXT,
    \\
    \\  chunk_size        INTEGER NOT NULL,
    \\  confirmed_offset  INTEGER NOT NULL DEFAULT 0,
    \\  total_bytes       INTEGER,
    \\  expected_sha256   TEXT,
    \\  verified_sha256   TEXT,
    \\  no_clobber        INTEGER NOT NULL DEFAULT 0 CHECK (no_clobber IN (0,1)),
    \\  state             TEXT NOT NULL,
    \\  failure_reason    TEXT,
    \\  created_at        INTEGER NOT NULL,
    \\  updated_at        INTEGER NOT NULL,
    \\
    \\  -- A file source is identified by path; an http source by url. Neither
    \\  -- may borrow the other's columns, because `verifyResume` switches on
    \\  -- `source_kind` and a row that carries the wrong family would take a
    \\  -- branch that then reads nulls.
    \\  CHECK (
    \\    (source_kind IN ('local_file','remote_file')
    \\       AND source_path IS NOT NULL AND source_url IS NULL)
    \\    OR
    \\    (source_kind = 'http'
    \\       AND source_url IS NOT NULL AND source_path IS NULL)
    \\  ),
    \\  -- The confirmed offset is a claim about bytes we can still prove are
    \\  -- ours, and the proof is the prefix hash. Zero needs none: there is
    \\  -- nothing to prove.
    \\  CHECK (confirmed_offset = 0 OR partial_sha256 IS NOT NULL),
    \\  CHECK (confirmed_offset >= 0 AND partial_len >= 0),
    \\  -- A non-zero offset is only worth keeping if the resume it licenses can
    \\  -- be proven safe, and that proof is `verifyResume`'s source comparison:
    \\  -- a content hash for a file, a strong validator for an HTTP object. A
    \\  -- source known only by its path (or by size and mtime, which a rewrite
    \\  -- can reproduce) gives that comparison nothing to fail on, so bytes
    \\  -- appended to the partial would be spliced onto a head nobody can
    \\  -- attribute. Named, because the drift probe looks for it by name.
    \\  CONSTRAINT offset_needs_source_identity CHECK (
    \\    confirmed_offset = 0
    \\    OR (source_kind IN ('local_file','remote_file') AND source_sha256 IS NOT NULL)
    \\    OR (source_kind = 'http' AND (source_etag IS NOT NULL OR source_last_modified IS NOT NULL))
    \\  )
    \\);
    \\CREATE UNIQUE INDEX idx_checkpoints_live_dest
    \\  ON transfer_checkpoints(dest_side, dest_path)
    \\  WHERE state IN ('planned','probing','transferring','paused',
    \\                  'verifying','publishing',
    \\                  'failed_source_changed','failed_remote_partial_mismatch',
    \\                  'failed_hash_mismatch','failed_no_space',
    \\                  'failed_clobber_conflict','failed_publish',
    \\                  'indeterminate_publish');
    ,
    // v12: a lease is held by an attempt, not by a machine.
    //
    // v7's `owner_token` came from `policy.ownerToken`, which mints one token
    // per machine profile and reuses it forever — and `leases.acquire` reads
    // its own owner's overlap as a *renewal*. So every agent, editor and
    // terminal on one machine was one lease owner: two concurrent sessions
    // never conflicted, they renewed each other's claim, and the layer that
    // exists to isolate peers isolated nothing.
    //
    // The owner is now `owner_request_id`, the id of the attempt holding the
    // lease. The profile token stays and is still written on every row, as
    // `profile_token`, purely as the audit subject — who the machine was. It
    // decides nothing, and no query compares it.
    //
    // Three shapes are deliberate:
    //
    // * No foreign key on `owner_request_id`. Not every holder is a ledger
    //   operation: `job kill` and `job rm` are supervisory acts on somebody
    //   *else's* attempt, so they mint an id from the same generator and have
    //   no `operations` row of their own. A foreign key would force either a
    //   fake operation row or a nullable owner, and a nullable owner is the
    //   defect this version removes.
    // * `CHECK (owner_request_id <> '')`. An empty owner would match every
    //   other empty owner and renew it — v7's defect written in one character
    //   instead of one column.
    // * v7's separate nullable `request_id` column is gone. The owner *is* the
    //   request id now, and two columns both meaning "the request" is how they
    //   come to disagree.
    //
    // Dropped and recreated rather than altered, and the rows are not carried.
    // An old `owner_token` is a machine profile, not a request id, and reading
    // one as the other would hand every pre-v12 row an owner that never
    // existed. Released rows are history and go with the table; a row that is
    // still *unreleased* is a live claim that cannot be re-owned at all, so
    // `checkBeforeApply` refuses the open before this runs rather than voiding
    // it — see `Refusal.live_leases_cannot_be_reowned`. Nothing in any shipped
    // path has ever written this table: `acquire` and `takeover` have no
    // non-test caller in the tree this replaces, so on a real store both counts
    // are zero.
    \\DROP INDEX IF EXISTS idx_leases_active;
    \\DROP INDEX IF EXISTS idx_leases_owner;
    \\DROP TABLE IF EXISTS leases;
    \\CREATE TABLE leases (
    \\  id               INTEGER PRIMARY KEY,
    \\  server_id        INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    \\  scope_kind       TEXT NOT NULL CHECK (scope_kind IN ('server','job','path')),
    \\  scope_key        TEXT NOT NULL,
    \\  -- Identity. The only column a conflict is decided by.
    \\  owner_request_id TEXT NOT NULL CHECK (owner_request_id <> ''),
    \\  -- Audit subject: which machine profile the holder ran as. Never compared.
    \\  profile_token    TEXT NOT NULL,
    \\  owner_label      TEXT,
    \\  note             TEXT,
    \\  acquired_at      INTEGER NOT NULL,
    \\  renewed_at       INTEGER NOT NULL,
    \\  expires_at       INTEGER NOT NULL,
    \\  released_at      INTEGER,
    \\  release_reason   TEXT CHECK (release_reason IS NULL OR release_reason IN (
    \\                     'released','expired','takeover','force')),
    \\  superseded_by    INTEGER REFERENCES leases(id)
    \\);
    \\CREATE UNIQUE INDEX idx_leases_active
    \\  ON leases(server_id, scope_kind, scope_key) WHERE released_at IS NULL;
    \\CREATE INDEX idx_leases_owner ON leases(owner_request_id) WHERE released_at IS NULL;
    ,
    // v13: when a memory's fact was observed, and whether its verify command
    // may be run.
    //
    // Two additions, one version, because they are one row's answer to "how much
    // is this note worth right now".
    //
    // **`observed_at` is not `updated_at`.** The table carried write times and
    // nothing else, so "the API listens on 8080" written six months ago and the
    // same sentence written this morning were the same row to every reader.
    // `cmd_handoff.readMemories` had to say so in prose — it reports the newest
    // `updated_at` and its header warns that this must not be read as a
    // verification — because the column that would have made the claim true did
    // not exist. `observed_at` is when the *fact* was seen, and
    // `observed_source` says how it came to be known, drawn from
    // `receipts.Source`'s existing vocabulary rather than a second one invented
    // beside it. `memories.observed_sources` is the subset a memory row can
    // carry and a gate holds the CHECK below against it.
    //
    // Nullable, because a store that does not know when a fact was observed has
    // to be able to say so. `updated_at` is NOT NULL and always has been; making
    // `observed_at` NOT NULL DEFAULT 0 would give every row that nobody has
    // observed a number, and a number is what a reader believes.
    //
    // **The backfill is labelled.** Existing rows get `observed_at =
    // updated_at`, which is a write time standing in for an observation, and
    // `observed_source` defaults to `backfill` so the row says that about itself.
    // The default is also the safe direction for any later writer that forgets
    // the column: an unlabelled row under-claims instead of claiming a reading it
    // never took.
    //
    // **`verify_cmd` is text, and text is not a permission.** A verify command
    // is an arbitrary line that runs on a host, and memories arrive by `terminus
    // import` from documents anybody can hand over. So a command is inert until
    // somebody grants it, and the grant is three columns because "why did this
    // run" takes all three: when (`trusted_at`), who (`trusted_by`), and what
    // was actually authorised (`trusted_cmd_sha256`).
    //
    // The third is the load-bearing one. A grant recorded as a flag keeps
    // applying after the text changes under it: trust `systemctl is-active
    // nginx`, then `memory add --key svc --verify-cmd 'curl … | sh'`, and the
    // flag is still set. Binding the grant to the digest of the text it was given
    // makes that unreachable without any writer having to remember to revoke — a
    // command that is not the command that was trusted simply has no grant.
    // `memories.trustState` is that comparison and nothing else decides it.
    //
    // `grant_is_whole` is named because half a grant is the shape that reads as
    // authorised while answering none of the three questions, and because the
    // drift probe looks for the version by name elsewhere. Every predicate in it
    // is `IS NULL` / `IS NOT NULL` before it is anything else: a CHECK whose
    // expression evaluates to NULL *passes*, so a bare `trusted_by <> ''` would
    // have admitted the all-but-one-column row it exists to refuse. Refused by
    // the database, where no caller can talk it round — v12's
    // `owner_request_id <> ''` for the same reason.
    //
    // **No trust column is reachable from an insert.** `memories.AddOptions` has
    // no field for one and `cmd_export_import.MemoryDoc` has no key for one, so
    // the only way into these three columns is `memories.grantTrust`, which
    // `memory trust` is the only caller of. That is the security boundary; the
    // CHECK is the second line behind it.
    //
    // ALTER rather than a re-cut, and this is the one table where that is not a
    // preference. v11 and v12 dropped and recreated tables that were provably
    // empty in the wild; `memories` is the opposite — it is the table the real
    // store at v4 has rows in, and those rows are the accumulated knowledge the
    // product exists to keep. Adding columns cannot lose them, so nothing here
    // needs a refusal like `checkpoints_would_be_dropped`.
    \\ALTER TABLE memories ADD COLUMN observed_at INTEGER;
    \\ALTER TABLE memories ADD COLUMN observed_source TEXT NOT NULL DEFAULT 'backfill'
    \\  CHECK (observed_source IN ('live','cache','legacy_import','backfill'));
    \\ALTER TABLE memories ADD COLUMN verify_cmd TEXT;
    \\ALTER TABLE memories ADD COLUMN trusted_at INTEGER;
    \\ALTER TABLE memories ADD COLUMN trusted_by TEXT;
    \\ALTER TABLE memories ADD COLUMN trusted_cmd_sha256 TEXT
    \\  CONSTRAINT grant_is_whole CHECK (
    \\    (trusted_at IS NULL AND trusted_by IS NULL AND trusted_cmd_sha256 IS NULL)
    \\    OR (trusted_at IS NOT NULL
    \\        AND trusted_by IS NOT NULL AND trusted_by <> ''
    \\        AND trusted_cmd_sha256 IS NOT NULL AND length(trusted_cmd_sha256) = 64)
    \\  );
    \\UPDATE memories SET observed_at = updated_at WHERE observed_at IS NULL;
    ,
};

/// Number of schema versions this binary knows about.
pub const latest_version = migrations.len;

/// The version at which `transfer_checkpoints` was dropped and recreated.
///
/// Named because two rules key on it — the drift probes for the re-cut table,
/// and the refusal to destroy checkpoint rows written before it — and because
/// it is a number in the frozen migration list rather than "the latest": it
/// must not follow `latest_version` upwards.
const checkpoints_recut_version = 11;

/// The version at which `leases` was dropped and recreated around
/// `owner_request_id`.
///
/// Named for the same two reasons as `checkpoints_recut_version`: the drift
/// probes and the refusal to void a live claim both key on it, and it is a
/// frozen number rather than "the latest".
const leases_reowned_version = 12;

/// The version at which `memories` gained the observation and trust columns.
///
/// Named for the same reason as the two above: the drift probe keys on it, and it
/// is a frozen number rather than "the latest".
const memories_observed_version = 13;

/// The verbatim text of one frozen statement, sliced out of its migration.
///
/// sqlite stores a `CREATE` statement in `sqlite_master.sql` exactly as it was
/// submitted — whitespace, line breaks and comments included — minus the
/// terminating semicolon. So the text this binary would write is directly
/// comparable to the text a database was actually built from, and that
/// comparison is total: it needs no needle per amendment, and it cannot be
/// satisfied by a statement that merely *contains* the right words.
///
/// Statements are terminated by `;` at the end of a line, and nothing in
/// `migrations` contains that inside a statement body. The gate that compares
/// each extracted statement against what sqlite stored is what enforces that: a
/// future statement with an embedded `;\n` would be truncated here and the
/// comparison would fail loudly at test time rather than silently probing a
/// prefix.
fn frozenStatement(comptime version: usize, comptime starts_with: []const u8) []const u8 {
    comptime {
        // The v11 text is several thousand characters and both searches walk it
        // one byte at a time.
        @setEvalBranchQuota(100_000);
        const text = migrations[version - 1];
        const start = std.mem.indexOf(u8, text, starts_with) orelse
            @compileError("no frozen statement starts with: " ++ starts_with);
        const rest = text[start..];
        // The last statement of a migration has no trailing newline — a Zig
        // multiline literal does not add one after its final line — so the
        // terminator is `;\n` or the `;` the text ends on.
        const end = std.mem.indexOf(u8, rest, ";\n") orelse
            if (std.mem.endsWith(u8, rest, ";")) rest.len - 1 else @compileError(
                "frozen statement is not terminated by a semicolon: " ++ starts_with,
            );
        return rest[0..end];
    }
}

/// The two v11 objects an in-place amendment can change without moving
/// `user_version`, as this binary writes them.
///
/// Both are exposed so the gate that holds the index predicate against
/// `transfers.State.holdsDestination` reads the same text the runtime probe
/// does, instead of a second transcription of it.
pub const checkpoints_table_ddl = frozenStatement(
    checkpoints_recut_version,
    "CREATE TABLE transfer_checkpoints (",
);
pub const checkpoints_index_ddl = frozenStatement(
    checkpoints_recut_version,
    "CREATE UNIQUE INDEX idx_checkpoints_live_dest",
);

/// The three v12 objects, as this binary writes them. Exposed for the same
/// reason as the v11 pair: the gate that holds a fresh store against this text
/// reads the same slices the runtime probe does.
pub const leases_table_ddl = frozenStatement(
    leases_reowned_version,
    "CREATE TABLE leases (",
);
pub const leases_active_index_ddl = frozenStatement(
    leases_reowned_version,
    "CREATE UNIQUE INDEX idx_leases_active",
);
pub const leases_owner_index_ddl = frozenStatement(
    leases_reowned_version,
    "CREATE INDEX idx_leases_owner",
);

/// What a pre-write refusal knows, for a caller that can word a message.
///
/// Zig error values carry no payload, and the numbers here are the whole
/// difference between "this database cannot be opened" and an operator knowing
/// what to do next. `checkBeforeApply` fills one when it is given somewhere to
/// put it, and **every** error it returns writes one first — `cli.openStore`
/// reads the variant its error names without re-checking the tag.
pub const Refusal = union(enum) {
    /// The file was written by a newer binary. `found` is its `user_version`,
    /// `known` is the highest this binary can produce.
    future_version: struct { found: i64, known: i64 },
    /// The file's contents do not match the version it claims, so it is not a
    /// Terminus store — or not the one it says it is. `detail` is a static
    /// string naming what was expected and missing, because "this is not our
    /// database" and "our database is damaged" send an operator to different
    /// places and only the payload can tell them apart.
    foreign_database: struct { version: i64, detail: []const u8 },
    /// A probe of the stored DDL failed. `probe` names which object did not
    /// match, as a static string, so a report can say what drifted rather than
    /// only that something did.
    pre_release_drift: struct { probe: []const u8 },
    /// The store predates the re-cut `transfer_checkpoints` and still holds
    /// rows there. Migrating would destroy `rows` resumable transfers.
    ///
    /// The operator's options, none of which this code will take on its own:
    /// finish or abandon those transfers with the binary that wrote them; or
    /// move this database aside and let a fresh one be created; or keep it and
    /// point `--db` elsewhere. A future build may carry the rows across — this
    /// one refuses rather than guessing that they are disposable.
    checkpoints_would_be_dropped: struct { rows: i64, version: i64 },
    /// The store predates the re-owned `leases` and still holds claims nobody
    /// has released. v12 decides conflicts by `owner_request_id`; a pre-v12 row
    /// names a *machine profile*, which is not a request id and must never be
    /// read as one, so those `rows` cannot be carried and cannot be re-owned.
    ///
    /// Refused rather than voided, because a live lease is somebody's claim on
    /// a scope right now: dropping it silently un-blocks whatever it was
    /// holding, which is the one thing the table exists to prevent. The
    /// operator's options: release them with the binary that took them, or move
    /// this database aside. Released rows are history, are not counted here, and
    /// go with the table — their owner column was never a request id either.
    live_leases_cannot_be_reowned: struct { rows: i64, version: i64 },
};

pub const PreApplyError = Db.Error || error{
    /// `user_version` is higher than anything this binary can produce, so the
    /// schema in front of it is one it does not understand. Every statement in
    /// this program is written against a known version; running them against a
    /// later one is not a read-only mistake, because the writes would land.
    SchemaNewerThanBinary,
    /// See `Refusal.foreign_database`.
    NotATerminusStore,
    /// See `checkPreReleaseDrift`.
    PreReleaseSchemaDrift,
    /// See `Refusal.checkpoints_would_be_dropped`.
    CheckpointsWouldBeDropped,
    /// See `Refusal.live_leases_cannot_be_reowned`.
    LiveLeasesCannotBeReowned,
};

/// Everything that must be true of a database *as found*, before any DDL runs.
///
/// The order is the point, and it is two orders at once.
///
/// Against `apply`: this used to run after it. v11 drops and recreates
/// `transfer_checkpoints`, so on a v6–v10 store holding real rows `apply`
/// destroyed them and the check that exists to stop exactly that then ran on
/// the wreckage. A gate that reports damage it could have prevented is not a
/// gate.
///
/// Within itself: the version is read before any table is, because what shape a
/// table has — indeed whether it exists — is a function of the version, so a
/// probe run against an unknown-version file is reading columns whose meaning
/// it cannot vouch for.
///
/// Every branch here refuses. None of them deletes, repairs, or migrates
/// anything: returning an error from `open` is the whole action, because a
/// caller asked for a database and did not ask for its history to be rewritten.
///
/// The whole gate runs inside one read transaction, and that is not tidiness.
/// The version and the contents are two reads, and `applyOne` moves both in one
/// `BEGIN IMMEDIATE`, so a peer performing the very first migration under us
/// would otherwise be caught halfway: version 0 read before its commit, tables
/// counted after it, and a brand new store refused as a foreign database on a
/// machine that merely started two commands at once. One snapshot makes the
/// pair atomic — a reader sees the file either before that migration or after
/// it, which are the only two states it is ever actually in.
pub fn checkBeforeApply(db: *Db, refusal: ?*Refusal) PreApplyError!void {
    try db.exec("BEGIN");
    errdefer db.exec("ROLLBACK") catch {};
    try checkBeforeApplyLocked(db, refusal);
    try db.exec("COMMIT");
}

fn checkBeforeApplyLocked(db: *Db, refusal: ?*Refusal) PreApplyError!void {
    const found = try userVersion(db);

    // (a) A file from a newer binary. Opening it silently — which is what
    //     happened until now — means running this binary's statements against
    //     columns, constraints and indexes it has never heard of, and the
    //     writes are not hypothetical: `apply`'s fast path returns immediately
    //     at a version above its own, so every command after it proceeds as if
    //     the schema were understood.
    if (found > latest_version) {
        if (refusal) |out| out.* = .{ .future_version = .{
            .found = found,
            .known = latest_version,
        } };
        return error.SchemaNewerThanBinary;
    }

    // (b) A file that is not ours at all.
    try checkContentsMatchVersion(db, found, refusal);

    // (c) The historical shape, at whatever version this file actually claims.
    try checkPreReleaseDrift(db, refusal);

    // (d) Checkpoint rows that v11 would destroy.
    if (found < checkpoints_recut_version and try tableExists(db, "transfer_checkpoints")) {
        const rows = try countCheckpoints(db);
        if (rows > 0) {
            if (refusal) |out| out.* = .{ .checkpoints_would_be_dropped = .{
                .rows = rows,
                .version = found,
            } };
            return error.CheckpointsWouldBeDropped;
        }
    }

    // (e) Live lease claims that v12 cannot re-own.
    //
    // Unreleased rows only. A released one is history whose owner column was a
    // machine profile either way, and refusing an open over a row that is
    // already over would be a trap rather than a barrier — nothing would ever
    // clear it, because expiry itself is lazy and needs the store open.
    if (found < leases_reowned_version and try tableExists(db, "leases")) {
        const rows = try countLiveLeases(db);
        if (rows > 0) {
            if (refusal) |out| out.* = .{ .live_leases_cannot_be_reowned = .{
                .rows = rows,
                .version = found,
            } };
            return error.LiveLeasesCannotBeReowned;
        }
    }
}

/// Whether the file's contents are consistent with the version it reports.
///
/// The gate had an upper bound on `user_version` and no lower one, and
/// `user_version` defaults to 0 — which is what essentially every SQLite file
/// in the world reports. So `--db ~/some-other-app.db` ran the whole ladder
/// into a stranger's database: nineteen tables grafted in and its
/// `user_version` overwritten with 11, destroying the schema version of any
/// application that uses that field the idiomatic way. At version 4 it was
/// worse in a quieter way — `applyOne` skips v1–v4, so the `CREATE TABLE keys`
/// collision that would have refused never happens, twelve tables land, v9's
/// `ALTER TABLE jobs` fails, and the caller is told only "cannot open
/// database" while the file has already been written to.
///
/// Two directions, because both are lies about the same file:
///
///  * version 0 with objects of its own. A brand new store is version 0 *and*
///    empty; anything else claiming 0 is either a foreign database or one of
///    ours whose header was zeroed, and neither is safe to run DDL into.
///  * a version whose defining tables are absent. `keys` is created by v1 and
///    `operations` by v5, and no migration drops either, so a file claiming to
///    be at or past those versions must have them.
///
/// Deliberately not a full inventory. The question here is ownership — is this
/// our database — and the shape *within* a version is `checkPreReleaseDrift`'s,
/// which runs next.
fn checkContentsMatchVersion(db: *Db, found: i64, refusal: ?*Refusal) PreApplyError!void {
    const detail: []const u8 = blk: {
        if (found == 0) {
            if (try userObjectCount(db) > 0)
                break :blk "the file reports user_version 0 but already contains objects of its own";
            return;
        }
        if (!try tableExists(db, "keys"))
            break :blk "no `keys` table, which every version from 1 onwards has";
        if (found >= 5 and !try tableExists(db, "operations"))
            break :blk "no `operations` table, which every version from 5 onwards has";
        return;
    };
    if (refusal) |out| out.* = .{ .foreign_database = .{ .version = found, .detail = detail } };
    return error.NotATerminusStore;
}

/// How many objects the file holds that are not sqlite's own bookkeeping.
///
/// `ESCAPE` because `_` is a LIKE wildcard: a bare `'sqlite_%'` also matches a
/// table called `sqliteXfoo`, so a foreign database could hide a table from
/// this count by naming it that way. The same wildcard is why the drift probes
/// below compare whole statements rather than LIKE-matching needles.
fn userObjectCount(db: *Db) Db.Error!i64 {
    var stmt = try db.prepare(
        "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
    );
    defer stmt.deinit();
    if (!try stmt.step()) return error.Sqlite;
    return stmt.columnInt(0);
}

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
/// were added afterwards — or carrying an earlier revision's index predicate
/// or constraint set — and the failures that follow are confusing SQL errors
/// far from the cause. Detecting it here turns that into one clear message,
/// and the only thing it does about it is refuse to open: repairing a schema
/// under a caller who asked for a database, not a migration, would be a
/// silent rewrite of state nobody agreed to. Costs one query per probe on
/// databases at v5 or above.
///
/// Runs *before* `apply`, so what it inspects is the version the file claims
/// for itself. A store below 11 skips the v11 probes and that is correct rather
/// than vacuous: those objects do not exist in their v11 form yet, and `apply`
/// is about to write them from this binary's own frozen text. What it no longer
/// covers is the shape `apply` produces — that was never a property of somebody
/// else's database, and it is asserted where it belongs, in the gate that opens
/// a fresh store and runs these probes against the result.
pub fn checkPreReleaseDrift(db: *Db, refusal: ?*Refusal) (Db.Error || error{PreReleaseSchemaDrift})!void {
    const version = try userVersion(db);
    if (version < 5) return;
    if (!try hasColumn(db, "operation_events", "last_observed"))
        return drifted(refusal, "operation_events.last_observed");
    if (version < checkpoints_recut_version) return;
    // Column names are not the whole shape, and needles are not either. v11 has
    // been amended three times since the first v11 databases existed: the
    // destination-holding index gained states in its predicate twice, and the
    // table gained a named CHECK. None of that is visible to
    // `pragma_table_info`, and `user_version` cannot express a change *within* a
    // version, so the stored DDL text is the only witness.
    //
    // It used to be read with three `LIKE '%needle%'` probes, and that was a
    // gate that opened for the shape it was written to catch. A predicate
    // missing `paused`, `failed_no_space`, `failed_clobber_conflict` and
    // `failed_publish` still contains the words `verifying` and
    // `failed_hash_mismatch`, so all three needles passed — and on that database
    // a checkpoint parked in `paused` is not in the unique index at all, which
    // is the *only* collision guard a locally-published transfer has
    // (`transfers.create` has no pre-insert check; `find_live_dest_sql` runs
    // after sqlite has already refused). Two drivers, one partial, one path.
    // The constraint probe was weaker still: it matched the CHECK's *name*
    // while the property lives in its body, so an intermediate revision with
    // the right name and a wrong expression passed.
    //
    // Whole-statement equality against the text this binary would write says
    // all of it at once, needs no needle per amendment, and cannot be satisfied
    // by an object that merely mentions the right words. sqlite stores the
    // statement verbatim, so the comparison is exact rather than approximate —
    // including the comments, which are part of what a reviewer of a drifted
    // database wants to see differ.
    if (!try schemaTextEquals(db, "transfer_checkpoints", checkpoints_table_ddl))
        return drifted(refusal, "transfer_checkpoints");
    if (!try schemaTextEquals(db, "idx_checkpoints_live_dest", checkpoints_index_ddl))
        return drifted(refusal, "idx_checkpoints_live_dest");
    if (version < leases_reowned_version) return;
    // Same reasoning one version on, and the property is narrower and easier to
    // lose: what makes v12 a fix rather than a rename is that the owner column
    // is `owner_request_id`, that it cannot be empty, and that the active index
    // and the owner index are over it. A store built by an intermediate
    // revision — the column added beside `owner_token` instead of replacing it,
    // or the CHECK missing — reads as v12 and decides conflicts by whatever it
    // has. Whole-statement equality is the only witness that separates them.
    if (!try schemaTextEquals(db, "leases", leases_table_ddl))
        return drifted(refusal, "leases");
    if (!try schemaTextEquals(db, "idx_leases_active", leases_active_index_ddl))
        return drifted(refusal, "idx_leases_active");
    if (!try schemaTextEquals(db, "idx_leases_owner", leases_owner_index_ddl))
        return drifted(refusal, "idx_leases_owner");
    if (version < memories_observed_version) return;
    // v13 adds columns to `memories` with `ALTER TABLE`, and that is why this
    // probe is column presence rather than the whole-statement equality the two
    // versions above use.
    //
    // The equality probes work because sqlite stores a `CREATE` statement exactly
    // as it was submitted, so the text this binary would write and the text the
    // database was built from are the same bytes by construction. An `ALTER TABLE
    // ADD COLUMN` has no such guarantee: sqlite *rewrites* the stored `CREATE
    // TABLE` by splicing the new column definition in before the closing paren,
    // and this binary would have to reproduce that splice to compare against it.
    // Reproducing a transformation somebody else performs is the one shape a
    // frozen-text probe must not take — the day a library upgrade changed the
    // splice by one character, every v13 store on the machine would refuse to
    // open, and the version's own guard would be the thing that bricked it.
    //
    // So the realistic pre-release shape is probed instead, which for an
    // ALTER-only migration is a missing column: an intermediate revision of v13
    // that added `observed_at` and not `observed_source`, or the two observation
    // columns and not the grant, reports `user_version` 13 and then fails much
    // later with a confusing SQL error. One column is named per half of the
    // version, and each is the *last* column its half adds, so a half applied
    // partway is caught rather than only a half omitted entirely.
    //
    // What this does not see is a v13 whose columns are all present and whose
    // CHECKs are not. That is defence in depth rather than the boundary:
    // `memories.trustState` reads the grant digest and compares it in Zig, so a
    // store missing `grant_is_whole` still cannot make a partial grant
    // executable — it can only store one. The gate that holds the CHECK text
    // against `memories.observed_sources` runs against a store this binary built,
    // which is where that agreement can be asserted honestly.
    if (!try hasColumn(db, "memories", "observed_source"))
        return drifted(refusal, "memories.observed_source");
    if (!try hasColumn(db, "memories", "trusted_cmd_sha256"))
        return drifted(refusal, "memories.trusted_cmd_sha256");
}

fn drifted(refusal: ?*Refusal, probe: []const u8) error{PreReleaseSchemaDrift} {
    if (refusal) |out| out.* = .{ .pre_release_drift = .{ .probe = probe } };
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

/// Whether a table of this name exists.
///
/// Asked before counting rows in it, because `prepare` on a missing table is a
/// bare `error.Sqlite` — indistinguishable from a real failure, and "the table
/// is not there" is an ordinary answer for a store below the version that
/// introduced it.
fn tableExists(db: *Db, name: [:0]const u8) Db.Error!bool {
    var stmt = try db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, name);
    return try stmt.step();
}

/// How many rows the pre-v11 `transfer_checkpoints` holds.
///
/// A full count rather than a `LIMIT 1` existence probe: the number is the
/// difference between a refusal an operator can act on and one they can only
/// obey. Only reached on a store below v11, where the table is small by
/// construction — nothing has ever shipped that writes it.
fn countCheckpoints(db: *Db) Db.Error!i64 {
    var stmt = try db.prepare("SELECT COUNT(*) FROM transfer_checkpoints");
    defer stmt.deinit();
    if (!try stmt.step()) return error.Sqlite;
    return stmt.columnInt(0);
}

/// How many leases the pre-v12 table still holds unreleased.
///
/// `released_at IS NULL` and not "unexpired": expiry in this schema is lazy, so
/// a lapsed row stays unreleased until some command sweeps it, and this gate
/// runs before any command can. Counting only what is genuinely still claimed
/// would therefore need a clock the open path does not have — and over-refusing
/// on a lapsed row is the safe direction, because the refusal names the number
/// and leaves the file untouched.
fn countLiveLeases(db: *Db) Db.Error!i64 {
    var stmt = try db.prepare("SELECT COUNT(*) FROM leases WHERE released_at IS NULL");
    defer stmt.deinit();
    if (!try stmt.step()) return error.Sqlite;
    return stmt.columnInt(0);
}

/// Whether the DDL sqlite stored for `name` is exactly the text this binary
/// would have written.
///
/// `sqlite_master.sql` holds the `CREATE` statement as submitted — whitespace,
/// line breaks and comments included — minus the terminating semicolon, so the
/// comparison against `frozenStatement`'s slice is byte-for-byte. A missing
/// object yields no row, which is a drift too.
///
/// Equality rather than containment on purpose. `LIKE '%needle%'` was what this
/// replaced, and it had two independent weaknesses: `_` is a LIKE wildcard, so
/// every needle was quietly a pattern, and a needle can only ever assert that
/// something is *present* — never that a predicate has not lost four of its
/// states, which is exactly how the index drifted.
fn schemaTextEquals(db: *Db, name: [:0]const u8, want: []const u8) Db.Error!bool {
    var stmt = try db.prepare("SELECT sql FROM sqlite_master WHERE name = ?1");
    defer stmt.deinit();
    try stmt.bindText(1, name);
    if (!try stmt.step()) return false;
    return std.mem.eql(u8, stmt.columnText(0), want);
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
