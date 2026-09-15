# Preserve cron originals before retention

Profiles that require durable execution originals can set:

```yaml
cron:
  execution_archive: true
```

Other profiles retain their existing retention behavior. Once initialized, the
ledger's archive policy is sticky: deleting or disabling this setting does not
remove the preservation and dispatch checks.

## Storage and ordering

The profile's `cron/executions.db` contains an append-only row-version journal.
SQLite triggers capture the full execution and incident row, SQL table definition,
column metadata, and SQLite schema user version in the transaction that changes
the row. Execution versions retain their job ID, run ID, scheduled occurrence,
owner process identity, status, timestamps, and errors. Before dispatch, the real
store-claimed job definition is bound as another immutable original, including its
registration fields, script, workdir, schedule, and fire claim.

Committed versions are published as private, content-addressed JSON files in
`cron/execution-archive/`. Each receipt includes its stream and event IDs, previous
event ID, exact row digest, and original schema and row. Publication uses a private
staging file, file fsync, atomic no-overwrite linking, directory fsync, and byte
read-back. SQLite receipt commits follow publication. Crash recovery deduplicates
an identical receipt and never overwrites a different original. Staging files are
removed only under the archive lock; originals have no automatic expiration.

The actual terminal outcome commits first. Pruning then runs separately under a
SQLite write fence, verifies the archive and the exact candidate version, and
retains the newest 1,000 terminal rows in the hot execution table. Archive failure
leaves terminal state truthful and hot rows intact. The next claim/start/adoption/
handoff must pass archive verification before dispatch. A failure propagates with
a generic error; raw rows and secrets are never included in new error logs.

## Stopped initialization

Use a reviewed runtime and an explicit profile home. The profile's cron directory
must be owned by the runtime user and mode `0700`; the database and existing WAL,
SHM, and journal files must be regular, single-link, owned files with mode `0600`.
Symlink paths, unsafe ownership, and permissive modes are rejected without repair.

```sh
HERMES_HOME=/absolute/path/to/profile /absolute/path/to/python -m cron.execution_archive --initialize
```

Run this from the reviewed Hermes source directory. This command initializes both
production ledger schemas, preserves existing originals, and prints counts and a
receipt-manifest digest. It does not prune rows, recover executions, alter jobs,
invoke an owner, or grant authority. Repeating it is safe. Idle recovery with no
interrupted attempts also does not invoke retention.

Legacy row contents are preserved as observed. Missing historical job definitions
and earlier unrecorded state versions remain unavailable; today's jobs are never
substituted for those originals. Installation cannot recreate already missing data.

## Historical lookup and recovery

`cron.execution_archive.lookup(path, table="executions", record_id=run_id)` returns
verified historical versions and receipts. The same API supports `cron_incidents`
and `execution_archive_jobs`. Every result explicitly says `historical_only=true`
and `confers_authority=false`. Live APIs such as `get_execution` keep returning
`None` for a pruned row; approval, dispatch, and resume do not fall back to archives.

If storage fails, keep the owner stopped, preserve both the journal and archive,
repair storage or permissions, and rerun stopped initialization. Never repair by
deleting receipts, synthesizing rows, or disabling archive policy. Do not roll back
to a runtime that ignores an initialized archive while dispatch is enabled.

Originals may contain private job or execution data. Keep this directory private
and apply the same private backup policy to the ledger and archive. Complete
verification on each dispatch and prune is proportional to retained version
history; do not add a TTL or skip old receipt checks to reduce that cost.
