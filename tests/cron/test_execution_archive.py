"""Lossless retention and fail-closed dispatch using real private SQLite/filesystem stores."""

import errno
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor

import pytest

from cron import execution_archive as archive
from cron import executions, incidents


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    home = tmp_path / "profile"
    home.mkdir(mode=0o700)
    (home / "config.yaml").write_text("cron:\n  execution_archive: true\n")
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(executions, "EXECUTIONS_FILE", home / "cron" / "executions.db")
    monkeypatch.setattr(incidents, "EXECUTIONS_FILE", None)
    return home, executions.EXECUTIONS_FILE


def _rows(path, table="executions"):
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]


def _claim(job_id="job"):
    record = executions.create_execution(job_id, source="mock-owner", scheduled_instant="2026-09-15T01:00:00Z")
    job = {"id": job_id, "name": "isolated job", "created_at": "2026-09-14T00:00:00Z",
           "script": "scripts/no-order.sh", "no_agent": True, "workdir": "/isolated",
           "schedule": {"kind": "cron", "expr": "0 10 * * 1-5"},
           "fire_claim": {"by": "mock-owner", "at": "2026-09-15T01:00:00Z"}}
    executions.bind_execution_job(record["id"], job)
    return record, job


def _seed(count):
    template = executions.create_execution("legacy", source="mock-owner")
    with executions._transaction() as conn:
        conn.execute("UPDATE executions SET status='failed', finished_at='2026-09-14T00:00:00Z' WHERE id=?",
                     (template["id"],))
        fields = list(template)
        sql = f"INSERT INTO executions({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})"
        for index in range(count - 1):
            row = {**template, "id": f"legacy-{index:06d}",
                   "status": ("completed", "failed", "unknown")[index % 3],
                   "finished_at": "2026-09-14T00:00:00Z", "error": f"historical state {index}"}
            conn.execute(sql, [row[key] for key in fields])
    return template["id"]


@pytest.mark.parametrize("count", [998, 999, 1000])
def test_retention_preserves_every_original_at_999_1000_1001(ledger, count):
    _, path = ledger
    _seed(count)
    originals = _rows(path)
    claimed, _ = _claim("new")
    finished = executions.finish_execution(claimed["id"], success=True)
    assert len(_rows(path)) == min(count + 1, 1000)
    for original in [*originals, finished]:
        history = archive.lookup(path, table="executions", record_id=original["id"])
        assert history[-1]["original"]["row"] == original
        assert history[-1]["row_digest"] == hashlib.sha256(archive._canonical(original)).hexdigest()
        assert history[-1]["confers_authority"] is False
    # Historical visibility does not restore the live owner record used for authority.
    hot = {row["id"] for row in _rows(path)}
    for original in originals:
        if original["id"] not in hot:
            assert executions.get_execution(original["id"]) is None


def test_versions_jobs_incidents_and_sticky_optin_are_immutable(ledger):
    home, path = ledger
    claimed, job = _claim()
    executions.mark_execution_running(claimed["id"])
    executions.finish_execution(claimed["id"], success=False, error="mock failure")
    identifier, _ = incidents.upsert_incident("job", "mock failure")
    incidents.set_incident_state(identifier, "alerted")
    incidents.ack_incident(identifier)
    states = archive.lookup(path, table="executions", record_id=claimed["id"])
    assert [item["original"]["row"]["status"] for item in states] == ["claimed", "running", "failed"]
    job_history = archive.lookup(path, table="execution_archive_jobs", record_id=claimed["id"])
    assert json.loads(job_history[0]["original"]["row"]["snapshot"]) == job
    assert states[0]["original"]["schema"]["columns"]
    assert [item["original"]["row"]["state"] for item in archive.lookup(
        path, table="cron_incidents", record_id=identifier)] == ["detected", "alerted", "closed"]
    for table in ("execution_archive_events", "execution_archive_receipts", "execution_archive_jobs", "execution_archive_meta"):
        with closing(sqlite3.connect(path)) as conn:
            for statement in (f"DELETE FROM {table}", f"INSERT OR REPLACE INTO {table} SELECT * FROM {table}"):
                with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                    conn.execute(statement)
                conn.rollback()
    (home / "config.yaml").write_text("cron:\n  execution_archive: false\n")
    next_row = executions.create_execution("still-guarded", source="mock-owner")
    assert archive.lookup(path, table="executions", record_id=next_row["id"])


@pytest.mark.parametrize("fault", ["fsync", "capacity", "corrupt", "permission", "symlink", "lock"])
def test_archive_fault_preserves_hot_outcome_and_blocks_next_dispatch(ledger, monkeypatch, fault):
    _, path = ledger
    old, _ = _claim("old")
    executions.finish_execution(old["id"], success=True)
    current, _ = _claim("current")
    executions.mark_execution_running(current["id"])
    monkeypatch.setattr(executions, "MAX_TERMINAL_EXECUTIONS", 1)
    directory = path.parent / "execution-archive"
    original = next(directory.glob("*.json"))
    lock = None
    if fault in ("fsync", "capacity"):
        def fail(*args):
            raise OSError(errno.ENOSPC if fault == "capacity" else errno.EIO, "injected failure")
        monkeypatch.setattr(archive.os, "fsync", fail)
    elif fault == "corrupt":
        original.write_bytes(b"corrupt")
    elif fault == "permission":
        original.chmod(0o644)
    elif fault == "symlink":
        original.unlink()
        original.symlink_to(path)
    else:
        import fcntl
        lock = os.open(directory / ".lock", os.O_RDWR)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with pytest.raises(archive.ArchiveUnavailable):
            executions.finish_execution(current["id"], success=True)
        hot = _rows(path)
        assert len(hot) == 2
        assert next(row for row in hot if row["id"] == current["id"])["status"] == "completed"
        with pytest.raises(archive.ArchiveUnavailable):
            executions.create_execution("must-not-fire", source="mock-owner")
        assert _rows(path) == hot
    finally:
        if lock is not None:
            os.close(lock)


@pytest.mark.parametrize("target", ["cron-permission", "database-symlink", "archive-symlink"])
def test_unsafe_paths_never_prune_or_create(ledger, target):
    _, path = ledger
    _claim()
    before = _rows(path)
    if target == "cron-permission":
        path.parent.chmod(0o755)
    elif target == "database-symlink":
        original = path.with_suffix(".original")
        path.rename(original)
        path.symlink_to(original)
    else:
        directory = path.parent / "execution-archive"
        moved = path.parent / "original-archive"
        directory.rename(moved)
        directory.symlink_to(moved, target_is_directory=True)
    with pytest.raises((archive.ArchiveUnavailable, OSError)):
        executions.create_execution("must-not-fire", source="mock-owner")
    assert _rows(path) == before


def test_initialization_and_idle_recovery_preserve_all_legacy_hot_rows(ledger):
    home, path = ledger
    (home / "config.yaml").write_text("cron: {}\n")
    # Seed unarchived legacy records without calling the retention path.
    _seed(1001)
    incidents.upsert_incident("legacy", "mock failure")
    before = _rows(path), _rows(path, "cron_incidents")
    path.chmod(0o600)
    (home / "config.yaml").write_text("cron:\n  execution_archive: true\n")
    result = archive.initialize_existing()
    assert result["counts"]["executions"] == 1001
    assert result["counts"]["cron_incidents"] == 1
    assert result["counts"]["execution_archive_jobs"] == 0
    assert result["pruned"] == 0
    assert executions.recover_interrupted_executions() == 0
    assert (_rows(path), _rows(path, "cron_incidents")) == before
    assert archive.initialize_existing() == result


def test_concurrent_finishes_preserve_unique_versions(ledger, monkeypatch):
    _, path = ledger
    rows = [_claim(f"job-{index}")[0] for index in range(12)]
    monkeypatch.setattr(executions, "MAX_TERMINAL_EXECUTIONS", 3)
    with ThreadPoolExecutor(max_workers=4) as pool:
        finished = list(pool.map(lambda row: executions.finish_execution(row["id"], success=True), rows))
    assert len(_rows(path)) == 3
    for row in finished:
        versions = archive.lookup(path, table="executions", record_id=row["id"])
        assert versions[-1]["original"]["row"] == row
        assert len({item["receipt"] for item in versions}) == len(versions)


@pytest.mark.parametrize("phase", ["before-publish", "after-publish", "after-link"])
def test_process_crash_replays_committed_originals_without_overwrite(ledger, phase):
    home, path = ledger
    _claim("existing")
    script = """
import os
from cron import execution_archive as a, executions as e
phase = os.environ['ARCHIVE_TEST_PHASE']
publish = a._publish
if phase == 'after-link':
    link = a.os.link
    def killed_link(*args, **kwargs):
        link(*args, **kwargs)
        os._exit(71)
    a.os.link = killed_link
else:
    def killed_publish(*args):
        if phase == 'after-publish':
            publish(*args)
        os._exit(71)
    a._publish = killed_publish
e.create_execution('crash', source='mock-owner')
"""
    child = subprocess.run([sys.executable, "-c", script], env={**os.environ,
                           "HERMES_HOME": str(home), "ARCHIVE_TEST_PHASE": phase},
                           capture_output=True, timeout=20)
    assert child.returncode == 71, child.stderr.decode()
    before = _rows(path)
    assert len(before) == 2  # committed claim exists even though caller never received it
    receipt_files = {f.name: f.read_bytes() for f in (path.parent / "execution-archive").glob("*.json")}
    archive.initialize_existing()
    for filename, content in receipt_files.items():
        assert (path.parent / "execution-archive" / filename).read_bytes() == content
    assert _rows(path) == before
    for row in before:
        assert archive.lookup(path, table="executions", record_id=row["id"])[-1]["original"]["row"] == row


def test_actual_owner_seam_requires_matching_snapshot_and_valid_archive(ledger, monkeypatch):
    from cron import scheduler

    _, path = ledger
    row = executions.create_execution("job", source="mock-owner")
    with pytest.raises(archive.ArchiveUnavailable, match="job original"):
        executions.mark_execution_running(row["id"])
    entered = []
    monkeypatch.setattr(scheduler, "_launch_external_cron_worker", lambda job: entered.append(job) or True)
    job = {"id": "job", "execution_id": row["id"], "script": "original.sh"}
    assert scheduler.run_one_job(job)
    assert len(entered) == 1
    with pytest.raises(archive.ArchiveUnavailable, match="differs"):
        scheduler.run_one_job({**job, "script": "changed.sh"})
    next((path.parent / "execution-archive").glob("*.json")).write_bytes(b"corrupt")
    with pytest.raises(archive.ArchiveUnavailable):
        scheduler.run_one_job(job)
    assert len(entered) == 1


def test_missing_directory_disabled_config_cannot_redirect_sticky_ledger(ledger):
    home, path = ledger
    _claim()
    directory = path.parent / "execution-archive"
    directory.rename(path.parent / "preserved-archive")
    (home / "config.yaml").write_text("cron:\n  execution_archive: false\n")
    original = path.with_suffix(".original")
    path.rename(original)
    original_bytes = original.read_bytes()
    path.symlink_to(original)
    with pytest.raises(archive.ArchiveUnavailable):
        executions.create_execution("must-not-fire", source="mock-owner")
    assert original.read_bytes() == original_bytes


def test_receipt_commit_failure_retries_without_losing_terminal_original(ledger, monkeypatch):
    _, path = ledger
    row, _ = _claim()
    connect = executions._connect

    class BrokenCommit:
        def __init__(self, conn):
            self.conn = conn

        def __getattr__(self, name):
            return getattr(self.conn, name)

        def __enter__(self):
            self.conn.__enter__()
            return self

        def __exit__(self, *args):
            return self.conn.__exit__(*args)

        def commit(self):
            raise sqlite3.OperationalError("injected archive receipt commit failure")

    monkeypatch.setattr(executions, "_connect", lambda: BrokenCommit(connect()))
    with pytest.raises(sqlite3.OperationalError, match="commit failure"):
        executions.finish_execution(row["id"], success=True)
    hot = _rows(path)
    assert hot[0]["status"] == "completed"
    with pytest.raises(sqlite3.OperationalError, match="commit failure"):
        executions.create_execution("blocked", source="mock-owner")
    assert _rows(path) == hot
    monkeypatch.setattr(executions, "_connect", connect)
    archive.initialize_existing()
    assert archive.lookup(path, table="executions", record_id=row["id"])[-1]["original"]["row"] == hot[0]


def test_process_writers_serialize_or_fail_closed_without_loss(ledger):
    home, path = ledger
    archive.initialize_existing()
    script = """
from cron import execution_archive as a, executions as e
import sys
try:
    row=e.create_execution(sys.argv[1], source='mock-owner')
    e.bind_execution_job(row['id'], {'id':sys.argv[1]})
    e.finish_execution(row['id'], success=True)
except (a.ArchiveUnavailable, __import__('sqlite3').OperationalError):
    sys.exit(72)
"""
    workers = [subprocess.Popen([sys.executable, "-c", script, f"parallel-{index}"],
                               env={**os.environ, "HERMES_HOME": str(home)},
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE) for index in range(4)]
    for worker in workers:
        _, stderr = worker.communicate(timeout=30)
        assert worker.returncode in (0, 72), stderr.decode()
    archive.initialize_existing()
    rows = _rows(path)
    assert rows
    assert len({row["id"] for row in rows}) == len(rows)
    for row in rows:
        assert archive.lookup(path, table="executions", record_id=row["id"])[-1]["original"]["row"] == row


@pytest.mark.parametrize("fault", ["drop-capture", "alter-capture", "alter-immutable", "drop-index",
                                   "drop-table", "change-source", "missing-manifest", "unknown-trigger"])
def test_schema_damage_blocks_open_dispatch_and_prune_without_repair(ledger, monkeypatch, fault):
    _, path = ledger
    row, _ = _claim()
    monkeypatch.setattr(executions, "MAX_TERMINAL_EXECUTIONS", 0)
    with closing(sqlite3.connect(path)) as conn:
        if fault in ("drop-capture", "alter-capture"):
            name = "execution_archive_capture_executions_UPDATE"
            conn.execute(f"DROP TRIGGER {name}")
            if fault == "alter-capture":
                conn.execute(f"CREATE TRIGGER {name} AFTER UPDATE ON executions BEGIN SELECT 1; END")
        elif fault == "alter-immutable":
            name = "execution_archive_receipts_immutable_UPDATE"
            conn.execute(f"DROP TRIGGER {name}")
            conn.execute(f"CREATE TRIGGER {name} BEFORE UPDATE ON execution_archive_receipts BEGIN SELECT 1; END")
        elif fault == "drop-index":
            conn.execute("DROP INDEX execution_archive_record")
        elif fault == "drop-table":
            conn.execute("DROP TABLE execution_archive_jobs")
        elif fault == "change-source":
            conn.execute("ALTER TABLE executions ADD COLUMN changed_source TEXT")
        elif fault == "missing-manifest":
            name = "execution_archive_schemas_immutable_DELETE"
            definition = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0]
            conn.execute(f"DROP TRIGGER {name}")
            conn.execute("DELETE FROM execution_archive_schemas WHERE table_name='executions'")
            conn.execute(definition)
        else:
            conn.execute("CREATE TRIGGER bypass_capture BEFORE UPDATE ON executions BEGIN SELECT RAISE(IGNORE); END")
        conn.commit()
        objects = conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()
    originals = _rows(path)
    for operation in (lambda: executions.mark_execution_running(row["id"]),
                      lambda: executions.create_execution("blocked", source="mock-owner"),
                      lambda: executions.finish_execution(row["id"], success=True),
                      executions._prune_archived):
        with pytest.raises(archive.ArchiveUnavailable):
            operation()
        assert _rows(path) == originals
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall() == objects


def test_restored_capture_cannot_hide_an_unjournaled_current_version(ledger):
    _, path = ledger
    row, _ = _claim()
    with closing(sqlite3.connect(path)) as conn:
        name = "execution_archive_capture_executions_UPDATE"
        definition = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0]
        conn.execute(f"DROP TRIGGER {name}")
        conn.execute("UPDATE executions SET status='running' WHERE id=?", (row["id"],))
        conn.execute(definition)
        conn.commit()
    originals = _rows(path)
    with pytest.raises(archive.ArchiveUnavailable, match="exact current row"):
        executions.finish_execution(row["id"], success=True)
    with pytest.raises(archive.ArchiveUnavailable, match="exact current row"):
        executions.create_execution("blocked", source="mock-owner")
    assert _rows(path) == originals


def test_schema_manifest_rejects_update_delete_and_replace(ledger):
    _, path = ledger
    _claim()
    with closing(sqlite3.connect(path)) as conn:
        originals = conn.execute("SELECT * FROM execution_archive_schemas ORDER BY table_name").fetchall()
        for statement in ("UPDATE execution_archive_schemas SET schema_json='{}'",
                          "DELETE FROM execution_archive_schemas",
                          "INSERT OR REPLACE INTO execution_archive_schemas SELECT * FROM execution_archive_schemas"):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                conn.execute(statement)
            conn.rollback()
        assert conn.execute("SELECT * FROM execution_archive_schemas ORDER BY table_name").fetchall() == originals


@pytest.mark.parametrize("fault", ["unlogged-current-row", "unreceipted-latest-event"])
def test_historical_lookup_rejects_incomplete_lineage(ledger, fault):
    _, path = ledger
    row, _ = _claim()
    initial = archive.lookup(path, table="executions", record_id=row["id"])
    assert initial[-1]["original"]["row"]["status"] == "claimed"
    with closing(sqlite3.connect(path)) as conn:
        name = "execution_archive_capture_executions_UPDATE"
        definition = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0]
        if fault == "unlogged-current-row":
            conn.execute(f"DROP TRIGGER {name}")
        conn.execute("UPDATE executions SET status='running' WHERE id=?", (row["id"],))
        if fault == "unlogged-current-row":
            conn.execute(definition)
        conn.commit()
    originals = _rows(path)
    events = _rows(path, "execution_archive_events")
    receipts = _rows(path, "execution_archive_receipts")
    expected = "exact current row" if fault == "unlogged-current-row" else "missing a durable receipt"
    with pytest.raises(archive.ArchiveUnavailable, match=expected):
        archive.lookup(path, table="executions", record_id=row["id"])
    assert _rows(path) == originals
    assert _rows(path, "execution_archive_events") == events
    assert _rows(path, "execution_archive_receipts") == receipts


@pytest.mark.parametrize("missing", ["entire-pruned-lineage", "trailing-pruned-version"])
def test_pruned_only_journal_corruption_blocks_lookup_and_dispatch(ledger, monkeypatch, missing):
    _, path = ledger
    monkeypatch.setattr(executions, "MAX_TERMINAL_EXECUTIONS", 0)
    row, _ = _claim()
    executions.finish_execution(row["id"], success=True)
    assert executions.get_execution(row["id"]) is None
    assert archive.lookup(path, table="executions", record_id=row["id"])
    with closing(sqlite3.connect(path)) as conn:
        name = "execution_archive_events_immutable_DELETE"
        definition = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0]
        conn.execute(f"DROP TRIGGER {name}")
        if missing == "entire-pruned-lineage":
            conn.execute("DELETE FROM execution_archive_events WHERE table_name='executions' AND record_id=?",
                         (row["id"],))
        else:
            conn.execute("DELETE FROM execution_archive_events WHERE event_id="
                         "(SELECT MAX(event_id) FROM execution_archive_events)")
        conn.execute(definition)
        conn.commit()
    remaining = _rows(path, "execution_archive_events")
    receipts = _rows(path, "execution_archive_receipts")
    for operation in (lambda: archive.lookup(path, table="executions", record_id=row["id"]),
                      lambda: executions.create_execution("blocked", source="mock-owner")):
        with pytest.raises(archive.ArchiveUnavailable, match="journal stream is incomplete"):
            operation()
    assert _rows(path) == []
    assert _rows(path, "execution_archive_events") == remaining
    assert _rows(path, "execution_archive_receipts") == receipts


def test_orphan_receipt_is_rejected_even_with_contiguous_events(ledger):
    _, path = ledger
    row, _ = _claim()
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("INSERT INTO execution_archive_receipts "
                     "SELECT 999999, digest, row_digest FROM execution_archive_receipts LIMIT 1")
        conn.commit()
    with pytest.raises(archive.ArchiveUnavailable, match="no original event"):
        archive.lookup(path, table="executions", record_id=row["id"])
    with pytest.raises(archive.ArchiveUnavailable, match="no original event"):
        executions.create_execution("blocked", source="mock-owner")
    assert len(_rows(path)) == 1


def test_pending_committed_event_recovers_by_durable_sync_without_reconstruction(ledger):
    _, path = ledger
    row, _ = _claim()
    receipts = _rows(path, "execution_archive_receipts")
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("UPDATE executions SET status='running' WHERE id=?", (row["id"],))
        conn.commit()
    originals = _rows(path)
    events = _rows(path, "execution_archive_events")
    assert len(events) == len(receipts) + 1
    with pytest.raises(archive.ArchiveUnavailable, match="missing a durable receipt"):
        archive.lookup(path, table="executions", record_id=row["id"])
    result = archive.initialize_existing()
    assert result["counts"]["execution_archive_events"] == result["counts"]["execution_archive_receipts"]
    assert _rows(path) == originals
    assert _rows(path, "execution_archive_events") == events
    assert _rows(path, "execution_archive_receipts")[:len(receipts)] == receipts
    history = archive.lookup(path, table="executions", record_id=row["id"])
    assert [entry["original"]["row"]["status"] for entry in history] == ["claimed", "running"]


def test_database_rollback_cannot_forget_newer_original_files(ledger):
    _, path = ledger
    first, _ = _claim("first")
    snapshot = path.with_name("prior-snapshot.db")
    with closing(sqlite3.connect(path)) as current, closing(sqlite3.connect(snapshot)) as saved:
        current.backup(saved)
    _claim("newer")
    files = {file.name: file.read_bytes() for file in (path.parent / "execution-archive").glob("*.json")}
    with closing(sqlite3.connect(snapshot)) as saved, closing(sqlite3.connect(path)) as current:
        saved.backup(current)
    originals = _rows(path)
    events = _rows(path, "execution_archive_events")
    receipts = _rows(path, "execution_archive_receipts")
    assert len(originals) == 1 and len(events) == len(receipts)
    for operation in (lambda: archive.lookup(path, table="executions", record_id=first["id"]),
                      lambda: executions.create_execution("blocked", source="mock-owner"),
                      executions._prune_archived):
        with pytest.raises(archive.ArchiveUnavailable, match="original file set"):
            operation()
    assert _rows(path) == originals
    assert _rows(path, "execution_archive_events") == events
    assert _rows(path, "execution_archive_receipts") == receipts
    assert {file.name: file.read_bytes() for file in (path.parent / "execution-archive").glob("*.json")} == files
