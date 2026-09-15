"""Private, append-only cron originals. Historical receipts never grant dispatch authority.

SQLite triggers journal each committed row version in the hot ledger transaction. A
separate immutable file is durably published and verified before its row can be pruned.
The journal is deliberately never compacted: it is the crash-recovery source of truth.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import uuid
from contextlib import contextmanager
from pathlib import Path

_TABLES = ("executions", "cron_incidents", "execution_archive_jobs")


class ArchiveUnavailable(RuntimeError):
    """Original preservation is unavailable; no pruning or new dispatch is allowed."""


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def requested(path: Path) -> bool:
    """Resolve the current profile, without default-profile config or cached fallbacks."""
    if (path.parent / "execution-archive").exists() or (path.parent / "execution-archive").is_symlink():
        return True
    config_path = path.parent.parent / "config.yaml"
    try:
        import yaml

        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        cron = config.get("cron") or {}
        value = cron.get("execution_archive", False)
        if type(value) is not bool:
            raise ValueError("invalid archive policy")
        return value or _existing_journal(path)
    except FileNotFoundError:
        return _existing_journal(path)
    except Exception:
        raise ArchiveUnavailable("Cron archive policy could not be verified") from None


def _existing_journal(path: Path) -> bool:
    # Sticky-policy detection is read-only and precedes schema initialization. Never
    # let a missing archive directory make a redirected SQLite target writable.
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ArchiveUnavailable("Cron ledger paths must not contain symlinks")
    if not path.exists():
        return False
    conn = None
    try:
        conn = sqlite3.connect(path.absolute().as_uri() + "?mode=ro", uri=True)
        return active(conn)
    except sqlite3.DatabaseError:
        # Preserve the preexisting corrupt-store error on profiles without an archive.
        return False
    finally:
        if conn is not None:
            conn.close()


def _check(st, *, directory: bool, private: bool = True) -> None:
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(st.st_mode) or st.st_uid != os.getuid():
        raise ArchiveUnavailable("Cron archive path has unsafe type or ownership")
    if private and stat.S_IMODE(st.st_mode) != (0o700 if directory else 0o600):
        raise ArchiveUnavailable("Cron archive path permissions must be private")
    if not directory and st.st_nlink != 1:
        raise ArchiveUnavailable("Cron archive originals must not have hard links")


def secure_ledger(path: Path) -> None:
    """Reject redirects before opening SQLite; never repair unsafe permissions implicitly."""
    for parent in [*reversed(path.absolute().parents), path.absolute()]:
        try:
            st = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode):
            raise ArchiveUnavailable("Cron archive paths must not contain symlinks")
        if parent == path.parent:
            _check(st, directory=True)
        if parent == path:
            _check(st, directory=False)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(path) + suffix)
        if sidecar.exists() or sidecar.is_symlink():
            _check(sidecar.lstat(), directory=False)
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        return
    os.close(fd)


def active(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='execution_archive_meta'").fetchone() is not None


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def initialize(conn: sqlite3.Connection, path: Path) -> None:
    """Opt-in is sticky in the ledger. Missing/toggled config cannot remove its guard."""
    if not active(conn) and not requested(path):
        return
    secure_ledger(path)
    conn.execute("BEGIN IMMEDIATE")
    conn.execute("CREATE TABLE IF NOT EXISTS execution_archive_meta "
                 "(id INTEGER PRIMARY KEY CHECK(id=1), stream_id TEXT NOT NULL)")
    if conn.execute("SELECT 1 FROM execution_archive_meta WHERE id=1").fetchone() is None:
        conn.execute("INSERT INTO execution_archive_meta VALUES (1, ?)", (uuid.uuid4().hex,))
    conn.execute("CREATE TABLE IF NOT EXISTS execution_archive_jobs "
                 "(id TEXT PRIMARY KEY, job_id TEXT NOT NULL, snapshot TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS execution_archive_events "
                 "(event_id INTEGER PRIMARY KEY AUTOINCREMENT, table_name TEXT NOT NULL, "
                 "record_id TEXT NOT NULL, snapshot TEXT NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS execution_archive_receipts "
                 "(event_id INTEGER PRIMARY KEY, digest TEXT NOT NULL, row_digest TEXT NOT NULL)")
    conn.execute("CREATE INDEX IF NOT EXISTS execution_archive_record "
                 "ON execution_archive_events(table_name, record_id, event_id)")
    conn.execute("CREATE TABLE IF NOT EXISTS execution_archive_schemas "
                 "(table_name TEXT PRIMARY KEY, schema_json TEXT NOT NULL)")
    for table in ("execution_archive_meta", "execution_archive_events",
                  "execution_archive_receipts", "execution_archive_jobs"):
        key = "event_id" if table in ("execution_archive_events", "execution_archive_receipts") else "id"
        conn.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_immutable_INSERT BEFORE INSERT ON {table} "
                     f"WHEN EXISTS (SELECT 1 FROM {table} WHERE {key}=NEW.{key}) BEGIN "
                     "SELECT RAISE(ABORT, 'Cron archive originals are immutable'); END")
        for action in ("UPDATE", "DELETE"):
            conn.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_immutable_{action} "
                         f"BEFORE {action} ON {table} BEGIN "
                         "SELECT RAISE(ABORT, 'Cron archive originals are immutable'); END")
    for table in _TABLES:
        _install_capture(conn, table)
    conn.commit()


def _install_capture(conn: sqlite3.Connection, table: str) -> None:
    definition = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                              (table,)).fetchone()
    if definition is None:
        return
    columns = [tuple(row) for row in conn.execute(f"PRAGMA table_info({table})")]
    schema = _canonical({"sql": definition[0], "columns": columns,
                         "user_version": conn.execute("PRAGMA user_version").fetchone()[0]}).decode()
    existing = conn.execute("SELECT schema_json FROM execution_archive_schemas WHERE table_name=?",
                            (table,)).fetchone()
    if existing is not None and existing[0] == schema:
        return
    fields = ", ".join(f"{_literal(col[1])}, NEW.\"{col[1]}\"" for col in columns)
    snapshot = (f"json_object('format', 1, 'table', '{table}', 'schema', json({_literal(schema)}), "
                f"'row', json_object({fields}))")
    for action in ("INSERT", "UPDATE"):
        name = f"execution_archive_capture_{table}_{action}"
        conn.execute(f"DROP TRIGGER IF EXISTS {name}")
        conn.execute(f"CREATE TRIGGER {name} AFTER {action} ON {table} BEGIN "
                     "INSERT INTO execution_archive_events(table_name, record_id, snapshot) "
                     f"VALUES ('{table}', NEW.id, {snapshot}); END")
    # Existing originals are observed exactly as stored; absent historical job definitions
    # are not reconstructed from today's jobs.json.
    for row in conn.execute(f"SELECT * FROM {table}"):
        value = {"format": 1, "table": table, "schema": json.loads(schema), "row": dict(row)}
        conn.execute("INSERT INTO execution_archive_events(table_name, record_id, snapshot) "
                     "VALUES (?, ?, ?)", (table, row["id"], _canonical(value).decode()))
    conn.execute("INSERT OR REPLACE INTO execution_archive_schemas VALUES (?, ?)", (table, schema))


@contextmanager
def _directory(path: Path):
    """Pin directories by descriptor; all original operations reject symlinks."""
    secure_ledger(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    archive = lock = None
    try:
        _check(os.fstat(parent), directory=True)
        try:
            os.mkdir("execution-archive", 0o700, dir_fd=parent)
            os.fsync(parent)
        except FileExistsError:
            pass
        archive = os.open("execution-archive", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=parent)
        _check(os.fstat(archive), directory=True)
        lock = os.open(".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=archive)
        _check(os.fstat(lock), directory=False)
        import fcntl

        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # A killed publisher may leave its staging link (including a second link to a
        # complete original). With the exclusive lock held, no staging writer is live.
        for name in os.listdir(archive):
            if re.fullmatch(r"\.pending-[0-9a-f]{32}", name):
                staged = os.stat(name, dir_fd=archive, follow_symlinks=False)
                if (not stat.S_ISREG(staged.st_mode) or staged.st_uid != os.getuid()
                        or stat.S_IMODE(staged.st_mode) != 0o600):
                    raise ArchiveUnavailable("Cron archive staging path is unsafe")
                os.unlink(name, dir_fd=archive)
                os.fsync(archive)
        yield archive
    except ArchiveUnavailable:
        raise
    except (OSError, ValueError):
        raise ArchiveUnavailable("Cron original archive unavailable; dispatch and prune blocked") from None
    finally:
        for fd in (lock, archive, parent):
            if fd is not None:
                os.close(fd)


def _read(directory: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        _check(os.fstat(fd), directory=False)
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def _publish(directory: int, name: str, data: bytes) -> None:
    try:
        previous = _read(directory, name)
    except FileNotFoundError:
        previous = None
    if previous is not None:
        if previous != data:
            raise ArchiveUnavailable("Cron original receipt content mismatch")
        # A previous process may have died before its directory sync/receipt commit.
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(directory)
        return
    # A crash while writing leaves a private .pending file, never a partial original.
    # O_EXCL publication via link is idempotent; a concurrent writer cannot overwrite.
    temporary = f".pending-{uuid.uuid4().hex}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
        try:
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory,
                    follow_symlinks=False)
        except FileExistsError:
            pass
    finally:
        os.close(fd)
        os.unlink(temporary, dir_fd=directory)
    os.fsync(directory)
    if _read(directory, name) != data:
        raise ArchiveUnavailable("Cron original archive read-back mismatch")


def _document(stream_id: str, event) -> tuple[bytes, str]:
    snapshot = json.loads(event["snapshot"])
    row_digest = _digest(_canonical(snapshot["row"]))
    value = {"format": 1, "historical_only": True, "confers_authority": False,
             "stream_id": stream_id, "event_id": event["event_id"],
             "previous_event_id": event["event_id"] - 1 or None,
             "row_digest": row_digest, "original": snapshot}
    return _canonical(value), row_digest


def sync(conn: sqlite3.Connection, path: Path, *, verify_all: bool = False) -> None:
    """Flush only committed journal versions. Caller holds the SQLite write fence."""
    if not active(conn):
        return
    stream_id = conn.execute("SELECT stream_id FROM execution_archive_meta WHERE id=1").fetchone()[0]
    with _directory(path) as directory:
        # A FULL SQLite commit is the first durable original; archive publishes are second.
        query = ("SELECT e.*, r.digest AS receipt_digest, r.row_digest AS receipt_row "
                                  "FROM execution_archive_events e LEFT JOIN execution_archive_receipts r "
                                  "ON r.event_id=e.event_id ")
        if not verify_all:
            query += "WHERE r.event_id IS NULL "
        for event in conn.execute(query + "ORDER BY e.event_id"):
            data, row_digest = _document(stream_id, event)
            digest = _digest(data)
            name = digest + ".json"
            if event["receipt_digest"] is not None:
                if (event["receipt_digest"] != digest or event["receipt_row"] != row_digest
                        or _read(directory, name) != data):
                    raise ArchiveUnavailable("Cron archive receipt verification failed")
            else:
                _publish(directory, name, data)
                conn.execute("INSERT INTO execution_archive_receipts VALUES (?, ?, ?)",
                             (event["event_id"], digest, row_digest))


def preserve(conn: sqlite3.Connection, path: Path, *, verify_all: bool = False) -> None:
    """Start after hot state commit; an archive failure never rewrites actual run state."""
    if not active(conn):
        return
    if conn.in_transaction:
        raise ArchiveUnavailable("Cannot archive an uncommitted execution state")
    conn.execute("BEGIN IMMEDIATE")
    try:
        sync(conn, path, verify_all=verify_all)
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def bind_job(conn: sqlite3.Connection, execution_id: str, job: dict) -> None:
    if not active(conn):
        return
    encoded = _canonical(job).decode()
    previous = conn.execute("SELECT job_id, snapshot FROM execution_archive_jobs WHERE id=?",
                            (execution_id,)).fetchone()
    if previous is not None:
        if previous[0] != str(job["id"]) or previous[1] != encoded:
            raise ArchiveUnavailable("Cron dispatch job differs from its immutable original")
        return
    conn.execute("INSERT INTO execution_archive_jobs VALUES (?, ?, ?)",
                 (execution_id, str(job["id"]), encoded))


def verify_prune(conn: sqlite3.Connection, record: dict) -> None:
    """Verify the exact version, not an earlier terminal state or another run's receipt."""
    event = conn.execute("SELECT e.*, r.digest AS receipt_digest FROM execution_archive_events e "
                         "LEFT JOIN execution_archive_receipts r ON r.event_id=e.event_id "
                         "WHERE e.table_name='executions' AND e.record_id=? "
                         "ORDER BY e.event_id DESC LIMIT 1", (record["id"],)).fetchone()
    if (event is None or event["receipt_digest"] is None
            or json.loads(event["snapshot"])["row"] != record):
        raise ArchiveUnavailable("Prune candidate has no verified exact original")


def lookup(path: Path, *, table: str, record_id: str) -> list[dict]:
    """Read original versions and receipt lineage. Never fall back from live authority APIs."""
    if table not in _TABLES:
        raise ValueError("Unknown cron archive record type")
    secure_ledger(path)
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        stream = conn.execute("SELECT stream_id FROM execution_archive_meta WHERE id=1").fetchone()[0]
        rows = conn.execute("SELECT e.*, r.digest FROM execution_archive_events e JOIN "
                            "execution_archive_receipts r ON r.event_id=e.event_id "
                            "WHERE e.table_name=? AND e.record_id=? ORDER BY e.event_id",
                            (table, record_id)).fetchall()
        result = []
        with _directory(path) as directory:
            for event in rows:
                data, _ = _document(stream, event)
                if _digest(data) != event["digest"] or _read(directory, event["digest"] + ".json") != data:
                    raise ArchiveUnavailable("Cron historical receipt verification failed")
                result.append({"receipt": event["digest"], **json.loads(data)})
        return result
    finally:
        conn.close()


def initialize_existing() -> dict:
    """Archive existing originals without pruning, recovery, dispatch, or job changes."""
    from cron import executions, incidents

    path = executions._db_path()
    if not requested(path):
        raise ArchiveUnavailable("Enable cron.execution_archive in this profile before initialization")
    # Both production schema initializers are used; no state transition function is called.
    for connect in (executions._connect, incidents._connect):
        conn = connect()
        try:
            preserve(conn, path, verify_all=True)
        finally:
            conn.close()
    conn = executions._connect()
    try:
        preserve(conn, path, verify_all=True)
        counts = {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in (*_TABLES, "execution_archive_events", "execution_archive_receipts")}
        digests = [row[0] for row in conn.execute("SELECT digest FROM execution_archive_receipts ORDER BY event_id")]
        return {"historical_only": True, "confers_authority": False, "pruned": 0,
                "counts": counts, "receipt_manifest_digest": _digest(_canonical(digests)),
                "legacy_job_definitions": "unavailable unless originally recorded"}
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Preserve profile-local cron originals without dispatch or pruning")
    parser.add_argument("--initialize", required=True, action="store_true")
    parser.parse_args()
    print(json.dumps(initialize_existing(), sort_keys=True))
