"""Pangkalan bukti bersama: skema, koneksi lintas proses, berita acia operator.

Kolektor, executor, dan CLI provisioning membuka file SQLite yang sama. Aturan
kepemilikan tulisan: hanya kolektor yang menulis tabel `events` (rantai hash);
executor menulis `remediation_runs`, memungut persetujuan, dan menulis
`patrol_events` untuk simulasi perataan; operator_audit ditulis siapa pun yang
melakukan tindakan operator.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.environ.get("DB_PATH", "/evidence/events.sqlite3")
CONNECT_TIMEOUT_SECONDS = float(os.environ.get("DB_TIMEOUT_SECONDS", "15"))
ALLOWED_HOSTS = frozenset(
    value.strip()
    for value in os.environ.get("ALLOWED_HOSTS", "server-a,server-b").split(",")
    if value.strip()
)


class ClosingConnection(sqlite3.Connection):
    """Konteks koneksi commit/rollback lalu menutup descriptor SQLite."""

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def connect(db_path=None):
    connection = sqlite3.connect(
        db_path or DB_PATH, timeout=CONNECT_TIMEOUT_SECONDS, factory=ClosingConnection,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize(db_path=None):
    path = db_path or DB_PATH
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    with connect(path) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS chain_state (id INTEGER PRIMARY KEY CHECK (id = 1), last_hash TEXT NOT NULL)"
        )
        connection.execute("INSERT OR IGNORE INTO chain_state (id, last_hash) VALUES (1, '')")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS agent_status (
                host_id TEXT PRIMARY KEY,
                last_seen TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS remediation_runs (
                event_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT NOT NULL,
                quarantine_path TEXT,
                step_history TEXT NOT NULL DEFAULT '[]',
                started_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT
            )"""
        )
        remediation_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(remediation_runs)")
        }
        if "step_history" not in remediation_columns:
            connection.execute(
                "ALTER TABLE remediation_runs ADD COLUMN step_history TEXT NOT NULL DEFAULT '[]'"
            )
        if "detect_seconds" not in remediation_columns:
            connection.execute("ALTER TABLE remediation_runs ADD COLUMN detect_seconds REAL")
        if "entry_json" not in remediation_columns:
            connection.execute("ALTER TABLE remediation_runs ADD COLUMN entry_json TEXT")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                trajectory_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                host_id TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                path TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                previous_hash TEXT NOT NULL,
                integrity_hash TEXT NOT NULL,
                p_attack REAL NOT NULL,
                impact REAL NOT NULL,
                risk REAL NOT NULL,
                level INTEGER NOT NULL,
                recommendation TEXT NOT NULL,
                advisor_verdict TEXT NOT NULL,
                mode TEXT NOT NULL
            )"""
        )
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(events)")
        }
        if "content_signal" not in columns:
            connection.execute(
                "ALTER TABLE events ADD COLUMN content_signal INTEGER NOT NULL DEFAULT 0"
            )
        if "response_action" not in columns:
            connection.execute(
                "ALTER TABLE events ADD COLUMN response_action TEXT NOT NULL DEFAULT 'none'"
            )
        if "canonical_json" not in columns:
            connection.execute("ALTER TABLE events ADD COLUMN canonical_json TEXT")
        for name in ("policy_category", "policy_reasons", "recommendation_json", "approval_id"):
            if name not in columns:
                connection.execute(f"ALTER TABLE events ADD COLUMN {name} TEXT")
        if "risk_assessment_json" not in columns:
            connection.execute("ALTER TABLE events ADD COLUMN risk_assessment_json TEXT")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS event_dedup (
                dedupe_key TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS event_relationships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_event_id TEXT NOT NULL,
                target_event_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(source_event_id, target_event_id, relation)
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patrol_snapshots (
                host_id TEXT PRIMARY KEY,
                scanned_at TEXT NOT NULL,
                files_json TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patrol_fs_scans (
                host_id TEXT PRIMARY KEY,
                scanned_at TEXT NOT NULL,
                directory_count INTEGER NOT NULL,
                entry_count INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patrol_fs_directories (
                host_id TEXT NOT NULL,
                path TEXT NOT NULL,
                denied INTEGER NOT NULL,
                entries_json TEXT NOT NULL,
                PRIMARY KEY (host_id, path)
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patrol_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                type TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                host_id TEXT NOT NULL,
                path TEXT NOT NULL,
                severity TEXT NOT NULL,
                hash_old TEXT,
                hash_new TEXT,
                status TEXT NOT NULL
            )"""
        )
        patrol_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(patrol_events)")
        }
        if "port" not in patrol_columns:
            connection.execute("ALTER TABLE patrol_events ADD COLUMN port INTEGER")
        connection.execute(
            """CREATE TABLE IF NOT EXISTS operator_approvals (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                action TEXT NOT NULL,
                host_id TEXT NOT NULL,
                path TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                event_id TEXT,
                approval_status TEXT NOT NULL,
                approved_at TEXT,
                approved_by TEXT,
                expires_at TEXT,
                execution_status TEXT NOT NULL DEFAULT 'NONE',
                execution_detail TEXT,
                execution_at TEXT
            )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_approvals_state "
            "ON operator_approvals (approval_status, execution_status)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_approvals_event ON operator_approvals (event_id)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS operator_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                detail TEXT NOT NULL,
                outcome TEXT NOT NULL
            )"""
        )


def load_approvals_row(connection, approval_id):
    return connection.execute(
        "SELECT * FROM operator_approvals WHERE id = ?", (approval_id,)
    ).fetchone()


def write_audit(actor, action, target, detail, outcome):
    with connect() as connection:
        connection.execute(
            """INSERT INTO operator_audit (ts, actor, action, target, detail, outcome)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (utc_now(), str(actor or "unknown"), str(action), str(target), str(detail), str(outcome)),
        )


def record_stage(
    event_key,
    status,
    detail,
    host_id,
    path,
    quarantine_path=None,
    complete=False,
    detect_seconds=None,
    entry=None,
):
    """Buat atau majukan satu baris remediation_runs dengan riwayat tahap berurutan."""
    now = utc_now()
    with connect() as connection:
        row = connection.execute(
            "SELECT step_history FROM remediation_runs WHERE event_id = ?", (event_key,)
        ).fetchone()
        history = json.loads(row["step_history"]) if row else []
        history.append({"stage": status, "detail": detail, "timestamp": now})
        if row is None:
            connection.execute(
                """INSERT INTO remediation_runs
                   (event_id, host_id, path, status, detail, quarantine_path,
                    step_history, started_at, updated_at, completed_at, detect_seconds, entry_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(event_key), str(host_id), str(path), str(status), str(detail), quarantine_path,
                    json.dumps(history, ensure_ascii=False), now, now,
                    now if complete else None, detect_seconds, entry and json.dumps(entry, ensure_ascii=False),
                ),
            )
            return
        connection.execute(
            """UPDATE remediation_runs
               SET status = ?, detail = ?, quarantine_path = COALESCE(?, quarantine_path),
                   step_history = ?, updated_at = ?,
                   completed_at = CASE WHEN ? THEN ? ELSE completed_at END
               WHERE event_id = ?""",
            (
                str(status), str(detail), quarantine_path,
                json.dumps(history, ensure_ascii=False), now,
                int(complete), now, str(event_key),
            ),
        )


def update_event_response(event_id, mode, response_action):
    """Kolektor hanya pemilik awal; executor menutup kolom respons setelah tahap selesai."""
    if not event_id:
        return
    with connect() as connection:
        connection.execute(
            "UPDATE events SET mode = ?, response_action = ? WHERE id = ?",
            (str(mode), str(response_action), str(event_id)),
        )


def store_patrol_event(event, allowed_hosts=ALLOWED_HOSTS):
    """Tulis event patroli. Dipakai kolektor dan executor (simulasi perataan)."""
    allowed_types = {"patrol_check", "access", "alert"}
    allowed_actions = {"read", "download", "modify", "delete", "denied", "login"}
    allowed_severity = {"safe", "suspicious", "compromised"}
    event_type = event.get("type")
    action = event.get("action")
    severity = event.get("severity")
    host_id = event.get("host_id")
    path = event.get("path")
    actor = event.get("actor")
    port = event.get("port")
    if not isinstance(event_type, str) or not isinstance(action, str):
        raise ValueError("invalid_patrol_event")
    if event_type not in allowed_types or action not in allowed_actions:
        raise ValueError("invalid_patrol_event")
    if not isinstance(severity, str) or not isinstance(host_id, str):
        raise ValueError("invalid_patrol_event")
    if severity not in allowed_severity or host_id not in allowed_hosts:
        raise ValueError("invalid_patrol_event")
    if not isinstance(path, str) or not path or len(path) > 2048:
        raise ValueError("invalid_patrol_path")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
        port = None
    path = "".join(char if char.isprintable() else "?" for char in path)[:2048]
    actor = str(actor or "unknown")[:96]
    if actor != "police":
        import ipaddress
        try:
            actor = str(ipaddress.ip_address(actor))
        except ValueError:
            actor = "unknown"
    status = event.get("status", "observed")
    if not isinstance(status, str) or status not in {"observed", "allowed", "blocked", "not_found", "contained", "demo"}:
        status = "observed"
    try:
        timestamp = datetime.fromisoformat(str(event.get("ts") or "").replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError):
        timestamp = utc_now()
    hashes = []
    for key in ("hash_old", "hash_new"):
        value = event.get(key)
        hashes.append(value if isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value) else None)
    with connect() as connection:
        cursor = connection.execute(
            """INSERT INTO patrol_events
               (ts, type, actor, action, host_id, path, severity, hash_old, hash_new, status, port)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, event_type, actor, action, host_id, path, severity, hashes[0], hashes[1], status, port),
        )
        return cursor.lastrowid
