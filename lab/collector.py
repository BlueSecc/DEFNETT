"""DEFNETT lab collector + Policy Gate + Scenario Driver.

Satu proses control-plane lab: ingestion event, penyimpanan bukti (hash chain),
aturan risiko deterministik, Policy Gate, playbook canary, Scenario Driver
demo, dan dashboard API. Collector menggabungkan komponen agar alur
end-to-end mudah dijalankan; dokumentasi harus menyebut batas desain ini.

Keamanan respons:
- Policy Gate deterministik (policy.py) menahan semua aksi otomatis.
- LLM (llm_advisor.py) hanya penasihat; verdict valid `benign`/
  `insufficient_evidence` memaksa HOLD, bukan izin.
- Aksi otomatis terbatas pada canary lab yang path/marker-nya dikunci.
- Idempotensi: satu remediasi aktif per host; cooldown dan rate limit aktif.
"""

import csv
import hashlib
import io
import hmac
import ipaddress
import json
import os
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import policy
import scenario as scenario_module
import llm_advisor


DB_PATH = os.environ.get("DB_PATH", "/evidence/events.sqlite3")
DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"
ALLOWED_HOSTS = {
    value.strip()
    for value in os.environ.get("ALLOWED_HOSTS", "server-a,server-b").split(",")
    if value.strip()
}
ENABLE_LAB_AUTOREPAIR = os.environ.get(
    "ENABLE_LAB_AUTOREPAIR", os.environ.get("ENABLE_LAB_DRAIN", "false")
).lower() == "true"
DEMO_RECOVERY_DELAY_SECONDS = max(0, int(
    os.environ.get(
        "DEMO_RECOVERY_DELAY_SECONDS",
        os.environ.get("DEMO_REPAIR_DELAY_SECONDS", "0"),
    )
))
DEMO_REPAIR_HOST = os.environ.get("DEMO_REPAIR_HOST", "server-a")
HAPROXY_HOST = os.environ.get("HAPROXY_HOST", "haproxy")
HAPROXY_RUNTIME_PORT = int(os.environ.get("HAPROXY_RUNTIME_PORT", "9999"))
APP_BASE_URLS = {
    "server-a": os.environ.get("APP_BASE_URL_SERVER_A", "http://server-a:8080"),
    "server-b": os.environ.get("APP_BASE_URL_SERVER_B", "http://server-b:8080"),
}
SERVICE_PROBE_URL = os.environ.get("SERVICE_PROBE_URL", "http://haproxy:8080/")
INGEST_TOKEN = (os.environ.get("COLLECTOR_INGEST_TOKEN") or "").encode("utf-8")

REMEDIED_STATUSES = ("REPAIRED", "FAILED", "FAILED_ISOLATED", "REJECTED", "HOLD")
RUNNING_STATUSES = {
    "DETECTED", "ISOLATING", "ISOLATED", "REPAIRING", "VERIFYING", "REJOINING",
}
IMPACT_CIA = (1, 3, 2)
IMPACT = sum(IMPACT_CIA) / 3


def connect():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with connect() as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS chain_state (id INTEGER PRIMARY KEY CHECK (id = 1), last_hash TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT OR IGNORE INTO chain_state (id, last_hash) VALUES (1, '')"
        )
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
        connection.execute(
            """CREATE TABLE IF NOT EXISTS patrol_snapshots (
                host_id TEXT PRIMARY KEY,
                scanned_at TEXT NOT NULL,
                files_json TEXT NOT NULL
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
        if "origin" not in patrol_columns:
            connection.execute(
                "ALTER TABLE patrol_events ADD COLUMN origin TEXT NOT NULL DEFAULT 'live'"
            )
        if "scenario_run" not in patrol_columns:
            connection.execute(
                "ALTER TABLE patrol_events ADD COLUMN scenario_run TEXT"
            )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS policy_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                run_id TEXT,
                event_id TEXT,
                host_id TEXT,
                initiator TEXT NOT NULL,
                decision TEXT NOT NULL,
                reasons TEXT NOT NULL,
                config TEXT NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scenario_runs (
                run_id TEXT PRIMARY KEY,
                scenario TEXT NOT NULL,
                target TEXT NOT NULL,
                survivor TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                steps TEXT NOT NULL DEFAULT '[]',
                evidence_ids TEXT NOT NULL DEFAULT '[]',
                metrics TEXT NOT NULL DEFAULT '{}',
                policy_context TEXT NOT NULL DEFAULT '{}',
                rejection_reason TEXT,
                pause_requested INTEGER NOT NULL DEFAULT 0,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                detail TEXT NOT NULL DEFAULT '{}'
            )"""
        )
        for statement in (
            "ALTER TABLE scenario_runs ADD COLUMN detail TEXT NOT NULL DEFAULT '{}'",
        ):
            try:
                connection.execute(statement)
            except sqlite3.OperationalError as error:
                if "duplicate column name" not in str(error).lower():
                    raise


# ---------------------------------------------------------------------------
# Aturan FIM canary dan risiko deterministik
# ---------------------------------------------------------------------------


def evaluate(event):
    if is_canary_detection(event):
        probability = 0.99
        risk = round(probability * IMPACT, 3)
        return probability, risk, 3, "auto_repair_canary_and_rejoin", "lab_canary_match"

    probability = {
        "file_created": 0.20,
        "file_modified": 0.55,
        "file_deleted": 0.72,
    }[event["event_type"]]
    risk = round(probability * IMPACT, 3)
    if risk >= 1.0:
        level, recommendation = 2, "operator_review"
    elif risk >= 0.5:
        level, recommendation = 1, "alert"
    else:
        level, recommendation = 0, "record"
    verdict = "suspicious" if event["event_type"] != "file_created" else "insufficient_evidence"
    return probability, risk, level, recommendation, verdict


def is_canary_detection(event):
    return (
        event.get("content_signal") is True
        and event.get("indicator") == "DEFNETT_LAB_CANARY"
        and event.get("path") == "DEFNETT-LAB-CANARY.txt"
        and event.get("event_type") in {"file_created", "file_modified"}
        and event.get("new_hash") is not None
        and event.get("host_id") in ALLOWED_HOSTS
    )


def canary_path_host_ok(event):
    return (
        event.get("path") == "DEFNETT-LAB-CANARY.txt"
        and event.get("host_id") in ALLOWED_HOSTS
        and event.get("event_type") in {"file_created", "file_modified"}
        and event.get("new_hash")
    )


# ---------------------------------------------------------------------------
# HAProxy runtime helpers
# ---------------------------------------------------------------------------


def haproxy_command(command):
    with socket.create_connection((HAPROXY_HOST, HAPROXY_RUNTIME_PORT), timeout=3) as connection:
        connection.settimeout(3)
        connection.sendall((command + "\n").encode("ascii"))
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace").strip()


def backend_is_up(server_name):
    response = haproxy_command("show stat")
    lines = response.splitlines()
    if not lines:
        return False
    header = lines[0].lstrip("# ").split(",")
    for row in csv.DictReader(lines[1:], fieldnames=header):
        if row.get("pxname") == "defnett_servers" and row.get("svname") == server_name:
            return row.get("status", "").startswith("UP")
    return False


def wait_for_backend(server_name, expected_up, attempts=10):
    for _ in range(attempts):
        if backend_is_up(server_name) is expected_up:
            return True
        time.sleep(0.5)
    return False


def backend_states():
    result = {host: "UNKNOWN" for host in ALLOWED_HOSTS}
    try:
        lines = haproxy_command("show stat").splitlines()
        if not lines:
            return result
        header = lines[0].lstrip("# ").split(",")
        for row in csv.DictReader(lines[1:], fieldnames=header):
            name = row.get("svname")
            if row.get("pxname") == "defnett_servers" and name in result:
                result[name] = row.get("status", "UNKNOWN")
    except (OSError, socket.timeout, UnicodeError):
        pass
    return result


def drained_backends(states):
    drained = []
    for host, state in (states or {}).items():
        upper = str(state or "").upper()
        if upper.startswith("MAINT") or "DRAIN" in upper:
            drained.append(host)
    return drained


def direct_health_probe(host_id):
    url = f"{APP_BASE_URLS.get(host_id, '')}/healthz"
    if not url or not url.startswith("http"):
        return None
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError, TimeoutError):
        return None


def agent_states():
    with connect() as connection:
        rows = connection.execute("SELECT host_id, last_seen FROM agent_status").fetchall()
    seen = {row["host_id"]: row["last_seen"] for row in rows}
    now = datetime.now(timezone.utc)
    result = {}
    for host_id in sorted(ALLOWED_HOSTS):
        timestamp = seen.get(host_id)
        age = None
        if timestamp:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            age = max(0, int((now - parsed).total_seconds()))
        result[host_id] = {
            "last_seen": timestamp,
            "age_seconds": age,
            "online": age is not None and age <= 25,
        }
    return result


# ---------------------------------------------------------------------------
# Remediation bookkeeping
# ---------------------------------------------------------------------------


def set_remediation(event_id, status, detail, quarantine_path=None, complete=False):
    now = datetime.now(timezone.utc).isoformat()
    with connect() as connection:
        row = connection.execute(
            "SELECT step_history FROM remediation_runs WHERE event_id = ?", (event_id,)
        ).fetchone()
        history = json.loads(row["step_history"]) if row else []
        history.append({"stage": status, "detail": detail, "timestamp": now})
        connection.execute(
            """UPDATE remediation_runs
               SET status = ?, detail = ?, quarantine_path = COALESCE(?, quarantine_path),
                   step_history = ?, updated_at = ?,
                   completed_at = CASE WHEN ? THEN ? ELSE completed_at END
               WHERE event_id = ?""",
            (status, detail, quarantine_path, json.dumps(history), now, int(complete), now, event_id),
        )


def insert_remediation_run(event_id, host_id, path, status, detail):
    now = datetime.now(timezone.utc).isoformat()
    with connect() as connection:
        connection.execute(
            """INSERT OR REPLACE INTO remediation_runs
               (event_id, host_id, path, status, detail, quarantine_path,
                step_history, started_at, updated_at, completed_at)
               VALUES (?, ?, ?, ?, ?, NULL, ?, ?, ?, NULL)""",
            (
                event_id, host_id, path, status, detail,
                json.dumps([{"stage": status, "detail": detail, "timestamp": now}]),
                now, now,
            ),
        )


def remediation_rows(limit=20):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM remediation_runs ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
    result = [dict(row) for row in rows]
    for row in result:
        try:
            row["steps"] = json.loads(row.pop("step_history"))
        except (json.JSONDecodeError, TypeError):
            row["steps"] = []
    return result


def remediation_by_event(event_id):
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM remediation_runs WHERE event_id = ?", (event_id,)
        ).fetchone()
    if not row:
        return None
    result = dict(row)
    try:
        result["steps"] = json.loads(result.pop("step_history"))
    except (json.JSONDecodeError, TypeError):
        result["steps"] = []
    return result


def active_remediation_for_host(host_id):
    with connect() as connection:
        row = connection.execute(
            "SELECT event_id FROM remediation_runs WHERE host_id = ? AND status NOT IN (?, ?, ?, ?, ?) LIMIT 1",
            (host_id, *REMEDIED_STATUSES),
        ).fetchone()
    return row["event_id"] if row else None


def last_concluded_action_age(host_id):
    with connect() as connection:
        row = connection.execute(
            "SELECT MAX(updated_at) AS last_updated FROM remediation_runs WHERE host_id = ? AND status IN (?, ?, ?)",
            (host_id, "REPAIRED", "FAILED", "FAILED_ISOLATED"),
        ).fetchone()
    raw = row["last_updated"] if row else None
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Policy Gate (deterministik) — hasil direkam untuk audit
# ---------------------------------------------------------------------------


def run_policy_gate_for(target, event_context=None, evidence_valid=False, run_id=None, initiator="fim_event"):
    """Susun konteks dari kondisi lab aktual dan minta keputusan gate."""
    survivor = "server-b" if target == "server-a" else "server-a"
    states = backend_states()
    event_context = event_context or {}

    with connect() as connection:
        recent_count = connection.execute(
            "SELECT COUNT(*) AS total FROM policy_decisions WHERE host_id = ? AND decision = 'approved' AND created_at >= ?",
            (target, (datetime.now(timezone.utc) - timedelta(seconds=policy.PolicyConfig().rate_window_seconds)).isoformat()),
        ).fetchone()["total"]

    context = {
        "event": {
            "host_id": target,
            "event_type": event_context.get("event_type"),
            "path": event_context.get("path"),
            "old_hash": event_context.get("old_hash"),
            "new_hash": event_context.get("new_hash"),
            "content_signal": event_context.get("content_signal"),
            "indicator": event_context.get("indicator"),
        },
        "evidence_valid": bool(evidence_valid),
        "risk": float(event_context.get("risk") or 0.0),
        "level": int(event_context.get("level") or 0),
        "target": target,
        "survivor": survivor,
        "target_allowed": target in ALLOWED_HOSTS,
        "backend_states": states,
        "survivor_reachable": direct_health_probe(survivor),
        "active_drains": drained_backends(states),
        "last_action_seconds_ago": last_concluded_action_age(target),
        "recent_action_count": recent_count,
        "canary_run_in_progress": active_remediation_for_host(target) is not None,
        "advisor_status": event_context.get("advisor_status", "disabled"),
        "advisor_verdict": event_context.get("advisor_verdict"),
    }
    decision = policy.evaluate_containment(context)
    record_policy_decision(run_id, None, target, initiator, decision)
    return decision


def run_policy_gate_for_event(event, event_id, initiator="fim_event"):
    advisor = collect_advisor(event, event_id)
    decision = run_policy_gate_for(
        event["host_id"],
        event_context={
            "event_type": event.get("event_type"),
            "path": event.get("path"),
            "old_hash": event.get("old_hash"),
            "new_hash": event.get("new_hash"),
            "content_signal": event.get("content_signal"),
            "indicator": event.get("indicator"),
            "risk": advisor.get("risk"),
            "level": advisor.get("level"),
            "advisor_status": advisor.get("status"),
            "advisor_verdict": advisor.get("verdict"),
        },
        evidence_valid=True,
        run_id=None,
        initiator=initiator,
    )
    return advisor, decision


def record_policy_decision(run_id, event_id, host_id, initiator, decision):
    reasons = json.dumps(decision.get("reasons", []), ensure_ascii=False)
    config = json.dumps(decision.get("config", {}), ensure_ascii=False)
    with connect() as connection:
        connection.execute(
            """INSERT INTO policy_decisions
               (created_at, run_id, event_id, host_id, initiator, decision, reasons, config)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(), run_id, event_id, host_id,
                initiator, decision.get("decision"), reasons, config,
            ),
        )


def recent_policy_decisions(limit=15):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM policy_decisions ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    result = [dict(row) for row in rows]
    for row in result:
        for key in ("reasons", "config"):
            try:
                row[key] = json.loads(row[key])
            except (json.JSONDecodeError, TypeError):
                row[key] = []
    return result


def collect_advisor(event, event_id, evidence_ids=None):
    """Panggil penasihat LLM bila mode aktif; selalu kembali dict status."""
    config = llm_advisor.AdviserConfig()
    ids = set(evidence_ids or ([event_id] if event_id else []))
    context = {
        "host_id": event.get("host_id"),
        "event_type": event.get("event_type"),
        "path": event.get("path"),
        "old_hash": event.get("old_hash"),
        "new_hash": event.get("new_hash"),
        "canary_signal": is_canary_detection(event),
        "risk": (0.99 * IMPACT) if is_canary_detection(event) else (
            {"file_created": 0.20, "file_modified": 0.55, "file_deleted": 0.72}.get(event.get("event_type"), 0) * IMPACT
        ),
        "level": 3 if is_canary_detection(event) else 0,
    }
    result = llm_advisor.advise(context, config=config, evidence_ids=ids)
    result["risk"] = context["risk"]
    result["level"] = context["level"]
    return result


# ---------------------------------------------------------------------------
# Playbook containment canary dengan gate
# ---------------------------------------------------------------------------


def request_lab_repair(event_id, host_id):
    payload = json.dumps({"host_id": host_id, "event_id": event_id}).encode("utf-8")
    request = urllib.request.Request(
        os.environ.get(
            f"REMEDIATOR_URL_{host_id.upper().replace('-', '_')}",
            {"server-a": "http://remediator-a:8091/v1/repair", "server-b": "http://remediator-b:8091/v1/repair"}[host_id],
        ),
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"remediator returned HTTP {response.status}")
        result = json.loads(response.read())
    if result.get("status") != "QUARANTINED_CANARY" or not result.get("quarantine_path"):
        raise RuntimeError(result.get("detail", "remediation_not_verified"))
    return result


def remediator_health(host_id):
    urls = {
        "server-a": os.environ.get("REMEDIATOR_HEALTH_URL_SERVER_A", "http://remediator-a:8091/healthz"),
        "server-b": os.environ.get("REMEDIATOR_HEALTH_URL_SERVER_B", "http://remediator-b:8091/healthz"),
    }
    try:
        with urllib.request.urlopen(urls[host_id], timeout=1) as response:
            return "ready" if response.status == 200 else "unavailable"
    except (KeyError, OSError, urllib.error.URLError, TimeoutError):
        return "unavailable"


def run_canary_response(event, event_id, initiator="fim_event"):
    """Jalankan playbook hanya setelah Policy Gate menyetujui."""
    if not is_canary_detection(event):
        return "DRY_RUN", "none"
    if not ENABLE_LAB_AUTOREPAIR:
        return "DRY_RUN", "would_isolate_repair_and_verify"
    target = event["host_id"]
    if target not in ALLOWED_HOSTS:
        return "REJECTED", "automatic_repair_not_allowed_for_this_host"
    survivor = "server-b" if target == "server-a" else "server-a"

    advisor, decision = run_policy_gate_for_event(event, event_id, initiator=initiator)
    failed_codes = decision.get("failed_codes") or []
    if decision.get("decision") != policy.DECISION_APPROVED:
        status = "HOLD" if any(code.startswith("ADVISOR") for code in failed_codes) else "REJECTED"
        mode = "HELD_FOR_OPERATOR" if status == "HOLD" else "REJECTED"
        detail = "Policy Gate tidak menyetujui containment aksi otomatis: " + ", ".join(failed_codes)
        insert_remediation_run(event_id, target, event.get("path"), status, detail)
        summary = {
            "event_id": event_id,
            "target": target,
            "decision": decision.get("decision"),
            "failed_codes": failed_codes,
            "advisor": {key: advisor.get(key) for key in ("status", "verdict", "model_used")},
        }
        print(json.dumps({"playbook": status, **summary}, ensure_ascii=False), flush=True)
        return mode, failed_codes[0] if failed_codes else "policy_not_approved"

    now = datetime.now(timezone.utc).isoformat()
    insert_remediation_run(
        event_id, target, event.get("path"), "DETECTED", "Canary lab terverifikasi; Policy Gate menyetujui tindakan."
    )

    try:
        if not backend_is_up(survivor):
            # Re-check dengan gate lagi sebelum benar-benar meniru aksi; ringkasan dibuat
            set_remediation(
                event_id, "FAILED",
                f"{survivor} tidak sehat pada saat eksekusi; {target} tidak diubah agar layanan tetap tersedia.",
                complete=True,
            )
            return "FAILED", f"survivor_not_healthy:{survivor}"
        set_remediation(event_id, "ISOLATING", f"Mengeluarkan {target} saja dari rotasi HAProxy.")
        haproxy_command(f"disable server defnett_servers/{target}")
        if not wait_for_backend(target, False):
            set_remediation(event_id, "FAILED", f"HAProxy belum mengonfirmasi isolasi {target}.", complete=True)
            return "FAILED", f"target_isolation_not_confirmed:{target}"

        set_remediation(
            event_id, "ISOLATED",
            f"{target} terisolasi; {survivor} tetap aktif dan tidak diubah.",
        )
        delay = DEMO_RECOVERY_DELAY_SECONDS if target == DEMO_REPAIR_HOST else 0
        if delay:
            set_remediation(
                event_id, "REPAIRING",
                f"Demo: perbaikan {target} berlangsung {delay // 60} menit; host tetap terisolasi.",
            )
            time.sleep(delay)
        else:
            set_remediation(event_id, "REPAIRING", f"Worker {target} mengarantina artefak canary pada host itu saja.")
        repair = request_lab_repair(event_id, target)
        set_remediation(
            event_id, "VERIFYING", f"Canary {target} dipindahkan; menunggu health check.",
            quarantine_path=repair["quarantine_path"],
        )
        haproxy_command(f"enable server defnett_servers/{target}")
        set_remediation(event_id, "REJOINING", f"HAProxy memeriksa {target} sebelum menerima trafik.")
        if not wait_for_backend(target, True, attempts=20):
            haproxy_command(f"disable server defnett_servers/{target}")
            set_remediation(event_id, "FAILED", f"Health check gagal; {target} tetap terisolasi.", complete=True)
            return "FAILED_ISOLATED", f"health_check_failed:{target}_remains_isolated"

        set_remediation(
            event_id, "REPAIRED", f"Health check {target} lolos; {target} aktif kembali. {survivor} tidak diubah.",
            quarantine_path=repair["quarantine_path"], complete=True,
        )
        return "ACTIVE_LAB", f"AUTO_REPAIRED_AND_REJOINED_{target.upper().replace('-', '_')}"
    except (OSError, socket.timeout, UnicodeError, urllib.error.URLError, ValueError, RuntimeError) as error:
        try:
            haproxy_command(f"disable server defnett_servers/{target}")
        except (OSError, socket.timeout, UnicodeError):
            pass
        set_remediation(
            event_id, "FAILED",
            f"Pemulihan {target} berhenti dengan aman: {type(error).__name__}; host itu tetap diisolasi, {survivor} tidak diubah.",
            complete=True,
        )
        return "FAILED_ISOLATED", f"repair_failed:{target}:{type(error).__name__}"


def finish_canary_response(event, event_id):
    mode, response_action = run_canary_response(event, event_id)
    with connect() as connection:
        connection.execute(
            "UPDATE events SET mode = ?, response_action = ? WHERE id = ?",
            (mode, response_action, event_id),
        )


# ---------------------------------------------------------------------------
# Event ingestion
# ---------------------------------------------------------------------------


def store_event(event):
    event_id = str(uuid.uuid4())
    parsed = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    timestamp = parsed.astimezone(timezone.utc).isoformat()
    trajectory_id = f"{event['host_id']}-{int(parsed.timestamp()) // 300}"
    p_attack, risk, level, recommendation, verdict = evaluate(event)
    canonical = json.dumps(
        {
            "event_id": event_id,
            "trajectory_id": trajectory_id,
            "timestamp": timestamp,
            **event,
            "p_attack": p_attack,
            "risk": risk,
            "recommendation": recommendation,
            "content_signal": bool(event.get("content_signal", False)),
            "indicator": event.get("indicator"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )

    with connect() as connection:
        previous_hash = connection.execute(
            "SELECT last_hash FROM chain_state WHERE id = 1"
        ).fetchone()["last_hash"]
        integrity_hash = hashlib.sha256(
            (previous_hash + canonical).encode("utf-8")
        ).hexdigest()
        connection.execute(
            """INSERT INTO events (
                id, trajectory_id, timestamp, host_id, source, event_type, path,
                old_hash, new_hash, previous_hash, integrity_hash, p_attack,
                impact, risk, level, recommendation, advisor_verdict, mode,
                content_signal, response_action
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id, trajectory_id, timestamp, event["host_id"], event["source"],
                event["event_type"], event["path"], event.get("old_hash"), event.get("new_hash"),
                previous_hash, integrity_hash, p_attack, IMPACT, risk, level,
                recommendation, verdict, "DRY_RUN", int(bool(event.get("content_signal"))), "none",
            ),
        )
        connection.execute(
            "UPDATE chain_state SET last_hash = ? WHERE id = 1", (integrity_hash,)
        )

    patrol_severity = "compromised" if level >= 3 else "suspicious" if level >= 2 else "safe"
    patrol_type = "patrol_check" if event["event_type"] == "file_created" and patrol_severity == "safe" else "alert"
    patrol_action = "delete" if event["event_type"] == "file_deleted" else "modify" if event["event_type"] == "file_modified" else "read"
    store_patrol_event({
        "type": patrol_type,
        "actor": "police",
        "action": patrol_action,
        "host_id": event["host_id"],
        "path": event["path"],
        "severity": patrol_severity,
        "hash_old": event.get("old_hash"),
        "hash_new": event.get("new_hash"),
        "status": "observed",
        "origin": "live",
    })

    if ENABLE_LAB_AUTOREPAIR and is_canary_detection(event):
        if scenario_run_pending_for(event["host_id"]):
            # Skenario aktif mengusir playboook otomatis; driver skenario
            # yang mengendalikan playbook untuk run ini.
            mode, response_action = "SCENARIO_DRIVEN", "SCENARIO_PLAYBOOK_WILL_DRIVE"
        else:
            threading.Thread(
                target=finish_canary_response,
                args=(event.copy(), event_id),
                name=f"canary-repair-{event_id[:8]}",
                daemon=True,
            ).start()
            mode, response_action = "ACTIVE_LAB", f"AUTO_REPAIR_QUEUED_{event['host_id'].upper().replace('-', '_')}"
    else:
        mode, response_action = run_canary_response(event, event_id)

    return {
        "event_id": event_id,
        "trajectory_id": trajectory_id,
        "risk": risk,
        "level": level,
        "recommendation": recommendation,
        "advisor_verdict": verdict,
        "mode": mode,
        "response_action": response_action,
        "content_signal": bool(event.get("content_signal", False)),
        "integrity_hash": integrity_hash,
    }


def event_rows(limit=100):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def find_event(event_id):
    with connect() as connection:
        row = connection.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------------
# Patrol events (dashboard peta)
# ---------------------------------------------------------------------------


def store_patrol_snapshot(host_id, files, scanned_at=None):
    if not isinstance(host_id, str) or host_id not in ALLOWED_HOSTS:
        raise ValueError("unknown_host")
    cleaned = []
    for item in files[:5000]:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        digest = item.get("sha256")
        if not isinstance(path, str) or not path or len(path) > 2048:
            continue
        parts = Path(path).parts
        if Path(path).is_absolute() or ".." in parts:
            continue
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            continue
        cleaned.append({"path": path, "sha256": digest})
    try:
        timestamp = datetime.fromisoformat(scanned_at.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except (AttributeError, TypeError, ValueError):
        timestamp = datetime.now(timezone.utc).isoformat()
    with connect() as connection:
        connection.execute(
            """INSERT INTO patrol_snapshots (host_id, scanned_at, files_json)
               VALUES (?, ?, ?) ON CONFLICT(host_id) DO UPDATE SET
               scanned_at = excluded.scanned_at, files_json = excluded.files_json""",
            (host_id, timestamp, json.dumps(cleaned, ensure_ascii=False)),
        )


def store_patrol_event(event):
    allowed_types = {"patrol_check", "access", "alert"}
    allowed_actions = {"read", "download", "modify", "delete", "denied"}
    allowed_severity = {"safe", "suspicious", "compromised"}
    allowed_origin = {"live", "simulation"}
    event_type = event.get("type")
    action = event.get("action")
    severity = event.get("severity")
    host_id = event.get("host_id")
    path = event.get("path")
    actor = event.get("actor")
    if not isinstance(event_type, str) or not isinstance(action, str):
        raise ValueError("invalid_patrol_event")
    if event_type not in allowed_types or action not in allowed_actions:
        raise ValueError("invalid_patrol_event")
    if not isinstance(severity, str) or not isinstance(host_id, str):
        raise ValueError("invalid_patrol_event")
    if severity not in allowed_severity or host_id not in ALLOWED_HOSTS:
        raise ValueError("invalid_patrol_event")
    if not isinstance(path, str) or not path or len(path) > 2048:
        raise ValueError("invalid_patrol_path")
    path = "".join(char if char.isprintable() else "?" for char in path)[:2048]
    actor = str(actor or "unknown")[:96]
    if actor != "police":
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
        timestamp = datetime.now(timezone.utc).isoformat()
    hashes = []
    for key in ("hash_old", "hash_new"):
        value = event.get(key)
        hashes.append(value if isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value) else None)
    origin = event.get("origin")
    origin = origin if isinstance(origin, str) and origin in allowed_origin else "live"
    scenario_run = event.get("scenario_run")
    scenario_run = scenario_run if isinstance(scenario_run, str) and 0 < len(scenario_run) <= 64 else None
    with connect() as connection:
        cursor = connection.execute(
            """INSERT INTO patrol_events
               (ts, type, actor, action, host_id, path, severity, hash_old, hash_new, status, origin, scenario_run)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (timestamp, event_type, actor, action, host_id, path, severity, hashes[0], hashes[1], status, origin, scenario_run),
        )
        return cursor.lastrowid


def patrol_events(after_id=0, limit=100):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM patrol_events WHERE id > ? ORDER BY id ASC LIMIT ?",
            (after_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def latest_patrol_event_id():
    with connect() as connection:
        row = connection.execute("SELECT MAX(id) FROM patrol_events").fetchone()
    return row[0]


def patrol_state():
    with connect() as connection:
        snapshots = connection.execute(
            "SELECT host_id, scanned_at, files_json FROM patrol_snapshots ORDER BY host_id"
        ).fetchall()
    files = []
    scanned = {}
    for snapshot in snapshots:
        scanned[snapshot["host_id"]] = snapshot["scanned_at"]
        for item in json.loads(snapshot["files_json"]):
            files.append({
                "host_id": snapshot["host_id"],
                "path": item["path"],
                "sha256": item["sha256"],
                "checked_at": snapshot["scanned_at"],
            })
    events = patrol_events(max(0, (latest_patrol_event_id() or 0) - 100), 100)
    recent = list(reversed(events))
    severity_by_file = {}
    for event in recent:
        key = (event["host_id"], event["path"])
        if key not in severity_by_file:
            severity_by_file[key] = event["severity"]
    safe = sum(1 for file in files if severity_by_file.get((file["host_id"], file["path"]), "safe") == "safe")
    suspicious = sum(1 for severity in severity_by_file.values() if severity == "suspicious")
    compromised = sum(1 for severity in severity_by_file.values() if severity == "compromised")
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": files,
        "scanned_at": scanned,
        "events": events[-100:],
        "counters": {"safe": safe, "suspicious": suspicious, "compromised": compromised},
    }


# ---------------------------------------------------------------------------
# Scenario Driver — deps di atas kondisi lab aktual
# ---------------------------------------------------------------------------


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def parse_scenario_json_keys(result):
    for key in ("steps", "evidence_ids", "metrics", "policy_context", "detail", "rejection_reason"):
        try:
            result[key] = json.loads(result[key])
        except (json.JSONDecodeError, TypeError):
            result[key] = [] if key in {"steps", "evidence_ids", "rejection_reason"} else {}
    return result


def scenario_run_row(run_id):
    with connect() as connection:
        row = connection.execute(
            "SELECT * FROM scenario_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
    if not row:
        return None
    return parse_scenario_json_keys(dict(row))


class ScenarioDeps:
    """Jembatan antara Runner (logika) dan kondisi lab nyata."""

    def __init__(self):
        self.extra_quarantine_budget = DEMO_RECOVERY_DELAY_SECONDS * 2 + 90

    # run helpers

    def allowed_hosts(self):
        return set(ALLOWED_HOSTS)

    def run(self, run_id):
        return scenario_run_row(run_id)

    def cancelled(self, run_id):
        row = self.run(run_id)
        return row is None or bool(row.get("cancel_requested"))

    def paused(self, run_id):
        row = self.run(run_id)
        return bool(row and row.get("pause_requested"))

    def enter_state(self, run_id, state, detail=None):
        row = self.run(run_id)
        if row is None:
            raise ValueError("run_not_found")
        current = row.get("state")
        if current == state:
            return
        if current in scenario_module.TERMINAL_STATES:
            return
        if not scenario_module.valid_transition(current, state):
            raise ValueError(f"invalid_transition:{current}->{state}")
        if state in scenario_module.TERMINAL_STATES:
            with connect() as connection:
                connection.execute(
                    "UPDATE scenario_runs SET state = ?, completed_at = ?, updated_at = ?, detail = ? WHERE run_id = ?",
                    (state, _iso_now(), _iso_now(), json.dumps(detail or {}), run_id),
                )
            return
        with connect() as connection:
            connection.execute(
                "UPDATE scenario_runs SET state = ?, updated_at = ?, detail = ? WHERE run_id = ?",
                (state, _iso_now(), json.dumps(detail or {}), run_id),
            )

    def record_step(self, run_id, state, detail):
        with connect() as connection:
            row = connection.execute(
                "SELECT steps FROM scenario_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            history = json.loads(row["steps"]) if row and row["steps"] else []
            history.append({
                "state": state,
                "detail": detail,
                "timestamp": _iso_now(),
            })
            connection.execute(
                "UPDATE scenario_runs SET steps = ?, updated_at = ? WHERE run_id = ?",
                (json.dumps(history, ensure_ascii=False), _iso_now(), run_id),
            )
        return {"step_count": len(history)}

    def record_evidence(self, run_id, event_ref):
        with connect() as connection:
            row = connection.execute(
                "SELECT evidence_ids FROM scenario_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            ids = json.loads(row["evidence_ids"]) if row and row["evidence_ids"] else []
            payload = {key: value for key, value in event_ref.items() if key != "detail"}
            ids.append(payload)
            connection.execute(
                "UPDATE scenario_runs SET evidence_ids = ?, updated_at = ? WHERE run_id = ?",
                (json.dumps(ids, ensure_ascii=False), _iso_now(), run_id),
            )

    def record_policy_context(self, run_id, detail):
        with connect() as connection:
            row = connection.execute(
                "SELECT policy_context FROM scenario_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            current = json.loads(row["policy_context"]) if row and row["policy_context"] else {}
            current["evidence_validation"] = {key: value for key, value in detail.items() if key != "detail"}
            connection.execute(
                "UPDATE scenario_runs SET policy_context = ?, updated_at = ? WHERE run_id = ?",
                (json.dumps(current, ensure_ascii=False), _iso_now(), run_id),
            )

    def read_metrics(self, run_id):
        row = self.run(run_id)
        return (row or {}).get("metrics") or {}

    def write_metrics(self, run_id, metrics):
        with connect() as connection:
            connection.execute(
                "UPDATE scenario_runs SET metrics = ?, updated_at = ? WHERE run_id = ?",
                (json.dumps(metrics, ensure_ascii=False), _iso_now(), run_id),
            )

    def finalize_metrics(self, run_id):
        row = self.run(run_id)
        if not row:
            return
        metrics = row.get("metrics") or {}
        latencies = metrics.setdefault("latencies", {})
        steps = row.get("steps") or []
        stamp_of = {}
        for step in steps:
            stamp_of.setdefault(step.get("state"), step.get("timestamp"))
        def span(start_state, end_state):
            try:
                parse = lambda value: datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                end = parse(stamp_of.get(end_state))
                start = parse(stamp_of.get(start_state))
                return int((end - start).total_seconds() * 1000)
            except (TypeError, ValueError):
                return None
        containment = span("POLICY_APPROVED", "TARGET_DRAINED")
        recovery = span("TARGET_DRAINED", "RECOVERY")
        total = None
        try:
            total = int(
                (
                    datetime.fromisoformat(str(row.get("completed_at") or _iso_now()).replace("Z", "+00:00"))
                    - datetime.fromisoformat(str(row.get("created_at")).replace("Z", "+00:00"))
                ).total_seconds() * 1000
            )
        except (TypeError, ValueError):
            total = None
        if containment is not None:
            latencies["containment_ms"] = containment
        latencies["recovery_ms"] = recovery if recovery is not None else None
        latencies["total_ms"] = total
        metrics["final_state"] = row.get("state")
        self.write_metrics(run_id, metrics)

    # probes

    def backend_states(self):
        return backend_states()

    def service_probe(self):
        url = SERVICE_PROBE_URL if SERVICE_PROBE_URL.endswith("/") else SERVICE_PROBE_URL + "/"
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                body = response.read(512).decode("utf-8", errors="replace")
                backend = None
                for host in sorted(ALLOWED_HOSTS):
                    if f"response from {host}" in body:
                        backend = host
                        break
                return {"status": "allowed", "code": response.status, "backend": backend}
        except (OSError, urllib.error.URLError, TimeoutError):
            return {"status": "error", "code": None, "backend": None}

    def denied_probe(self, run):
        run_id = (run or {}).get("run_id")
        url = f"{APP_BASE_URLS[run['target']]}/files/.env"
        headers = {}
        if run_id:
            headers["X-Defnett-Scenario"] = run_id
            headers["X-Defnett-Origin"] = "simulation"
        try:
            request = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(request, timeout=3) as response:
                return {"status": "allowed" if response.status == 200 else "denied", "code": response.status, "path": ".env"}
        except urllib.error.HTTPError as error:
            return {"status": "denied", "code": error.code, "path": ".env"}
        except (OSError, urllib.error.URLError, TimeoutError) as error:
            return {"status": "error", "code": None, "path": ".env", "detail": type(error).__name__}

    def _post_fixture(self, run, route, body):
        run_id = (run or {}).get("run_id")
        url = f"{APP_BASE_URLS[run['target']]}{route}"
        headers = {"Content-Type": "application/json"}
        if run_id:
            headers["X-Defnett-Scenario"] = run_id
            headers["X-Defnett-Origin"] = "simulation"
        try:
            request = urllib.request.Request(
                url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST"
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read())
                return {
                    "accepted": response.status == 201 and payload.get("accepted") is True,
                    "path": payload.get("path"),
                    "written_at": payload.get("written_at"),
                    "detail": payload.get("detail"),
                }
        except urllib.error.HTTPError as error:
            try:
                payload = json.loads(error.read())
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = {}
            return {"accepted": False, "detail": f"HTTP {error.code}: {payload.get('error', '')}"}
        except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            return {"accepted": False, "detail": type(error).__name__}

    def fixture_write(self, run):
        """Tulis fixture lab sesuai skenario: canary atau catatan jinak."""
        scenario = (run or {}).get("scenario")
        if scenario == "containment_blocked_evidence_invalid":
            return self._post_fixture(run, "/lab/fixture/note", {"kind": "note"})
        return self._post_fixture(run, "/lab/fixture/canary", {"kind": "canary"})

    def wait_for_canary_event(self, run, path, since_iso, timeout_seconds):
        deadline = time.time() + max(5, float(timeout_seconds))
        while time.time() < deadline:
            with connect() as connection:
                row = connection.execute(
                    """SELECT id, timestamp, host_id, path, event_type, p_attack, risk, level,
                              integrity_hash, trajectory_id
                       FROM events
                       WHERE host_id = ? AND path = ? AND timestamp >= ?
                             AND event_type IN ('file_created', 'file_modified') AND new_hash IS NOT NULL
                       ORDER BY rowid ASC LIMIT 1""",
                    (run["target"], path, since_iso),
                ).fetchone()
            if row:
                return dict(row)
            time.sleep(0.5)
        return None

    # gate / evidence

    def validate_evidence(self, run):
        fresh = self.run(run["run_id"]) or run
        evidences = (fresh.get("evidence_ids") or [])
        if not evidences:
            return {
                "evidence_valid": False,
                "detail": "Belum ada bukti FIM; validasi gagal.",
            }
        latest = evidences[-1]
        event_id = latest.get("id")
        row = find_event(event_id) if event_id else None
        if not row:
            return {"evidence_valid": False, "detail": "Event bukti tidak ditemukan."}
        synthetic_event = {
            "content_signal": bool(row.get("content_signal")),
            "indicator": "DEFNETT_LAB_CANARY" if row.get("content_signal") else None,
            "host_id": row.get("host_id"),
            "path": row.get("path"),
            "event_type": row.get("event_type"),
            "new_hash": row.get("new_hash"),
        }
        evidence_valid = is_canary_detection(synthetic_event)
        return {
            "evidence_valid": bool(evidence_valid),
            "event_id": event_id,
            "event_type": row.get("event_type"),
            "path": row.get("path"),
            "content_signal": bool(row.get("content_signal")),
            "risk": row.get("risk"),
            "level": row.get("level"),
            "integrity_hash": row.get("integrity_hash"),
            "trajectory_id": row.get("trajectory_id"),
            "detail": "Bukti lulus kriteria canary lab." if evidence_valid else "Bukti tidak memenuhi kriteria canary lab.",
        }

    def run_policy_gate(self, run):
        detail_row = self.validate_evidence(run)
        evidence_valid = bool(detail_row.get("evidence_valid"))
        decision = run_policy_gate_for(
            run["target"],
            event_context={
                "event_type": detail_row.get("event_type"),
                "path": detail_row.get("path"),
                "old_hash": None,
                "new_hash": "sha256" if evidence_valid else None,
                "content_signal": bool(detail_row.get("content_signal")),
                "indicator": "DEFNETT_LAB_CANARY" if evidence_valid else None,
                "risk": detail_row.get("risk"),
                "level": detail_row.get("level"),
            },
            evidence_valid=evidence_valid,
            run_id=run["run_id"],
            initiator="scenario_driver",
        )
        return decision

    def record_decision(self, run_id, decision):
        # Keputusan sudah direkam oleh run_policy_gate_for saat evaluasi;
        # di sini cukup baca keputusan terakhir untuk dikembalikan ke runner.
        del decision
        with connect() as connection:
            row = connection.execute(
                "SELECT decision, reasons FROM policy_decisions WHERE run_id = ? ORDER BY id DESC LIMIT 1",
                (run_id,),
            ).fetchone()
        if not row:
            return {}
        try:
            reasons = json.loads(row["reasons"])
        except (json.JSONDecodeError, TypeError):
            reasons = row["reasons"]
        return {"decision": row["decision"], "reasons": reasons}

    def latest_decision(self, run_id):
        return self.record_decision(run_id, None)

    def persist_rejection(self, run_id):
        with connect() as connection:
            row = connection.execute(
                "SELECT decision, reasons FROM policy_decisions WHERE run_id = ? ORDER BY id DESC LIMIT 1",
                (run_id,),
            ).fetchone()
            reasons = json.loads(row["reasons"]) if row else []
            # rejection_reason hanya memuat kode check yang GAGAL — versi lama
            # memuat seluruh kode (lulus + gagal) sehingga "ditolak: EVIDENCE_VALID"
            # pun bisa muncul di dashboard; sekarang tampak benar.
            reason_codes = [
                reason.get("code")
                for reason in reasons
                if isinstance(reason, dict) and not reason.get("passed")
            ]
            connection.execute(
                "UPDATE scenario_runs SET rejection_reason = ?, updated_at = ? WHERE run_id = ?",
                (json.dumps(reason_codes), _iso_now(), run_id),
            )
        return {"rejection": reason_codes}

    def mark_remediation_intent(self, run):
        fresh = self.run(run["run_id"]) or run
        evidence_ids = fresh.get("evidence_ids") or []
        latest = (evidence_ids[-1] or {}).get("id") if evidence_ids else None
        row = find_event(latest) if latest else None
        if not row:
            raise RuntimeError("canary_event_missing_for_playbook")
        synthetic = {
            "host_id": row["host_id"],
            "event_type": row["event_type"],
            "path": row["path"],
            "old_hash": row["old_hash"],
            "new_hash": row["new_hash"],
            "content_signal": bool(row["content_signal"]),
            "indicator": "DEFNETT_LAB_CANARY" if row["content_signal"] else None,
        }
        threading.Thread(
            target=finish_canary_response,
            args=(synthetic, latest),
            name=f"scenario-playbook-{run['run_id'][:8]}",
            daemon=True,
        ).start()
        return {"detail": f"Playbook canary dipicu untuk event bukti {latest}."}

    def wait_remediation_stage(self, run_id, stages, timeout_seconds):
        run_row = self.run(run_id)
        if run_row is None:
            return {"stage": None, "detail": "run_missing"}
        evidence_ids = run_row.get("evidence_ids") or []
        event_id = (evidence_ids[-1] or {}).get("id") if evidence_ids else None
        deadline = time.time() + max(5, float(timeout_seconds))
        while time.time() < deadline:
            if self.cancelled(run_id):
                return {"stage": scenario_module.CANCEL_SENTINEL}
            row = remediation_by_event(event_id) if event_id else None
            if row:
                current = row.get("status")
                history = [step.get("stage") for step in (row.get("steps") or [])]
                if current in stages:
                    return {"stage": current, "detail": row.get("detail")}
                seen = [stage for stage in history if stage in stages]
                if seen:
                    return {"stage": seen[0], "detail": row.get("detail")}
            time.sleep(0.5)
        label = sorted(s for s in stages if s != scenario_module.CANCEL_SENTINEL)
        return {"stage": None, "detail": f"timeout menunggu status dalam {label}"}

    def remediation_detail(self, run_id):
        run_row = self.run(run_id)
        evidence_ids = (run_row or {}).get("evidence_ids") or []
        event_id = (evidence_ids[-1] or {}).get("id") if evidence_ids else None
        return remediation_by_event(event_id) if event_id else None

    def quarantine_timeout(self):
        return self.extra_quarantine_budget

    # fixture kondisi lab untuk skenario negatif

    def prepare_survivor_down(self, run):
        """Simulasi survivor tidak sehat dengan mengeluarkannya dari rotasi.

        Status HAProxy berubah menjadi MAINT, bukti yang dibaca Policy Gate
        jadi SURVIVOR_NOT_HEALTHY. Restore selalu dilakukan di akhir run.
        """
        survivor = (run or {}).get("survivor")
        if not survivor:
            return {"status": "skipped"}
        try:
            haproxy_command(f"disable server defnett_servers/{survivor}")
            confirmed = wait_for_backend(survivor, False, attempts=10)
            return {
                "status": "simulated_down" if confirmed else "unconfirmed",
                "survivor": survivor,
            }
        except (OSError, socket.timeout, UnicodeError) as error:
            return {"status": "error", "detail": type(error).__name__}

    def restore_survivor(self, run):
        """Idempoten: kembalikan survivor ke rotasi; dipanggil di akhir/finally."""
        survivor = (run or {}).get("survivor")
        if not survivor:
            return {"status": "skipped"}
        try:
            haproxy_command(f"enable server defnett_servers/{survivor}")
            confirmed = wait_for_backend(survivor, True, attempts=20)
            return {
                "status": "restored" if confirmed else "unconfirmed",
                "survivor": survivor,
            }
        except (OSError, socket.timeout, UnicodeError) as error:
            return {"status": "error", "detail": type(error).__name__}


SCENARIO_DEPS = None
SCENARIO_RUNNER = None
SCENARIO_THREADS = {}


def wire_scenario_components():
    global SCENARIO_DEPS, SCENARIO_RUNNER
    if SCENARIO_DEPS is not None:
        return
    SCENARIO_DEPS = ScenarioDeps()
    config = {
        "step_wait_seconds": float(os.environ.get("SCENARIO_STEP_WAIT_SECONDS", "150")),
        "probe_count": int(os.environ.get("SCENARIO_PROBE_COUNT", "4")),
        "isolated_probe_count": int(os.environ.get("SCENARIO_ISOLATED_PROBE_COUNT", "6")),
        "recovery_probe_count": int(os.environ.get("SCENARIO_RECOVERY_PROBE_COUNT", "6")),
        "probe_interval_seconds": float(os.environ.get("SCENARIO_PROBE_INTERVAL", "0.4")),
    }
    SCENARIO_RUNNER = scenario_module.Runner(SCENARIO_DEPS, config)


def scenario_summary(row):
    return parse_scenario_json_keys(dict(row))


def list_scenario_runs(limit=20):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM scenario_runs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [scenario_summary(dict(row)) for row in rows]


def active_scenario_runs():
    with connect() as connection:
        rows = connection.execute(
            """SELECT run_id FROM scenario_runs
               WHERE state NOT IN (?, ?, ?)""",
            (scenario_module.STATE_COMPLETE, scenario_module.STATE_FAILED, scenario_module.STATE_CANCELLED),
        ).fetchall()
    return [row["run_id"] for row in rows]


def scenario_run_pending_for(host_id):
    """Skenario aktif menargetkan host ini? Kunci klaritas driver skenario."""
    with connect() as connection:
        row = connection.execute(
            """SELECT run_id FROM scenario_runs
               WHERE target = ? AND state NOT IN (?, ?, ?)
               ORDER BY created_at ASC LIMIT 1""",
            (host_id, scenario_module.STATE_COMPLETE, scenario_module.STATE_FAILED, scenario_module.STATE_CANCELLED),
        ).fetchone()
    return row["run_id"] if row else None


def fail_stale_scenario_runs(reason):
    for run_id in active_scenario_runs():
        with connect() as connection:
            connection.execute(
                "UPDATE scenario_runs SET state = ?, completed_at = ?, updated_at = ?, rejection_reason = ? WHERE run_id = ?",
                (
                    scenario_module.STATE_FAILED, _iso_now(), _iso_now(),
                    f"collector_restarted:{reason}", run_id,
                ),
            )


def start_scenario(scenario_name, requested_target=None):
    wire_scenario_components()
    if not SCENARIO_RUNNER.valid_scenario(scenario_name):
        return None, {"error": "unknown_scenario", "scenarios": sorted(scenario_module.SCENARIOS)}
    target = requested_target if requested_target in ALLOWED_HOSTS else "server-a"
    survivor = "server-b" if target == "server-a" else "server-a"
    if scenario_name == "containment_allowed" and not ENABLE_LAB_AUTOREPAIR:
        return None, {"error": "playbook_mode_inactive", "detail": "Jalankan lab dengan overlay compose.canary.yaml untuk skenario containment_allowed."}
    if active_scenario_runs():
        return None, {"error": "scenario_in_progress", "detail": "Tunggu run aktif selesai atau jalankan cancel."}
    run_id = str(uuid.uuid4())
    now = _iso_now()
    with connect() as connection:
        connection.execute(
            """INSERT INTO scenario_runs
               (run_id, scenario, target, survivor, state, created_at, updated_at,
                completed_at, steps, evidence_ids, metrics, policy_context,
                rejection_reason, pause_requested, cancel_requested)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL, '[]', '[]', '{}', '{}', NULL, 0, 0)""",
            (run_id, scenario_name, target, survivor, scenario_module.STATE_IDLE, now, now),
        )
    run_row = scenario_run_row(run_id)

    def worker():
        try:
            SCENARIO_RUNNER.execute(run_row)
        except Exception as error:  # fail-safe thread
            SCENARIO_DEPS.enter_state(
                run_id, scenario_module.STATE_FAILED,
                detail={"detail": f"{type(error).__name__}: {error}"},
            )
        finally:
            with connect() as connection:
                row = connection.execute(
                    "SELECT state FROM scenario_runs WHERE run_id = ?", (run_id,)
                ).fetchone()
                if row and row["state"] not in scenario_module.TERMINAL_STATES:
                    connection.execute(
                        "UPDATE scenario_runs SET state = ?, completed_at = ?, updated_at = ? WHERE run_id = ?",
                        (scenario_module.STATE_FAILED, _iso_now(), _iso_now(), run_id),
                    )
            try:
                SCENARIO_DEPS.finalize_metrics(run_id)
            except Exception:
                pass
            SCENARIO_THREADS.pop(run_id, None)
        return

    thread = threading.Thread(target=worker, name=f"scenario-{run_id[:8]}", daemon=True)
    SCENARIO_THREADS[run_id] = thread
    thread.start()
    return run_row, None


def pause_resume_cancel(run_id, action):
    wire_scenario_components()
    row = scenario_run_row(run_id)
    if row is None:
        return None, {"error": "run_not_found"}
    if row["state"] in scenario_module.TERMINAL_STATES:
        return None, {"error": "run_already_finished", "state": row["state"]}
    if action == "pause":
        flag = "pause_requested"
    elif action == "resume":
        flag = "pause_requested"
    elif action == "cancel":
        flag = "cancel_requested"
    else:
        return None, {"error": "unknown_action"}
    value = 1 if action in {"pause", "cancel"} else 0
    with connect() as connection:
        connection.execute(
            f"UPDATE scenario_runs SET {flag} = ?, updated_at = ? WHERE run_id = ?",
            (value, _iso_now(), run_id),
        )
    return scenario_run_row(run_id), None


# ---------------------------------------------------------------------------
# Observability: dashboard + metrik
# ---------------------------------------------------------------------------


def remediation_health_summary():
    return {
        "status": "ready" if all(remediator_health(host) == "ready" for host in ALLOWED_HOSTS) else "unavailable",
        "by_host": {host: {"status": remediator_health(host)} for host in sorted(ALLOWED_HOSTS)},
    }


def scenario_active_summary():
    runs = list_scenario_runs(10)
    active = [run for run in runs if run["state"] not in scenario_module.TERMINAL_STATES]
    return {"active": active, "recent": runs}


def dashboard_state():
    remediations = remediation_rows(20)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "ACTIVE_LAB" if ENABLE_LAB_AUTOREPAIR else "DRY_RUN",
        "analysis": {
            "engine": "FIM + canary rules (heuristik) + Policy Gate deterministik",
            "model": "advisor_off" if llm_advisor.AdviserConfig().mode == "off" else f"advisor_{llm_advisor.AdviserConfig().mode}",
            "canary_response_enabled": ENABLE_LAB_AUTOREPAIR,
            "auto_repair_enabled": ENABLE_LAB_AUTOREPAIR,
            "demo_repair_host": DEMO_REPAIR_HOST,
            "demo_recovery_delay_seconds": DEMO_RECOVERY_DELAY_SECONDS,
            "demo_repair_delay_seconds": DEMO_RECOVERY_DELAY_SECONDS,
            "advisor": llm_advisor.AdviserConfig().snapshot(),
            "policy": policy.PolicyConfig().snapshot(),
        },
        "remediator": remediation_health_summary(),
        "backends": backend_states(),
        "agents": agent_states(),
        "remediation": remediations[0] if remediations else None,
        "remediations": remediations,
        "events": event_rows(40),
        "policy_decisions": recent_policy_decisions(10),
        "scenarios": scenario_active_summary(),
        "patrol_state": patrol_state().get("counters"),
    }


def scenario_metrics_runs(limit=50):
    runs = list_scenario_runs(limit)
    output = []
    for run in runs:
        metrics = run.get("metrics") or {}
        output.append({
            "run_id": run["run_id"],
            "scenario": run["scenario"],
            "target": run["target"],
            "survivor": run["survivor"],
            "state": run["state"],
            "created_at": run["created_at"],
            "completed_at": run.get("completed_at"),
            "rejection_reason": run.get("rejection_reason"),
            "latencies_ms": metrics.get("latencies") or {},
            "requests": metrics.get("requests") or {},
        })
    return output


def scenario_metrics_csv(limit=50):
    rows = scenario_metrics_runs(limit)
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "run_id", "scenario", "target", "survivor", "final_state",
        "created_at", "completed_at", "rejection_reason",
        "detection_ms", "containment_ms", "recovery_ms", "total_ms",
        "baseline_success", "baseline_total",
        "during_drain_success", "during_drain_total",
        "after_recovery_success", "after_recovery_total",
        "after_rejection_success", "after_rejection_total",
    ])
    for run in rows:
        latencies = run["latencies_ms"]
        requests = run["requests"]
        baseline = requests.get("baseline") or {}
        during = requests.get("during_drain") or {}
        after = requests.get("after_recovery") or {}
        rejected = requests.get("after_rejection") or {}
        writer.writerow([
            run["run_id"], run["scenario"], run["target"], run["survivor"], run["state"],
            run["created_at"], run.get("completed_at") or "",
            (run.get("rejection_reason") or ""),
            latencies.get("detection_ms", ""),
            latencies.get("containment_ms", ""),
            latencies.get("recovery_ms", ""),
            latencies.get("total_ms", ""),
            baseline.get("success", ""), baseline.get("total", ""),
            during.get("success", ""), during.get("total", ""),
            after.get("success", ""), after.get("total", ""),
            rejected.get("success", ""), rejected.get("total", ""),
        ])
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------


def token_valid(headers):
    if not INGEST_TOKEN:
        return True
    supplied = headers.get("X-Defnett-Token", "")
    return hmac.compare_digest(supplied.encode("utf-8"), INGEST_TOKEN)


RUN_ID_CHARS = set("0123456789abcdef-")


def is_safe_run_id(value):
    return isinstance(value, str) and 8 <= len(value) <= 64 and all(char in RUN_ID_CHARS for char in value)


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def respond_file(self, filename, content_type):
        try:
            body = (DASHBOARD_DIR / filename).read_bytes()
        except OSError:
            return self.respond(404, {"error": "dashboard_asset_not_found"})
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self, maximum=2_000_000):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > maximum:
            raise ValueError("invalid_body_size")
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in {"/", "/index.html"}:
            return self.respond_file("index.html", "text/html; charset=utf-8")
        if path == "/dashboard.css":
            return self.respond_file("dashboard.css", "text/css; charset=utf-8")
        if path == "/dashboard.js":
            return self.respond_file("dashboard.js", "text/javascript; charset=utf-8")
        if path == "/patrol.css":
            return self.respond_file("patrol.css", "text/css; charset=utf-8")
        if path == "/patrol.js":
            return self.respond_file("patrol.js", "text/javascript; charset=utf-8")
        if path == "/healthz":
            return self.respond(200, {"status": "ok"})
        if path == "/v1/dashboard":
            return self.respond(200, dashboard_state())
        if path == "/api/patrol/state":
            return self.respond(200, patrol_state())
        if path.startswith("/api/patrol/stream"):
            return self.stream_patrol_events()
        if path == "/v1/events":
            return self.respond(200, {"events": event_rows()})
        if path == "/v1/summary":
            events = event_rows(1000)
            counts = {}
            for event in events:
                counts[event["host_id"]] = counts.get(event["host_id"], 0) + 1
            return self.respond(200, {"event_count": len(events), "by_host": counts})
        if path == "/api/demo/scenarios":
            wire_scenario_components()
            return self.respond(200, {
                "scenarios": scenario_module.SCENARIOS,
                "runs": list_scenario_runs(20),
                "active_run_ids": active_scenario_runs(),
            })
        if path.startswith("/api/demo/scenarios/"):
            run_id = path[len("/api/demo/scenarios/"):]
            if not is_safe_run_id(run_id):
                return self.respond(400, {"error": "invalid_run_id"})
            row = scenario_run_row(run_id)
            if row is None:
                return self.respond(404, {"error": "run_not_found"})
            return self.respond(200, row)
        if path == "/api/demo/metrics":
            return self.respond(200, {"runs": scenario_metrics_runs(50)})
        if path == "/api/demo/metrics.csv":
            body = scenario_metrics_csv(50).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        return self.respond(404, {"error": "not_found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/v1/patrol/snapshot":
            if not token_valid(self.headers):
                return self.respond(403, {"error": "authentication_required"})
            return self.receive_patrol_snapshot()
        if path == "/api/patrol/events":
            if not token_valid(self.headers):
                return self.respond(403, {"error": "authentication_required"})
            return self.receive_patrol_event()
        if path == "/v1/agent/heartbeat":
            if not token_valid(self.headers):
                return self.respond(403, {"error": "authentication_required"})
            return self.receive_heartbeat()

        if path == "/api/demo/scenarios/start":
            return self.handle_scenario_start()
        parts = path.strip("/").split("/")
        if len(parts) == 5 and parts[:3] == ["api", "demo", "scenarios"] and parts[3] not in {"start"}:
            run_id, action = parts[3], parts[4]
            if not is_safe_run_id(run_id) or action not in {"pause", "resume", "cancel"}:
                return self.respond(400, {"error": "invalid_request"})
            row, error = pause_resume_cancel(run_id, action)
            if error:
                return self.respond(404 if error.get("error") == "run_not_found" else 409, error)
            return self.respond(200, {"accepted": True, "run": self.safe_run(row)})
        if path.startswith("/v1/lab/recover/"):
            if not ENABLE_LAB_AUTOREPAIR:
                return self.respond(403, {"error": "lab_drain_mode_disabled"})
            host_id = path.rsplit("/", 1)[-1]
            if host_id not in ALLOWED_HOSTS:
                return self.respond(404, {"error": "unknown_host"})
            try:
                haproxy_command(f"enable server defnett_servers/{host_id}")
                if not wait_for_backend(host_id, True):
                    return self.respond(409, {"error": "backend_not_healthy_after_enable", "host_id": host_id})
                print(f"operator action: enable {host_id}", flush=True)
                return self.respond(200, {
                    "mode": "ACTIVE_LAB", "action": f"ENABLE_{host_id.upper().replace('-', '_')}",
                    "host_id": host_id, "result": "backend_up",
                })
            except (OSError, socket.timeout, UnicodeError) as error:
                return self.respond(503, {"error": "haproxy_unavailable", "detail": type(error).__name__})
        if not token_valid(self.headers):
            return self.respond(403, {"error": "authentication_required"})
        if path != "/v1/events":
            return self.respond(404, {"error": "not_found"})
        return self.receive_event()

    def safe_run(self, row):
        if not row:
            return None
        return {key: row.get(key) for key in (
            "run_id", "scenario", "target", "survivor", "state",
            "created_at", "completed_at", "rejection_reason",
        )}

    def handle_scenario_start(self):
        try:
            payload = self.read_json_body(4096)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            return self.respond(400, {"error": str(error) or "invalid_body"})
        if not isinstance(payload, dict):
            return self.respond(400, {"error": "invalid_body"})
        scenario_name = payload.get("scenario")
        target = payload.get("target") if payload.get("target") in ALLOWED_HOSTS else None
        wire_scenario_components()
        run_row, error = start_scenario(scenario_name, target)
        if error:
            return self.respond(
                409 if error.get("error") in {"scenario_in_progress", "playbook_mode_inactive"} else 400,
                error,
            )
        return self.respond(202, {"accepted": True, "run": self.safe_run(run_row)})

    def receive_heartbeat(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2048:
                return self.respond(413, {"error": "invalid_body_size"})
            payload = json.loads(self.rfile.read(length))
            host_id = payload.get("host_id") if isinstance(payload, dict) else None
            if host_id not in ALLOWED_HOSTS:
                return self.respond(403, {"error": "unknown_host"})
            timestamp = datetime.now(timezone.utc).isoformat()
            with connect() as connection:
                connection.execute(
                    "INSERT INTO agent_status (host_id, last_seen) VALUES (?, ?) "
                    "ON CONFLICT(host_id) DO UPDATE SET last_seen = excluded.last_seen",
                    (host_id, timestamp),
                )
            return self.respond(202, {"accepted": True, "host_id": host_id})
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return self.respond(400, {"error": "invalid_heartbeat"})

    def receive_event(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 16384:
                return self.respond(413, {"error": "invalid_body_size"})
            event = json.loads(self.rfile.read(length))
            required = {"host_id", "source", "event_type", "path", "timestamp"}
            if not isinstance(event, dict) or not required.issubset(event):
                return self.respond(400, {"error": "missing_fields"})
            if event["host_id"] not in ALLOWED_HOSTS:
                return self.respond(403, {"error": "unknown_host"})
            if event["event_type"] not in {"file_created", "file_modified", "file_deleted"}:
                return self.respond(400, {"error": "unknown_event_type"})
            if "content_signal" in event and not isinstance(event["content_signal"], bool):
                return self.respond(400, {"error": "invalid_content_signal"})
            if not isinstance(event["path"], str) or len(event["path"]) > 2048:
                return self.respond(400, {"error": "invalid_path"})
            result = store_event(event)
            print(json.dumps({"accepted": True, **result}), flush=True)
            return self.respond(201, result)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, KeyError) as error:
            return self.respond(400, {"error": "invalid_event", "detail": str(error)})
        except Exception as error:
            print(f"event storage failed: {error}", flush=True)
            return self.respond(500, {"error": "storage_failure"})

    def receive_patrol_snapshot(self):
        try:
            payload = self.read_json_body()
            host_id = payload.get("host_id") if isinstance(payload, dict) else None
            files = payload.get("files") if isinstance(payload, dict) else None
            if not isinstance(host_id, str) or host_id not in ALLOWED_HOSTS or not isinstance(files, list):
                return self.respond(400, {"error": "invalid_patrol_snapshot"})
            store_patrol_snapshot(host_id, files, payload.get("timestamp"))
            return self.respond(202, {"accepted": True, "host_id": host_id, "file_count": len(files)})
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            return self.respond(400, {"error": str(error) or "invalid_patrol_snapshot"})

    def receive_patrol_event(self):
        try:
            payload = self.read_json_body(16384)
            if not isinstance(payload, dict):
                return self.respond(400, {"error": "invalid_patrol_event"})
            event_id = store_patrol_event(payload)
            return self.respond(202, {"accepted": True, "id": event_id})
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            return self.respond(400, {"error": str(error) or "invalid_patrol_event"})

    def stream_patrol_events(self):
        query = parse_qs(urlsplit(self.path).query)
        try:
            last_id = max(0, int(self.headers.get("Last-Event-ID", query.get("after", ["0"])[0])))
        except ValueError:
            last_id = 0
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            while True:
                rows = patrol_events(last_id, 100)
                for event in rows:
                    last_id = event["id"]
                    message = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
                    self.wfile.write(f"id: {last_id}\nevent: patrol\ndata: {message}\n\n".encode("utf-8"))
                if not rows:
                    self.wfile.write(b": heartbeat\n\n")
                self.wfile.flush()
                time.sleep(1)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} {format_string % args}", flush=True)


if __name__ == "__main__":
    initialize()
    wire_scenario_components()
    fail_stale_scenario_runs("process restarted")
    ThreadingHTTPServer(("0.0.0.0", 8090), Handler).serve_forever()
