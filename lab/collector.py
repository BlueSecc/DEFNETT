"""Kolektor: menerima bukti, rantai hash, Policy Gate, dan antarmuka operator.

Tahap 1 (security boundary): kolektor hanya ANALISIS — tidak lagi memegang akses
HAProxy runtime maupun remediator. Event berisiko berhenti menjadi
PENDING_APPROVAL di tabel operator_approvals; satu-satunya proses yang boleh
mengeksekusi adalah executor terpisah, dan hanya untuk approval yang APPROVED.
"""
import hashlib
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
import zlib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import authority_client
import approvals
import db
import operator_auth
import policy_gate
import risk_engine
import trajectory
import tls_support

DB_PATH = db.DB_PATH
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard")
ALLOWED_HOSTS = db.ALLOWED_HOSTS
DEMO_REPAIR_HOST = os.environ.get("DEMO_REPAIR_HOST", "server-a")
DEMO_REPAIR_DELAY_SECONDS = max(0, int(os.environ.get("DEMO_REPAIR_DELAY_SECONDS", "0")))
TRAFFIC_PROBE_ENABLED = os.environ.get("TRAFFIC_PROBE_ENABLED", "true").lower() == "true"
TRAFFIC_PROBE_URL = os.environ.get("TRAFFIC_PROBE_URL", "http://haproxy:8080/healthz")
OT_GATEWAY_HOST = os.environ.get("OT_GATEWAY_HOST", "")
OT_GATEWAY_PORT = int(os.environ.get("OT_GATEWAY_PORT", "5020"))
TRAFFIC_PROBE_INTERVAL = max(0.2, float(os.environ.get("TRAFFIC_PROBE_INTERVAL", "1")))
EXECUTOR_URL = os.environ.get("EXECUTOR_URL", "http://executor:8092").rstrip("/")
EXECUTOR_TOKEN = os.environ.get("EXECUTOR_API_TOKEN", "")
IMPACT_CIA = (1, 3, 2)
IMPACT = sum(IMPACT_CIA) / 3
MAX_BODY_BYTES = 64_000_000
MAX_INVENTORY_DIRECTORIES = 200_000
MAX_INVENTORY_ENTRIES = 1_000_000
MAX_LISTING_ENTRIES = 5000
API_TOKEN = os.environ.get("LAB_API_TOKEN", "")
OT_API_TOKEN = os.environ.get("OT_API_TOKEN", "")
OT_ALLOWED_DEVICE_ID = os.environ.get("OT_ALLOWED_DEVICE_ID", "OT-SIM-01")
APPROVAL_TEST_ADAPTER = None
AGENT_PATHS = {"/v1/events", "/v1/patrol/snapshot", "/v1/patrol/inventory", "/api/patrol/events", "/v1/agent/heartbeat"}
ENTRY_WINDOW_SECONDS = 600
CHAIN_LOCK = threading.Lock()
MAX_OPEN_PORTS = 32
OPEN_PORTS = {}
FS_ENTRY_KINDS = {"dir", "file", "link", "other", "virtual"}
FS_KIND_ORDER = {"dir": 0, "virtual": 1, "link": 2, "file": 3, "other": 4}
ASSET_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/dashboard.css": ("dashboard.css", "text/css; charset=utf-8"),
    "/dashboard.js": ("dashboard.js", "text/javascript; charset=utf-8"),
    "/patrol.css": ("patrol.css", "text/css; charset=utf-8"),
    "/patrol.js": ("patrol.js", "text/javascript; charset=utf-8"),
}
SESSION_REQUIRED_GET = {
    "/v1/dashboard", "/v1/approvals", "/api/patrol/state", "/v1/fsmap", "/v1/evidence/verify",
    "/v1/events", "/v1/summary", "/v1/trajectories", "/api/patrol/fs", "/api/patrol/stream",
}
LAB_ATTACK_VECTORS = {"ssh": 22, "web": 80}


def connect():
    return db.connect(DB_PATH)


def approval_request(path, *, method="GET", payload=None, cookie=None, csrf=None, internal=False):
    token = authority_client.COLLECTOR_TOKEN if internal else None
    try:
        return authority_client.request(
            path, method=method, payload=payload, token=token, cookie=cookie,
            csrf=csrf, timeout=4,
        )
    except (OSError, urllib.error.URLError, TimeoutError, ValueError):
        return 503, {"error": "approval_authority_unavailable"}, None


def create_approval(action, host_id, path, parameters, event_id=None, created_by="policy_gate", reason=""):
    if APPROVAL_TEST_ADAPTER is not None:
        return APPROVAL_TEST_ADAPTER.create(action, host_id, path, parameters, event_id, created_by, reason)
    result, _ = authority_client.require(
        "/internal/approvals", method="POST", token=authority_client.COLLECTOR_TOKEN,
        payload={"action": action, "host_id": host_id, "path": path,
                 "parameters": parameters, "event_id": event_id, "reason": reason}, timeout=5,
    )
    return result["approval"]


def list_approvals(limit=30):
    if APPROVAL_TEST_ADAPTER is not None:
        return APPROVAL_TEST_ADAPTER.list_approvals(limit)
    result, _ = authority_client.require(
        "/internal/approvals", token=authority_client.COLLECTOR_TOKEN, timeout=3,
    )
    if not isinstance(result.get("approvals"), list):
        raise RuntimeError(f"approval_authority_invalid:{result.get('error', 'no_approvals')}")
    return result["approvals"][:max(1, min(int(limit), 50))]


def get_approval(approval_id):
    if APPROVAL_TEST_ADAPTER is not None:
        return APPROVAL_TEST_ADAPTER.get(approval_id)
    result, _ = authority_client.require(
        f"/internal/approval/{approval_id}", token=authority_client.COLLECTOR_TOKEN, timeout=3,
    )
    return result["approval"]


def approve_via_authority(approval_id, actor, cookie="", csrf=""):
    if APPROVAL_TEST_ADAPTER is not None:
        return APPROVAL_TEST_ADAPTER.approve(approval_id, actor)
    result, _ = authority_client.require(
        f"/v1/approvals/{approval_id}/approve", method="POST", cookie=cookie, csrf=csrf, timeout=4,
    )
    return result["approval"]


def restored_hashes():
    if APPROVAL_TEST_ADAPTER is not None:
        return APPROVAL_TEST_ADAPTER.restored_hashes()
    result, _ = authority_client.require(
        "/internal/restored-hashes", method="POST", payload={}, token=authority_client.COLLECTOR_TOKEN, timeout=3,
    )
    return {(item["host_id"], item["path"]): item["sha256"] for item in result["restored_hashes"]}


def authority_identity(cookie):
    if APPROVAL_TEST_ADAPTER is not None:
        return operator_auth.get_session(parsed_cookie(cookie).get("defnett_session"))
    status, payload, _ = approval_request("/v1/operator/whoami", cookie=cookie)
    return payload if status == 200 and payload.get("authenticated") else None


def authority_csrf_ok(headers, identity):
    if not identity:
        return False
    return hmac.compare_digest(headers.get("X-DEFNETT-CSRF", ""), identity.get("csrf", ""))


def authority_authorized(identity, required="viewer"):
    roles = {"viewer": 1, "operator": 2}
    return bool(identity and roles.get(identity.get("role"), 0) >= roles.get(required, 99))


def initialize():
    db.initialize(DB_PATH)


def evaluate(event):
    if event.get("event_type") in {"OT_MODBUS_TRANSACTION", "OT_FRAME_REJECTED"}:
        denied = event.get("policy_decision") == "DENY" or event.get("event_type") == "OT_FRAME_REJECTED"
        probability = 0.85 if denied else 0.05
        risk = round(probability * IMPACT, 3)
        return probability, risk, 2 if denied else 0, "operator_review" if denied else "record", "ot_policy_violation" if denied else "ot_policy_allowed"
    if policy_gate.is_canary_detection(event):
        probability = 0.99
        risk = round(probability * IMPACT, 3)
        return probability, risk, 3, "operator_approval_containment", "lab_canary_match"
    if policy_gate.is_key_detection(event):
        probability = 0.99
        risk = round(probability * IMPACT, 3)
        return probability, risk, 3, "operator_approval_restore_keys", "lab_key_match"

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


TRAFFIC_PHASES = ("before", "during", "after")
TRAFFIC_STAGE_PHASE = {
    "EXECUTING": "before",
    "ISOLATION_CONFIRMED": "during", "ISOLATION_UNCONFIRMED": "during",
    "REPAIRING": "during", "MASTER_UNTRUSTED": "during",
    "VERIFYING": "during", "REJOINING": "during",
    "EXECUTION_FAILED": "during", "HEALTH_CHECK_FAILED": "during",
    "REPAIRED": "after",
}
TRAFFIC_LOCK = threading.Lock()


def _traffic_bucket():
    return {"ok": 0, "fail": 0, "by_host": {host: 0 for host in sorted(ALLOWED_HOSTS)}, "first_at": None, "last_at": None}


TRAFFIC = {"phase": "before", "run_id": None, "buckets": {phase: _traffic_bucket() for phase in TRAFFIC_PHASES}}


def traffic_enter_stage(event_id, stage):
    """Pindahkan fase hitungan trafik mengikuti tahap playbook yang tercatat."""
    with TRAFFIC_LOCK:
        if stage == "DETECTED":
            if TRAFFIC["run_id"] == event_id:
                return
            if TRAFFIC["phase"] == "after":
                TRAFFIC["buckets"]["before"] = TRAFFIC["buckets"]["after"]
            TRAFFIC["buckets"]["during"] = _traffic_bucket()
            TRAFFIC["buckets"]["after"] = _traffic_bucket()
            TRAFFIC["phase"] = "before"
            TRAFFIC["run_id"] = event_id
        elif TRAFFIC["run_id"] == event_id and stage in TRAFFIC_STAGE_PHASE:
            TRAFFIC["phase"] = TRAFFIC_STAGE_PHASE[stage]


def traffic_record(ok, host_id=None):
    now = datetime.now(timezone.utc).isoformat()
    with TRAFFIC_LOCK:
        bucket = TRAFFIC["buckets"][TRAFFIC["phase"]]
        bucket["ok" if ok else "fail"] += 1
        if ok and host_id in bucket["by_host"]:
            bucket["by_host"][host_id] += 1
        bucket["first_at"] = bucket["first_at"] or now
        bucket["last_at"] = now


def traffic_probe_once():
    sync_traffic_from_runs()
    host_id = None
    try:
        with urllib.request.urlopen(TRAFFIC_PROBE_URL, timeout=2) as response:
            ok = response.status == 200
            host_id = response.headers.get("X-DEFNETT-Host")
    except (urllib.error.URLError, OSError, TimeoutError, ValueError) as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        ok = False
    traffic_record(ok, host_id)


def traffic_probe_loop():
    while True:
        started = time.monotonic()
        traffic_probe_once()
        time.sleep(max(0.05, TRAFFIC_PROBE_INTERVAL - (time.monotonic() - started)))


def traffic_state():
    with TRAFFIC_LOCK:
        windows = {}
        for phase in TRAFFIC_PHASES:
            bucket = TRAFFIC["buckets"][phase]
            windows[phase] = {
                "ok": bucket["ok"], "fail": bucket["fail"], "total": bucket["ok"] + bucket["fail"],
                "by_host": dict(bucket["by_host"]),
                "first_at": bucket["first_at"], "last_at": bucket["last_at"],
            }
        return {
            "enabled": TRAFFIC_PROBE_ENABLED,
            "interval_seconds": TRAFFIC_PROBE_INTERVAL,
            "phase": TRAFFIC["phase"],
            "windows": windows,
        }


def sync_traffic_from_runs():
    """Fase trafik kini mengikuti tahap yang executor tulis di remediation_runs."""
    try:
        rows = remediation_rows(1)
    except sqlite3.Error:
        return
    if not rows:
        return
    run = rows[0]
    steps = run.get("steps") or []
    latest = steps[-1]["stage"] if steps else run["status"]
    traffic_enter_stage(run["event_id"], latest)


def format_duration(seconds):
    return f"{seconds // 60} menit" if seconds >= 60 and seconds % 60 == 0 else f"{seconds} detik"


def close_rejected_run(approval):
    """Tolak menutup insiden agar host tidak terkunci di DETECTED; tidak ada playbook yang berjalan."""
    if not approval or not approval.get("event_id"):
        return
    if approval.get("action") not in ("RESTORE_KEYS", "CONTAIN_CANARY"):
        return
    db.record_stage(
        approval["event_id"], "REJECTED",
        "Operator menolak playbook; tidak ada tindakan, file tetap seperti saat terdeteksi.",
        host_id=approval.get("host_id", ""), path=approval.get("path", ""), complete=True,
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
        try:
            row["entry"] = json.loads(row.pop("entry_json") or "null")
        except (json.JSONDecodeError, TypeError):
            row["entry"] = None
        row["metrics"] = run_metrics(row)
    return result


def _stage_stamp(run):
    stamps = {}
    for step in run["steps"]:
        try:
            stamps[step["stage"]] = datetime.fromisoformat(step["timestamp"])
        except (KeyError, TypeError, ValueError):
            continue
    return stamps


def run_metrics(run):
    """Waktu respons satu insiden; mendukung nama tahap baru dan lama."""
    stamps = _stage_stamp(run)

    def elapsed(start, end):
        if start not in stamps or end not in stamps:
            return None
        return round((stamps[end] - stamps[start]).total_seconds(), 2)

    recover = elapsed("EXECUTING", "REPAIRED") or elapsed("DETECTED", "REPAIRED")
    isolate = elapsed("EXECUTING", "ISOLATION_CONFIRMED") or elapsed("DETECTED", "ISOLATED")
    hold = DEMO_REPAIR_DELAY_SECONDS if repair_delay_applies(run["host_id"]) else 0
    return {
        "detect": run.get("detect_seconds"),
        "isolate": isolate,
        "recover": recover,
        "demo_hold": hold,
        "recover_without_hold": None if recover is None else round(max(0.0, recover - hold), 2),
    }


def recent_entry(host_id):
    """Login berhasil terakhir di host ini, dipakai sebagai dugaan jalur masuk insiden."""
    with connect() as connection:
        rows = connection.execute(
            """SELECT ts, actor, port, path FROM patrol_events
               WHERE host_id = ? AND action = 'login' AND status = 'allowed' AND port IS NOT NULL
               ORDER BY id DESC LIMIT 1""",
            (host_id,),
        ).fetchall()
    if not rows:
        return None
    entry = dict(rows[0])
    try:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(entry["ts"])).total_seconds()
    except ValueError:
        return None
    return entry if 0 <= age <= ENTRY_WINDOW_SECONDS else None


def verify_evidence():
    """Periksa rantai hash event: tautan antarbaris, hash isi, dan kecocokan kolom utama."""
    with connect() as connection:
        rows = connection.execute(
            """SELECT id, host_id, path, old_hash, new_hash, previous_hash, integrity_hash, canonical_json
               FROM events ORDER BY rowid"""
        ).fetchall()
        last_hash = connection.execute("SELECT last_hash FROM chain_state WHERE id = 1").fetchone()["last_hash"]

    def broken(row, reason):
        return {"status": "broken", "events": len(rows), "reason": reason, "event_id": row["id"] if row else None}

    previous = ""
    fully_verified = 0
    for row in rows:
        if row["previous_hash"] != previous:
            return broken(row, "chain_link_mismatch")
        canonical = row["canonical_json"]
        if canonical is not None:
            if hashlib.sha256((previous + canonical).encode("utf-8")).hexdigest() != row["integrity_hash"]:
                return broken(row, "content_hash_mismatch")
            recorded = json.loads(canonical)
            if any(recorded.get(key) != row[key] for key in ("host_id", "path", "old_hash", "new_hash")):
                return broken(row, "stored_field_mismatch")
            fully_verified += 1
        previous = row["integrity_hash"]
    if previous != last_hash:
        return broken(rows[-1] if rows else None, "chain_head_mismatch")
    return {"status": "ok", "events": len(rows), "fully_verified": fully_verified,
            "link_only": len(rows) - fully_verified}


def repair_delay_applies(target):
    return DEMO_REPAIR_HOST in ("all", target)


def executor_claimed(approval, actor):
    """Teruskan approval yang sudah APPROVED ke executor (HTTP, m2m token)."""
    if not EXECUTOR_TOKEN:
        raise RuntimeError("executor_http_disabled")
    request = urllib.request.Request(
        f"{EXECUTOR_URL}/v1/execute",
        data=json.dumps({"approval_id": approval["id"]}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {EXECUTOR_TOKEN}"},
        method="POST",
    )
    try:
        response_context = urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        status = error.code
        error.close()
        raise RuntimeError(f"executor_returned_http_{status}") from None
    with response_context as response:
        if response.status != 202:
            raise RuntimeError(f"executor_returned_http_{response.status}")
    db.write_audit(actor, "approval_submitted", f"{approval['action']}:{approval['host_id']}", f"approval={approval['id']}", "SUBMITTED")


def store_event(event):
    event_id = str(uuid.uuid4())
    parsed = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    timestamp = parsed.astimezone(timezone.utc).isoformat()
    p_attack, risk, level, recommendation, verdict = evaluate(event)
    restored = None
    if policy_gate.is_key_detection(event):
        try:
            restored = restored_hashes()
        except (OSError, RuntimeError, urllib.error.URLError, TimeoutError):
            print("approval authority unavailable while checking restored evidence; treating as unverified", flush=True)
    decision = policy_gate.decide(event, p_attack, risk, level, recommendation, restored_hashes=restored or None)
    with CHAIN_LOCK, connect() as connection:
        dedupe_key = event.get("dedupe_key")
        if isinstance(dedupe_key, str):
            existing = connection.execute("SELECT event_id FROM event_dedup WHERE dedupe_key = ?", (dedupe_key,)).fetchone()
            if existing:
                row = connection.execute("SELECT id, trajectory_id, integrity_hash FROM events WHERE id = ?", (existing["event_id"],)).fetchone()
                if row:
                    return {"event_id": row["id"], "trajectory_id": row["trajectory_id"], "duplicate": True,
                            "risk": risk, "level": level, "policy_category": decision["category"],
                            "integrity_hash": row["integrity_hash"]}
        trajectory_id, relationships = trajectory.assign(connection, event, event_id, timestamp)
        assessment = risk_engine.assess(
            event, threat_indicator_strength=p_attack * 100,
            asset_impact=event.get("asset_impact"),
            evidence_confidence=event.get("evidence_confidence", 90 if (event.get("new_hash") or event.get("raw_evidence_sha256")) else None),
            telemetry_quality=event.get("telemetry_quality", 75),
            correlation_strength=max((edge["confidence"] * 100 for edge in relationships), default=0),
            operational_context=event.get("operational_context_score"),
        )
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
                "policy_category": decision["category"],
                "policy_action": decision["action"],
                "policy_reasons": decision["reasons"],
                "risk_assessment": assessment,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
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
                content_signal, response_action, canonical_json,
                policy_category, policy_reasons, recommendation_json, risk_assessment_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id, trajectory_id, timestamp, event["host_id"], event["source"],
                event["event_type"], event["path"], event.get("old_hash"), event.get("new_hash"),
                previous_hash, integrity_hash, p_attack, IMPACT, risk, level,
                recommendation, verdict, "OPERATIONAL", int(bool(event.get("content_signal"))), "none",
                canonical, decision["category"], json.dumps(decision["reasons"]),
                json.dumps(decision, ensure_ascii=False), json.dumps(assessment, ensure_ascii=False),
            ),
        )
        if isinstance(dedupe_key, str):
            connection.execute("INSERT INTO event_dedup(dedupe_key,event_id,created_at) VALUES(?,?,?)", (dedupe_key, event_id, timestamp))
        connection.execute(
            "UPDATE chain_state SET last_hash = ? WHERE id = 1", (integrity_hash,)
        )
        for edge in relationships:
            connection.execute(
                """INSERT OR IGNORE INTO event_relationships
                   (source_event_id, target_event_id, relation, confidence, reason, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (edge["source_event_id"], edge["target_event_id"], edge["relation"],
                 edge["confidence"], edge["reason"], timestamp),
            )

    if event["event_type"] in {"file_created", "file_modified", "file_deleted"}:
        patrol_severity = "compromised" if level >= 3 else "suspicious" if level >= 2 else "safe"
        patrol_type = "patrol_check" if event["event_type"] == "file_created" and patrol_severity == "safe" else "alert"
        patrol_action = "delete" if event["event_type"] == "file_deleted" else "modify" if event["event_type"] == "file_modified" else "read"
        store_patrol_event({
            "type": patrol_type, "actor": "police", "action": patrol_action,
            "host_id": event["host_id"], "path": event["path"],
            "severity": patrol_severity, "hash_old": event.get("old_hash"),
            "hash_new": event.get("new_hash"), "status": "observed",
        })

    mode, response_action, approval_id = "OPERATIONAL", "none", None
    if decision["category"] == policy_gate.CATEGORY_PENDING_APPROVAL:
        survivor = "server-b" if event["host_id"] == "server-a" else "server-a"
        detect_seconds = event.get("detect_seconds")
        if not isinstance(detect_seconds, (int, float)) or isinstance(detect_seconds, bool) or not 0 <= detect_seconds <= 3600:
            detect_seconds = None
        parameters = {
            "artifact": decision["parameters"].get("artifact"),
            "survivor": survivor,
            "detect_seconds": detect_seconds,
            "entry": recent_entry(event["host_id"]),
            "delay_seconds": DEMO_REPAIR_DELAY_SECONDS if repair_delay_applies(event["host_id"]) else 0,
        }
        try:
            approval = create_approval(
            decision["action"], event["host_id"], event["path"], parameters,
            event_id=event_id, created_by="policy_gate",
            )
        except Exception as error:
            print(f"approval authority unavailable; event remains recorded without execution: {type(error).__name__}", flush=True)
            with connect() as connection:
                connection.execute("UPDATE events SET mode = ?, response_action = ? WHERE id = ?",
                                   ("AUTHORITY_UNAVAILABLE", "none", event_id))
            return {"event_id": event_id, "trajectory_id": trajectory_id, "relationships": relationships,
                    "risk": risk, "level": level, "recommendation": recommendation,
                    "advisor_verdict": verdict, "policy_category": decision["category"],
                    "policy_action": decision["action"], "mode": "AUTHORITY_UNAVAILABLE",
                    "response_action": "none", "approval_id": None,
                    "content_signal": bool(event.get("content_signal", False)), "integrity_hash": integrity_hash}
        with connect() as connection:
            connection.execute("UPDATE events SET approval_id = ? WHERE id = ?", (approval["id"], event_id))
        db.record_stage(
            event_id, "DETECTED",
            "Bukti terverifikasi; menunggu persetujuan operator sebelum playbook dijalankan.",
            host_id=event["host_id"], path=event["path"],
            detect_seconds=detect_seconds, entry=parameters["entry"],
        )
        mode, response_action = "PENDING_APPROVAL", f"pending_approval:{approval['id']}"
        with connect() as connection:
            connection.execute(
                "UPDATE events SET mode = ?, response_action = ? WHERE id = ?",
                (mode, response_action, event_id),
            )
        approval_id = approval["id"]

    return {
        "event_id": event_id,
        "trajectory_id": trajectory_id,
        "relationships": relationships,
        "risk": risk,
        "level": level,
        "recommendation": recommendation,
        "advisor_verdict": verdict,
        "policy_category": decision["category"],
        "policy_action": decision["action"],
        "mode": mode,
        "response_action": response_action,
        "approval_id": approval_id,
        "content_signal": bool(event.get("content_signal", False)),
        "integrity_hash": integrity_hash,
        "risk_assessment": assessment,
        "duplicate": False,
    }


def event_rows(limit=100):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
    result = [dict(row) for row in rows]
    for row in result:
        try:
            row["risk_assessment"] = json.loads(row.get("risk_assessment_json") or "null")
        except (json.JSONDecodeError, TypeError):
            row["risk_assessment"] = None
    return result


def patrol_events(after_id=0, limit=100):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM patrol_events WHERE id > ? ORDER BY id ASC LIMIT ?",
            (after_id, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def store_patrol_snapshot(host_id, files, scanned_at=None):
    if not isinstance(host_id, str) or host_id not in ALLOWED_HOSTS:
        raise ValueError("unknown_host")
    cleaned = []
    for item in files[:50000]:
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
        size = item.get("size")
        mtime = item.get("mtime")
        if not isinstance(size, int) or size < 0:
            size = None
        if not isinstance(mtime, str):
            mtime = None
        cleaned.append({"path": path, "sha256": digest, "size": size, "mtime": mtime})
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


def normalize_fs_path(value):
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096:
        raise ValueError("invalid_fs_path")
    parts = [part for part in value.split("/") if part and part != "."]
    if ".." in parts or "\x00" in value:
        raise ValueError("invalid_fs_path")
    return "/" + "/".join(parts)


def clean_fs_entry(entry):
    if not isinstance(entry, list) or len(entry) != 4:
        return None
    name, kind, size, mtime = entry
    if not isinstance(name, str) or not name or len(name) > 1024 or "/" in name or "\x00" in name:
        return None
    if kind not in FS_ENTRY_KINDS:
        return None
    return [
        name, kind,
        size if isinstance(size, int) and size >= 0 else None,
        mtime if isinstance(mtime, int) else None,
    ]


def store_fs_inventory(host_id, directories, scanned_at=None):
    if not isinstance(host_id, str) or host_id not in ALLOWED_HOSTS:
        raise ValueError("unknown_host")
    if not isinstance(directories, dict) or len(directories) > MAX_INVENTORY_DIRECTORIES:
        raise ValueError("invalid_inventory")
    rows = []
    entry_count = 0
    for raw_path, directory in directories.items():
        if not isinstance(directory, dict) or not isinstance(directory.get("entries"), list):
            raise ValueError("invalid_inventory")
        entries = [
            cleaned for cleaned in map(clean_fs_entry, directory["entries"])
            if cleaned is not None
        ]
        entry_count += len(entries)
        if entry_count > MAX_INVENTORY_ENTRIES:
            raise ValueError("inventory_too_large")
        rows.append((
            host_id, normalize_fs_path(raw_path), int(directory.get("denied") is True),
            json.dumps(entries, separators=(",", ":")),
        ))
    try:
        timestamp = datetime.fromisoformat(scanned_at.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except (AttributeError, TypeError, ValueError):
        timestamp = datetime.now(timezone.utc).isoformat()
    with connect() as connection:
        connection.execute("DELETE FROM patrol_fs_directories WHERE host_id = ?", (host_id,))
        connection.executemany(
            """INSERT OR REPLACE INTO patrol_fs_directories (host_id, path, denied, entries_json)
               VALUES (?, ?, ?, ?)""",
            rows,
        )
        connection.execute(
            """INSERT INTO patrol_fs_scans (host_id, scanned_at, directory_count, entry_count)
               VALUES (?, ?, ?, ?) ON CONFLICT(host_id) DO UPDATE SET
               scanned_at = excluded.scanned_at, directory_count = excluded.directory_count,
               entry_count = excluded.entry_count""",
            (host_id, timestamp, len(rows), entry_count),
        )
    return entry_count


def fs_listing(host_id, raw_path="/"):
    if host_id not in ALLOWED_HOSTS:
        raise ValueError("unknown_host")
    path = normalize_fs_path(raw_path)
    with connect() as connection:
        scan = connection.execute(
            "SELECT scanned_at, directory_count, entry_count FROM patrol_fs_scans WHERE host_id = ?",
            (host_id,),
        ).fetchone()
        row = connection.execute(
            "SELECT denied, entries_json FROM patrol_fs_directories WHERE host_id = ? AND path = ?",
            (host_id, path),
        ).fetchone()
    result = {
        "host_id": host_id, "path": path, "found": row is not None, "denied": False,
        "scanned_at": scan["scanned_at"] if scan else None,
        "directory_count": scan["directory_count"] if scan else 0,
        "entry_count": scan["entry_count"] if scan else 0,
        "total": 0, "entries": [],
    }
    if row is None:
        return result
    entries = sorted(
        json.loads(row["entries_json"]),
        key=lambda entry: (FS_KIND_ORDER[entry[1]], entry[0].casefold()),
    )
    result["denied"] = bool(row["denied"])
    result["total"] = len(entries)
    result["entries"] = [
        {"name": name, "type": kind, "size": size, "mtime": mtime}
        for name, kind, size, mtime in entries[:MAX_LISTING_ENTRIES]
    ]
    return result


def store_patrol_event(event):
    return db.store_patrol_event(event, allowed_hosts=ALLOWED_HOSTS)


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
                "size": item.get("size"),
                "mtime": item.get("mtime"),
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


def build_fs_tree(root="/"):
    """Build per-host filesystem trees from the latest agent snapshots."""
    with connect() as connection:
        snapshots = connection.execute(
            "SELECT host_id, scanned_at, files_json FROM patrol_snapshots ORDER BY host_id"
        ).fetchall()

    hosts = []
    for snapshot in snapshots:
        root_node = {"name": "/", "path": "/", "type": "directory", "children": []}
        nodes = {"": root_node}
        for item in json.loads(snapshot["files_json"]):
            relative = item.get("path", "")
            parts = Path(relative).parts
            if not relative or Path(relative).is_absolute() or ".." in parts:
                continue
            parent = ""
            for part in parts[:-1]:
                current = f"{parent}/{part}" if parent else part
                if current not in nodes:
                    node = {
                        "name": part, "path": f"/{current}", "type": "directory",
                        "children": [],
                    }
                    nodes[parent]["children"].append(node)
                    nodes[current] = node
                parent = current
            name = parts[-1]
            path = f"/{relative}"
            node = {
                "name": name, "path": path, "type": "file",
                "size": item.get("size"), "mtime": item.get("mtime"),
                "sha256": item.get("sha256"),
            }
            nodes[parent]["children"].append(node)

        def sort_nodes(node):
            node["children"].sort(key=lambda child: (child["type"] != "directory", child["name"].casefold()))
            for child in node["children"]:
                if child["type"] == "directory":
                    sort_nodes(child)

        sort_nodes(root_node)
        hosts.append({
            "host_id": snapshot["host_id"],
            "scanned_at": snapshot["scanned_at"],
            "tree": root_node,
        })
    return {
        "root": root,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hosts": hosts,
    }


def latest_patrol_event_id():
    with connect() as connection:
        row = connection.execute("SELECT MAX(id) FROM patrol_events").fetchone()
    return row[0]


def executor_states():
    """Status backend & worker dari executor (kolektor tidak lagi menyentuh HAProxy)."""
    empty = {"generated_at": None, "backends": {host: "UNKNOWN" for host in sorted(ALLOWED_HOSTS)},
             "workers": {host: "unavailable" for host in sorted(ALLOWED_HOSTS)}}
    if not EXECUTOR_TOKEN:
        return {**empty, "status": "unavailable", "reason": "executor_http_disabled"}
    try:
        request = urllib.request.Request(
            f"{EXECUTOR_URL}/v1/haproxy-states",
            headers={"Authorization": f"Bearer {EXECUTOR_TOKEN}"},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=2) as response:
            data = json.loads(response.read())
        return {
            "status": "ready",
            "generated_at": data.get("generated_at"),
            "backends": {**empty["backends"], **data.get("backends", {})},
            "workers": {**empty["workers"], **data.get("workers", {})},
        }
    except (urllib.error.URLError, OSError, TimeoutError, ValueError, json.JSONDecodeError) as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        return {**empty, "status": "unavailable", "reason": "executor_unreachable"}


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


def ot_sensor_state():
    """Report configured lab gateway reachability separately from observed events."""
    reachable = False
    if OT_GATEWAY_HOST:
        try:
            with socket.create_connection((OT_GATEWAY_HOST, OT_GATEWAY_PORT), timeout=0.35):
                reachable = True
        except (OSError, TimeoutError, ValueError):
            pass
    latest = None
    with connect() as connection:
        row = connection.execute(
            "SELECT timestamp FROM events WHERE event_type IN ('OT_MODBUS_TRANSACTION','OT_FRAME_REJECTED') ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
    if row:
        latest = row["timestamp"]
    recent = False
    if latest:
        try:
            parsed = datetime.fromisoformat(latest.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds()
            recent = 0 <= age <= 60
        except ValueError:
            pass
    status = "SENSOR_UNAVAILABLE" if not reachable else "LIVE_LAB_TELEMETRY" if recent else "LAB_SIMULATED"
    return {"status": status, "gateway_reachable": reachable, "last_event_at": latest,
            "mode": "instrumented_gateway_not_passive_sensor"}


def dashboard_state():
    states = executor_states()
    ready = states["status"] == "ready"
    workers = states["workers"]
    try:
        approval_items = list_approvals(20)
        authority_status = "ready"
    except (OSError, RuntimeError, urllib.error.URLError):
        approval_items = []
        authority_status = "unavailable"
    return {
        "generated_at": db.utc_now(),
        "mode": "OPERATIONAL" if ready else "DEGRADED",
        "analysis": {
            "engine": "FIM + canary rules",
            "model": "not_connected",
            "canary_response_enabled": ready,
            "auto_repair_enabled": False,
            "approvals_required": True,
            "executor_ready": ready,
            "demo_repair_host": DEMO_REPAIR_HOST,
            "demo_repair_delay_seconds": DEMO_REPAIR_DELAY_SECONDS,
        },
        "executor": {"status": states["status"]},
        "approval_authority": {"status": authority_status},
        "remediator": {
            "status": "ready" if all(value == "ready" for value in workers.values()) else "unavailable",
            "by_host": {host: {"status": workers[host]} for host in sorted(workers)},
        },
        "backends": states["backends"],
        "ports": OPEN_PORTS,
        "traffic": traffic_state(),
        "agents": agent_states(),
        "ot": ot_sensor_state(),
        "approvals": approval_items,
        "remediation": None,
        "remediations": [],
        "events": event_rows(40),
    }


def _attach_latest_remediation(state):
    remediations = remediation_rows(20)
    state["remediation"] = remediations[0] if remediations else None
    state["remediations"] = remediations
    return state


def parsed_cookie(raw):
    if not raw:
        return {}
    cookies = {}
    for part in raw.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            cookies[key.strip()] = value.strip()
    return cookies


def session_from_headers(headers):
    return authority_identity(headers.get("Cookie", ""))


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload, extra_headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def respond_file(self, filename, content_type):
        try:
            body = (Path(DASHBOARD_DIR) / filename).read_bytes()
        except OSError:
            return self.respond(404, {"error": "dashboard_asset_not_found"})
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        target = urlsplit(self.path)
        if target.path in ASSET_ROUTES:
            self.path = target.path
            filename, content_type = ASSET_ROUTES[target.path]
            return self.respond_file(filename, content_type)
        if target.path == "/healthz":
            return self.respond(200, {"status": "ok", "collector": True})
        if target.path == "/v1/operator/whoami":
            return self.operator_whoami()
        session = session_from_headers(self.headers)
        if target.path not in SESSION_REQUIRED_GET:
            return self.respond(404, {"error": "not_found"})
        if not authority_authorized(session, "viewer"):
            return self.respond(401, {"error": "unauthorized"})
        if target.path == "/v1/dashboard":
            return self.respond(200, _attach_latest_remediation(dashboard_state()))
        if target.path == "/v1/approvals":
            return self.approvals_list()
        if target.path == "/api/patrol/state":
            return self.respond(200, patrol_state())
        if target.path == "/v1/fsmap":
            return self.respond(200, build_fs_tree("/"))
        if target.path == "/v1/evidence/verify":
            return self.respond(200, verify_evidence())
        if target.path == "/api/patrol/fs":
            query = parse_qs(target.query)
            try:
                return self.respond(200, fs_listing(
                    query.get("host", [""])[0], query.get("path", ["/"])[0],
                ))
            except ValueError as error:
                return self.respond(400, {"error": str(error)})
        if target.path == "/api/patrol/stream":
            return self.stream_patrol_events()
        if target.path == "/v1/events":
            return self.respond(200, {"events": event_rows()})
        if target.path == "/v1/trajectories":
            with connect() as connection:
                items = trajectory.list_trajectories(connection)
            return self.respond(200, {"trajectories": items})
        if target.path == "/v1/summary":
            events = event_rows(1000)
            counts = {}
            for event in events:
                counts[event["host_id"]] = counts.get(event["host_id"], 0) + 1
            return self.respond(200, {"event_count": len(events), "by_host": counts})
        if target.path == "/v1/approvals" or target.path.startswith("/v1/approvals/"):
            return self.approvals_list()
        return self.respond(404, {"error": "not_found"})

    def read_json_body(self, maximum=16_000_000):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > maximum:
            raise ValueError("invalid_body_size")
        body = self.rfile.read(length)
        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            decoder = zlib.decompressobj(wbits=31)
            try:
                body = decoder.decompress(body, MAX_BODY_BYTES)
            except zlib.error as error:
                raise ValueError("invalid_gzip_body") from error
            if decoder.unconsumed_tail:
                raise ValueError("invalid_body_size")
        return json.loads(body)

    def csrf_or_401(self, session):
        """POST operator wajib token CSRF dari sesi: tanpa/berbeda ditolak."""
        valid = (operator_auth.authorize(session, "operator") and bool(session.get("session_id"))
                 and hmac.compare_digest(self.headers.get(operator_auth.CSRF_HEADER, ""), session.get("csrf", ""))) if APPROVAL_TEST_ADAPTER is not None else (
                     authority_authorized(session, "operator") and authority_csrf_ok(self.headers, session))
        if not valid:
            self.respond(403, {"error": "csrf_required"})
            return None
        return session

    def proxy_authority(self, path=None, method=None, payload=None):
        # Dashboard mengirim POST tanpa isi (Content-Length: 0) untuk logout; itu bukan body rusak.
        if payload is None and self.command != "GET" and int(self.headers.get("Content-Length") or 0) > 0:
            try:
                payload = self.read_json_body(8192)
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                return self.respond(400, {"error": "invalid_body"})
        status, result, set_cookie = approval_request(
            path or self.path, method=method or self.command, payload=payload,
            cookie=self.headers.get("Cookie"), csrf=self.headers.get(operator_auth.CSRF_HEADER),
        )
        headers = {"Set-Cookie": set_cookie} if set_cookie else None
        return self.respond(status, result, headers)

    def operator_login(self):
        if APPROVAL_TEST_ADAPTER is None:
            return self.proxy_authority("/v1/operator/login", "POST")
        source = self.client_address[0]
        wait = operator_auth.login_tracker.locked(source)
        if wait:
            return self.respond(429, {"error": "too_many_failures", "retry_seconds": max(1, wait)})
        try:
            payload = self.read_json_body(4096)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as error:
            return self.respond(400, {"error": str(error) or "invalid_body"})
        profile = operator_auth.authenticate(payload.get("username"), payload.get("password"))
        if profile is None:
            operator_auth.login_tracker.record_failure(source)
            return self.respond(401, {"error": "kredensial_tidak_sah"})
        operator_auth.login_tracker.reset(source)
        try:
            if operator_auth.maybe_rehash(payload.get("username"), payload.get("password")):
                print(f"operator {payload.get('username')}: hash diangkat ke {operator_auth.DEFAULT_ITERATIONS} iterasi", flush=True)
        except Exception as error:  # Upgrade gagal tidak boleh menolak login.
            print(f"rehash operator gagal: {error}", flush=True)
        session = operator_auth.create_session(profile["username"], profile["role"])
        cookie = (
            f"{operator_auth.SESSION_COOKIE}={session['session_id']}; Path=/; HttpOnly; SameSite=Strict"
        )
        return self.respond(200, {
            "approved": True,
            "username": session["username"],
            "role": session["role"],
            "csrf": session["csrf"],
        }, {"Set-Cookie": cookie})

    def operator_logout(self):
        if APPROVAL_TEST_ADAPTER is None:
            return self.proxy_authority("/v1/operator/logout", "POST")
        session = session_from_headers(self.headers)
        if session and not self.csrf_or_401(session):
            return
        if session:
            operator_auth.destroy_session(session["session_id"])
        cookie = f"{operator_auth.SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
        return self.respond(200, {"logged_out": True}, {"Set-Cookie": cookie})

    def operator_whoami(self):
        if APPROVAL_TEST_ADAPTER is None:
            return self.proxy_authority("/v1/operator/whoami", "GET")
        session = session_from_headers(self.headers)
        if not session:
            return self.respond(200, {"authenticated": False})
        return self.respond(200, {
            "authenticated": True, "username": session["username"],
            "role": session["role"], "csrf": session["csrf"],
        })

    def approvals_list(self):
        if APPROVAL_TEST_ADAPTER is None:
            return self.proxy_authority("/v1/approvals", "GET")
        session = session_from_headers(self.headers)
        if not authority_authorized(session, "viewer"):
            return self.respond(401, {"error": "unauthorized"})
        return self.respond(200, {"approvals": list_approvals(50)})

    def handle_approval_action(self, action):
        if APPROVAL_TEST_ADAPTER is None and action in {"approve", "reject"}:
            payload = None
            if action == "reject":
                try:
                    payload = self.read_json_body(2048)
                except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                    payload = {}
            status, result, _ = approval_request(self.path, method="POST", payload=payload,
                                                 cookie=self.headers.get("Cookie"),
                                                 csrf=self.headers.get(operator_auth.CSRF_HEADER))
            if status == 200 and action == "approve":
                approval = result.get("approval")
                if approval:
                    try:
                        executor_claimed(approval, f"operator:{approval.get('approved_by', 'operator')}")
                    except (RuntimeError, OSError, urllib.error.URLError):
                        result["submitted"] = False
                        result["note"] = "authority sudah menyetujui; executor akan mencoba melalui poll"
                    else:
                        result["submitted"] = True
            if status == 200 and action == "reject":
                close_rejected_run(result.get("approval"))
            return self.respond(status, result)
        if APPROVAL_TEST_ADAPTER is None and action == "execute":
            identity = session_from_headers(self.headers)
            if not authority_authorized(identity, "operator"):
                return self.respond(401, {"error": "unauthorized"})
            if not authority_csrf_ok(self.headers, identity):
                return self.respond(403, {"error": "csrf_required"})
            approval_id = urlsplit(self.path).path.split("/")[-2]
            try:
                approval = get_approval(approval_id)
                if approval is None or approval["approval_status"] != "APPROVED":
                    return self.respond(409, {"error": "approval_not_approved"})
                executor_claimed(approval, f"operator:{identity['username']}")
                return self.respond(202, {"approval": approval, "submitted": True})
            except RuntimeError as error:
                return self.respond(503, {"error": str(error)})
        session = session_from_headers(self.headers)
        if not authority_authorized(session, "operator"):
            return self.respond(401, {"error": "unauthorized"})
        if not self.csrf_or_401(session):
            return
        approval_id = urlsplit(self.path).path.split("/")[-2]
        try:
            payload = self.read_json_body(2048) if action in ("reject",) else {}
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            payload = {}
        try:
            actor = f"operator:{session['username']}"
            if action == "approve":
                updated = approvals.approve(approval_id, actor)
                try:
                    executor_claimed(updated, actor)
                except (RuntimeError, OSError, urllib.error.URLError):
                    approval = approvals.get(approval_id)
                    executor_poll_note = "menunggu siklus klaim executor"
                    return self.respond(202, {
                        "approval": approval,
                        "submitted": False,
                        "note": executor_poll_note,
                    })
                return self.respond(200, {"approval": updated, "submitted": True})
            if action == "reject":
                rejected = approvals.reject(approval_id, actor, str(payload.get("reason") or "operator_rejected"))
                close_rejected_run(rejected)
                return self.respond(200, {"approval": rejected})
            if action == "execute":
                approval = approvals.get(approval_id)
                if approval is None or approval["approval_status"] != approvals.STATUS_APPROVED:
                    return self.respond(409, {"error": "approval_not_approved"})
                try:
                    executor_claimed(approval, actor)
                except RuntimeError as error:
                    return self.respond(503, {"error": str(error)})
                except (OSError, urllib.error.URLError) as error:
                    return self.respond(503, {"error": "executor_unreachable", "detail": type(error).__name__})
                return self.respond(202, {"approval": approvals.get(approval_id), "submitted": True})
        except approvals.ApprovalError as error:
            return self.respond(409, {"error": str(error)})

    def request_lab_attack(self):
        session = session_from_headers(self.headers)
        if not authority_authorized(session, "operator"):
            return self.respond(401, {"error": "unauthorized"})
        if not self.csrf_or_401(session):
            return
        target = urlsplit(self.path)
        host_id = target.path.rsplit("/", 1)[-1]
        if host_id not in ALLOWED_HOSTS:
            return self.respond(404, {"error": "unknown_host"})
        vector = parse_qs(target.query).get("vector", [None])[0]
        if vector is not None and vector not in LAB_ATTACK_VECTORS:
            return self.respond(400, {"error": "unknown_vector"})
        actor = f"operator:{session['username']}"
        try:
            approval = create_approval(
                "SIMULATE_LAB_ATTACK", host_id,
                f"simulasi-lewat-{vector or 'statik'}",
                {"vector": vector, "entry_gate": True},
                created_by=actor, reason="operator_meminta_simulasi_serangan_lab",
            )
            approval = approve_via_authority(
                approval["id"], actor, self.headers.get("Cookie", ""),
                self.headers.get(operator_auth.CSRF_HEADER, ""),
            )
            try:
                executor_claimed(approval, actor)
            except (RuntimeError, OSError, urllib.error.URLError) as error:
                print(f"executor submit deferred: {type(error).__name__}", flush=True)
        except (approvals.ApprovalError, RuntimeError) as error:
            return self.respond(409, {"error": str(error)})
        print(f"lab attack approval dibuat oleh {actor} untuk {host_id}", flush=True)
        return self.respond(202, {
            "accepted": True, "host_id": host_id,
            "approval_id": approval["id"], "approval_status": "APPROVED",
        })

    def request_backend_rejoin(self):
        session = session_from_headers(self.headers)
        if not authority_authorized(session, "operator"):
            return self.respond(401, {"error": "unauthorized"})
        if not self.csrf_or_401(session):
            return
        host_id = urlsplit(self.path).path.rsplit("/", 1)[-1]
        if host_id not in ALLOWED_HOSTS:
            return self.respond(404, {"error": "unknown_host"})
        with db.connect() as connection:
            recovery = connection.execute(
                """SELECT event_id, status, completed_at FROM remediation_runs
                   WHERE host_id = ? AND status IN
                     ('REPAIRED', 'REPAIR_FAILED', 'EXECUTION_FAILED', 'MASTER_UNTRUSTED', 'HEALTH_CHECK_FAILED')
                   ORDER BY updated_at DESC LIMIT 1""",
                (host_id,),
            ).fetchone()
        if recovery is None or recovery["status"] != "REPAIRED" or not recovery["completed_at"]:
            return self.respond(409, {"error": "recovery_state_invalid"})
        actor = f"operator:{session['username']}"
        try:
            approval = create_approval(
                "REJOIN_BACKEND", host_id, f"rejoin-{host_id}",
                {"recovery_run_key": recovery["event_id"]},
                created_by=actor, reason="operator_meminta_rejoin_backend",
            )
            approval = approve_via_authority(
                approval["id"], actor, self.headers.get("Cookie", ""),
                self.headers.get(operator_auth.CSRF_HEADER, ""),
            )
            try:
                executor_claimed(approval, actor)
            except (RuntimeError, OSError, urllib.error.URLError):
                pass
        except (approvals.ApprovalError, RuntimeError) as error:
            return self.respond(409, {"error": str(error)})
        return self.respond(202, {
            "mode": "OPERATIONAL", "action": f"REJOIN_{host_id.upper().replace('-', '_')}",
            "host_id": host_id, "approval_id": approval["id"],
        })

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

    def receive_fs_inventory(self):
        try:
            payload = self.read_json_body()
            if not isinstance(payload, dict):
                return self.respond(400, {"error": "invalid_inventory"})
            host_id = payload.get("host_id")
            entry_count = store_fs_inventory(host_id, payload.get("directories"), payload.get("timestamp"))
            return self.respond(202, {"accepted": True, "host_id": host_id, "entry_count": entry_count})
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            return self.respond(400, {"error": str(error) or "invalid_inventory"})

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
        except sqlite3.Error as error:
            print(f"event storage failed: {error}", flush=True)
            return self.respond(500, {"error": "storage_failure"})

    def receive_ot_event(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 8192:
                return self.respond(413, {"error": "invalid_body_size"})
            event = json.loads(self.rfile.read(length))
            if not isinstance(event, dict):
                return self.respond(400, {"error": "invalid_event"})
            required = {"event_type", "timestamp", "host_id", "source", "path", "protocol", "device_id",
                        "source_ip", "destination", "unit_id", "function_code", "operation",
                        "policy_id", "policy_decision", "policy_reason", "response_status",
                        "raw_evidence_sha256", "evidence_reference", "dedupe_key"}
            if not required.issubset(event):
                return self.respond(400, {"error": "missing_fields"})
            if event["event_type"] not in {"OT_MODBUS_TRANSACTION", "OT_FRAME_REJECTED"}:
                return self.respond(400, {"error": "unsupported_ot_event"})
            if event["host_id"] != OT_ALLOWED_DEVICE_ID or event["device_id"] != OT_ALLOWED_DEVICE_ID:
                return self.respond(403, {"error": "unknown_ot_device"})
            if event["source"] != "instrumented_modbus_gateway" or event["protocol"] != "MODBUS_TCP":
                return self.respond(400, {"error": "untrusted_ot_source"})
            try:
                ipaddress.ip_address(event["source_ip"])
            except (ValueError, TypeError):
                return self.respond(400, {"error": "invalid_source_ip"})
            if not isinstance(event["destination"], str) or len(event["destination"]) > 96:
                return self.respond(400, {"error": "invalid_destination"})
            for name, maximum in (("unit_id", 247), ("function_code", 255)):
                value = event[name]
                if type(value) is not int or not 0 <= value <= maximum:
                    return self.respond(400, {"error": f"invalid_{name}"})
            for name, maximum in (("register_start", 65535), ("register_quantity", 125), ("register_value", 65535)):
                value = event.get(name)
                if value is not None and (type(value) is not int or not 0 <= value <= maximum):
                    return self.respond(400, {"error": f"invalid_{name}"})
            if event.get("operation") not in {"READ", "WRITE", "UNSUPPORTED"}:
                return self.respond(400, {"error": "invalid_operation"})
            if event["policy_decision"] not in {"ALLOW", "DENY"} or event["response_status"] not in {"SUCCESS", "MODBUS_EXCEPTION"}:
                return self.respond(400, {"error": "invalid_policy_result"})
            if event["policy_decision"] == "ALLOW" and event["response_status"] != "SUCCESS":
                return self.respond(400, {"error": "inconsistent_policy_result"})
            if event["policy_decision"] == "DENY" and event["response_status"] != "MODBUS_EXCEPTION":
                return self.respond(400, {"error": "inconsistent_policy_result"})
            if event["event_type"] == "OT_MODBUS_TRANSACTION":
                expected_operation = {3: "READ", 6: "WRITE"}.get(event["function_code"], "UNSUPPORTED")
                if event["operation"] != expected_operation:
                    return self.respond(400, {"error": "inconsistent_operation"})
            elif event["policy_decision"] != "DENY":
                return self.respond(400, {"error": "rejected_frame_must_be_denied"})
            for name in ("raw_evidence_sha256", "dedupe_key"):
                value = event[name]
                if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                    return self.respond(400, {"error": f"invalid_{name}"})
            if event["evidence_reference"] != f"sha256:{event['raw_evidence_sha256']}":
                return self.respond(400, {"error": "evidence_reference_mismatch"})
            expected_dedupe = hashlib.sha256(
                f"{event['source_ip']}|{event['device_id']}|{event['raw_evidence_sha256']}".encode("utf-8")
            ).hexdigest()
            if not hmac.compare_digest(event["dedupe_key"], expected_dedupe):
                return self.respond(400, {"error": "dedupe_key_mismatch"})
            if not isinstance(event["policy_id"], str) or not 1 <= len(event["policy_id"]) <= 64:
                return self.respond(400, {"error": "invalid_policy_id"})
            if not isinstance(event["policy_reason"], str) or not 1 <= len(event["policy_reason"]) <= 128:
                return self.respond(400, {"error": "invalid_policy_reason"})
            try:
                datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
            except ValueError:
                return self.respond(400, {"error": "invalid_timestamp"})
            event = dict(event)
            event["path"] = f"modbus://{OT_ALLOWED_DEVICE_ID}/unit/{event['unit_id']}/register/{event.get('register_start', 'unknown')}"
            result = store_event(event)
            return self.respond(200 if result.get("duplicate") else 201, result)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, KeyError, TypeError):
            return self.respond(400, {"error": "invalid_ot_event"})
        except sqlite3.Error as error:
            print(f"OT event storage failed: {error}", flush=True)
            return self.respond(500, {"error": "storage_failure"})

    def do_POST(self):
        if self.path == "/v1/ot/events":
            if not OT_API_TOKEN or not hmac.compare_digest(
                self.headers.get("Authorization", ""), f"Bearer {OT_API_TOKEN}"
            ):
                return self.respond(401, {"error": "unauthorized"})
            return self.receive_ot_event()
        if self.path in AGENT_PATHS and API_TOKEN and not hmac.compare_digest(
            self.headers.get("Authorization", ""), f"Bearer {API_TOKEN}"
        ):
            return self.respond(401, {"error": "unauthorized"})
        if self.path == "/v1/patrol/snapshot":
            return self.receive_patrol_snapshot()
        if self.path == "/v1/patrol/inventory":
            return self.receive_fs_inventory()
        if self.path == "/api/patrol/events":
            return self.receive_patrol_event()
        if self.path == "/v1/agent/heartbeat":
            return self.receive_heartbeat()
        if self.path == "/v1/operator/login":
            return self.operator_login()
        if self.path == "/v1/operator/logout":
            return self.operator_logout()
        if self.path == "/v1/operator/whoami":
            return self.operator_whoami()
        for action in ("approve", "reject", "execute"):
            path = urlsplit(self.path).path
            if path.startswith("/v1/approvals/") and path.endswith(f"/{action}") and len(path.split("/")) == 5:
                return self.handle_approval_action(action)
        if self.path.startswith("/v1/lab/attack/"):
            return self.request_lab_attack()
        if self.path.startswith("/v1/lab/recover/"):
            return self.request_backend_rejoin()
        if self.path != "/v1/events":
            return self.respond(404, {"error": "not_found"})
        return self.receive_event()

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
            ports = payload.get("ports")
            if isinstance(ports, list):
                OPEN_PORTS[host_id] = sorted({
                    port for port in ports[:MAX_OPEN_PORTS]
                    if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536
                })
            with connect() as connection:
                connection.execute(
                    "INSERT INTO agent_status (host_id, last_seen) VALUES (?, ?) "
                    "ON CONFLICT(host_id) DO UPDATE SET last_seen = excluded.last_seen",
                    (host_id, timestamp),
                )
            return self.respond(202, {"accepted": True, "host_id": host_id})
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            return self.respond(400, {"error": "invalid_heartbeat"})

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} {format_string % args}", flush=True)


if __name__ == "__main__":
    if (not EXECUTOR_TOKEN or not authority_client.COLLECTOR_TOKEN
            or EXECUTOR_TOKEN.startswith("GANTI-")
            or authority_client.COLLECTOR_TOKEN.startswith("GANTI-")):
        raise SystemExit("collector requires provisioned executor and approval-authority tokens")
    initialize()
    if TRAFFIC_PROBE_ENABLED:
        threading.Thread(target=traffic_probe_loop, name="traffic-probe", daemon=True).start()
    tls_port = int(os.environ.get("DASHBOARD_TLS_PORT", "8443"))
    tls_server = ThreadingHTTPServer(("0.0.0.0", tls_port), Handler)
    tls_context = tls_support.server_context(
        os.environ.get("DASHBOARD_TLS_CERT_FILE", ""),
        os.environ.get("DASHBOARD_TLS_KEY_FILE", ""),
    )
    tls_server.socket = tls_context.wrap_socket(tls_server.socket, server_side=True)
    print(f"collector HTTPS ready on :{tls_port}", flush=True)
    tls_server.serve_forever()
