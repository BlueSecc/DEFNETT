"""Satu pintu persetujuan: eksekusi hanya boleh dimulai dari approval di sini.

Approval dibuat kolektor (dari Policy Gate) atau operator (untuk serangan lab).
Operator menyetujui/menolak; executor mengklaim dengan pembaruan atomik sehingga
satu approval hanya bisa dipakai satu kali; dan kedaluwarsa. Setiap tindakan
mendapat catatan operator_audit.
"""
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import db

APPROVAL_TTL_SECONDS = max(10, int(os.environ.get("OPERATOR_APPROVAL_TTL_SECONDS", "600")))
STATUS_PENDING = "PENDING"
STATUS_APPROVED = "APPROVED"
STATUS_REJECTED = "REJECTED"
STATUS_EXPIRED = "EXPIRED"
EXECUTION_NONE = "NONE"
EXECUTION_CLAIMED = "CLAIMED"
EXECUTION_DONE = "DONE"
EXECUTION_FAILED = "FAILED"
EXECUTION_QUEUED = "QUEUED"
ALLOWED_ACTIONS = {"CONTAIN_CANARY", "RESTORE_KEYS", "SIMULATE_LAB_ATTACK", "REJOIN_BACKEND"}


class ApprovalError(ValueError):
    """Dipanting bila persetujuan tidak boleh diproses (fail-closed)."""


def _audit_tx(connection, actor, action, target, detail, outcome):
    connection.execute(
        """INSERT INTO operator_audit (ts, actor, action, target, detail, outcome)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (db.utc_now(), str(actor or "unknown"), str(action), str(target), str(detail), str(outcome)),
    )


def _parse_expiry(value):
    try:
        parsed = datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _row_to_dict(row):
    if row is None:
        return None
    approval = dict(row)
    try:
        approval["parameters"] = json.loads(approval.pop("parameters_json") or "{}")
    except (json.JSONDecodeError, TypeError):
        approval["parameters"] = {}
        approval["parameters_json"] = approval.get("parameters_json")
        approval.pop("parameters", None)
    return approval


def create(action, host_id, path, parameters, event_id=None, created_by="policy_gate", reason=""):
    """Daftarkan permintaan eksekusi yang menunggu persetujuan operator."""
    if action not in ALLOWED_ACTIONS:
        raise ApprovalError("unknown_action")
    if host_id not in db.ALLOWED_HOSTS:
        raise ApprovalError("unknown_host")
    if not isinstance(path, str) or not path:
        raise ApprovalError("invalid_target")
    if not isinstance(parameters, dict):
        raise ApprovalError("invalid_parameters")
    approval_id = str(uuid.uuid4())
    now = db.utc_now()
    expires = (datetime.now(timezone.utc) + timedelta(seconds=APPROVAL_TTL_SECONDS)).isoformat()
    reason = str(reason or f"menunggu_persetujuan:{action}")[:160]
    target = f"{action}:{host_id}{(':' + str(event_id)) if event_id else ''}"
    with db.connect() as connection:
        connection.execute(
            """INSERT INTO operator_approvals
               (id, created_at, created_by, action, host_id, path, parameters_json,
                reason, event_id, approval_status, expires_at, execution_status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                approval_id, now, str(created_by)[:96], action, host_id, path[:2048],
                json.dumps(parameters, ensure_ascii=False), reason,
                str(event_id) if event_id else None, STATUS_PENDING, expires, EXECUTION_NONE,
            ),
        )
        if event_id:
            connection.execute(
                "UPDATE events SET approval_id = ? WHERE id = ?", (approval_id, str(event_id))
            )
        _audit_tx(connection, created_by, "approval_create", target, f"approval={approval_id}", STATUS_PENDING)
    return get(approval_id)


def get(approval_id):
    with db.connect() as connection:
        row = db.load_approvals_row(connection, approval_id)
    return _row_to_dict(row)


def list_approvals(limit=30):
    with db.connect() as connection:
        rows = connection.execute(
            "SELECT * FROM operator_approvals ORDER BY rowid DESC LIMIT ?", (max(1, min(int(limit), 200)),)
        ).fetchall()
    return [_row_to_dict(row) for row in rows]


def approve(approval_id, actor, ttl_seconds=None):
    ttl = APPROVAL_TTL_SECONDS if ttl_seconds is None else max(10, int(ttl_seconds))
    expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl)).isoformat()
    with db.connect() as connection:
        approval = db.load_approvals_row(connection, approval_id)
        if approval is None:
            raise ApprovalError("approval_not_found")
        if approval["approval_status"] != STATUS_PENDING:
            raise ApprovalError("approval_not_pending")
        cursor = connection.execute(
            """UPDATE operator_approvals
               SET approval_status = ?, approved_at = ?, approved_by = ?, expires_at = ?
               WHERE id = ? AND approval_status = ?""",
            (STATUS_APPROVED, db.utc_now(), str(actor)[:96], expires, approval_id, STATUS_PENDING),
        )
        if cursor.rowcount != 1:
            raise ApprovalError("approval_not_pending")
        _audit_tx(connection, actor, "approval_approve", f"{approval['action']}:{approval['host_id']}{approval['path']}", f"approval={approval_id}", STATUS_APPROVED)
    return get(approval_id)


def reject(approval_id, actor, reason="operator_rejected"):
    with db.connect() as connection:
        approval = db.load_approvals_row(connection, approval_id)
        if approval is None:
            raise ApprovalError("approval_not_found")
        if approval["approval_status"] != STATUS_PENDING:
            raise ApprovalError("approval_not_pending")
        cursor = connection.execute(
            "UPDATE operator_approvals SET approval_status = ? WHERE id = ? AND approval_status = ?",
            (STATUS_REJECTED, approval_id, STATUS_PENDING),
        )
        if approval["event_id"]:
            connection.execute(
                "UPDATE events SET approval_id = NULL WHERE id = ? AND approval_id = ?",
                (str(approval["event_id"]), approval_id),
            )
        if cursor.rowcount != 1:
            raise ApprovalError("approval_not_pending")
        _audit_tx(connection, actor, "approval_reject", f"{approval['action']}:{approval['host_id']}{approval['path']}",
                  f"approval={approval_id}; {str(reason)[:160]}", STATUS_REJECTED)
    return get(approval_id)


def claim(approval_id, execution_detail=""):
    """Klaim atomik: kembalikan approval bila VALID; lainnya ApprovalError.

    Hanya approval APPROVED, berstatus eksekusi NONE, belum kedaluwarsa, dan
    belum pernah dipakai yang bisa dimuat; rowcount==1 menjamin satu pemutur.
    Ganti status expired ditulis lalu di-commit SEBELUM audit dan error,
    agar penandaaan status tidak ikut tergulung balik oleh pengecualian.
    """
    now = db.utc_now()
    expired = False
    with db.connect() as connection:
        row = db.load_approvals_row(connection, approval_id)
        if row is None:
            raise ApprovalError("approval_not_found")
        if row["approval_status"] == STATUS_PENDING:
            raise ApprovalError("approval_not_approved")
        if row["approval_status"] != STATUS_APPROVED:
            raise ApprovalError(f"approval_{row['approval_status'].lower()}")
        expires = _parse_expiry(row["expires_at"])
        if expires is None or expires < datetime.now(timezone.utc):
            cursor = connection.execute(
                "UPDATE operator_approvals SET approval_status = ? WHERE id = ? AND approval_status = ?",
                (STATUS_EXPIRED, approval_id, STATUS_APPROVED),
            )
            if cursor.rowcount == 1:
                _audit_tx(connection, "executor", "approval_claim", f"{row['action']}:{row['host_id']}", f"approval={approval_id}", STATUS_EXPIRED)
            expired = True
        elif row["execution_status"] != EXECUTION_NONE:
            raise ApprovalError("approval_already_used")
        else:
            cursor = connection.execute(
                """UPDATE operator_approvals
                   SET execution_status = ?, execution_at = ?, execution_detail = ?
                   WHERE id = ? AND approval_status = ? AND execution_status = ?""",
                (EXECUTION_CLAIMED, now, str(execution_detail)[:192], approval_id, STATUS_APPROVED, EXECUTION_NONE),
            )
            if cursor.rowcount != 1:
                raise ApprovalError("approval_race_lost")
            _audit_tx(connection, "executor", "approval_claim", f"{row['action']}:{row['host_id']}", f"approval={approval_id}", EXECUTION_CLAIMED)
    if expired:
        raise ApprovalError("approval_expired")
    return get(approval_id)


def complete(approval_id, outcome, detail, parameters_update=None):
    if outcome not in (EXECUTION_DONE, EXECUTION_FAILED):
        raise ApprovalError("unknown_execution_outcome")
    with db.connect() as connection:
        row = db.load_approvals_row(connection, approval_id)
        if row is None:
            raise ApprovalError("approval_not_found")
        if row["execution_status"] in (EXECUTION_DONE, EXECUTION_FAILED):
            if row["execution_status"] == outcome and row["execution_detail"] == str(detail)[:192]:
                return _row_to_dict(row)
            raise ApprovalError("execution_already_completed")
        if row["approval_status"] != STATUS_APPROVED or row["execution_status"] != EXECUTION_CLAIMED:
            raise ApprovalError("execution_not_claimed")
        merged = {}
        if parameters_update:
            try:
                merged = json.loads(row["parameters_json"] or "{}")
            except (json.JSONDecodeError, TypeError):
                merged = {}
            merged.update(parameters_update)
            connection.execute(
                "UPDATE operator_approvals SET parameters_json = ? WHERE id = ?",
                (json.dumps(merged, ensure_ascii=False), approval_id),
            )
        connection.execute(
            "UPDATE operator_approvals SET execution_status = ?, execution_detail = ?, execution_at = ? WHERE id = ?",
            (outcome, str(detail)[:192], db.utc_now(), approval_id),
        )
        if outcome == EXECUTION_FAILED and row["event_id"]:
            connection.execute(
                "UPDATE events SET approval_id = NULL WHERE id = ? AND approval_id = ?",
                (str(row["event_id"]), approval_id),
            )
        _audit_tx(connection, "executor", "approval_complete", f"{row['action']}:{row['host_id']}",
                  f"approval={approval_id}; {str(detail)[:160]}", outcome)
    return get(approval_id)


def pending_count():
    with db.connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM operator_approvals WHERE approval_status = ? AND execution_status = ?",
            (STATUS_PENDING, EXECUTION_NONE),
        ).fetchone()
    return int(row["total"])


def expired_pending():
    """Tandai PENDING kedaluwarsa: persetujuan tidak boleh bertahan selamanya."""
    with db.connect() as connection:
        rows = connection.execute(
            "SELECT id, action, host_id, expires_at FROM operator_approvals WHERE approval_status = ?",
            (STATUS_PENDING,),
        ).fetchall()
        for row in rows:
            expiry = _parse_expiry(row["expires_at"])
            if expiry is not None and expiry >= datetime.now(timezone.utc):
                continue
            cursor = connection.execute(
                "UPDATE operator_approvals SET approval_status = ? WHERE id = ?",
                (STATUS_EXPIRED, row["id"]),
            )
            if cursor.rowcount == 1:
                _audit_tx(connection, "system", "approval_expire", f"{row['action']}:{row['host_id']}",
                          f"approval={row['id']}", STATUS_EXPIRED)
    return [dict(row) for row in rows]


def restored_hashes():
    """Pemetaan (host_id, jalur kunci) -> sha256 hasil pemulihan yang tercatat."""
    result = {}
    for approval in list_approvals(200):
        if approval["approval_status"] != STATUS_APPROVED or approval["execution_status"] != EXECUTION_DONE:
            continue
        for restored in approval.get("parameters", {}).get("restored", []):
            if isinstance(restored, dict) and restored.get("path") and restored.get("sha256"):
                result[(approval["host_id"], str(restored["path"]).lstrip("/"))] = restored["sha256"]
    return result
