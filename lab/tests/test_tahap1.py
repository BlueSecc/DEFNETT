"""Uji TAHAP 1: pengaman di luar arus analisis.

Cakupan:
- Otentikasi operator (PBKDF2, sesi, kunci belakang, percobaan gagal).
- Ingestion hanya mencatat dan mengantre persetujuan; eksekusi tidak dipicu agent.
- Policy Gate deterministik + konfirmasi pemulihan (restore-confirmed).
- Siklus persetujuan: approve/reject/claim sekali/kedaluwarsa/audit.
- Executor: klaim + playbook terisolasi via palsu (fakes) HAProxy + remediator.
- Trust anchor: provision_master + verifikasi manifes + penolakan pemulihan.

Test ini harus berjalan setelah test_core (urutan alfabetis discovery): test_core
mengatur variabel lingkungan lama; di sini semuanya diatur ulang per-test lewat
retarget variabel modul, bukan lingkungan (env sudah terbaca saat import).
"""
import hashlib
import http.cookiejar
import ipaddress
import json
import os
import secrets
import shutil
import socket
import sqlite3
import struct
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import approvals
import collector
import db
import executor
import operator_auth
import policy_gate
import provision_master
import provision_operators
import modbus_lab
import risk_engine
import remediator
import trajectory


ORIGINALS = [
    (db, "DB_PATH"),
    (collector, "DB_PATH"),
    (approvals, "APPROVAL_TTL_SECONDS"),
    (operator_auth, "AUTH_FILE"),
    (collector, "DEMO_REPAIR_HOST"),
    (collector, "DEMO_REPAIR_DELAY_SECONDS"),
    (collector, "TRAFFIC_PROBE_ENABLED"),
    (collector, "API_TOKEN"),
    (collector, "OT_API_TOKEN"),
    (collector, "OT_ALLOWED_DEVICE_ID"),
    (collector, "EXECUTOR_TOKEN"),
    (collector, "APPROVAL_TEST_ADAPTER"),
    (executor, "APPROVAL_TEST_ADAPTER"),
    (collector, "EXECUTOR_URL"),
    (executor, "EXECUTOR_TOKEN"),
    (executor, "HAPROXY_HOST"),
    (executor, "HAPROXY_RUNTIME_PORT"),
    (executor, "REMEDIATOR_URLS"),
    (executor, "_sleep"),
]
RESCORE = None


def now_iso():  # noqa: FLY002 - kejelasan pembaca diuji, bukan kecepatan
    return datetime.now(timezone.utc).isoformat()


class TahapBase(unittest.TestCase):
    def setUp(self):
        self.previous = [(module, name, getattr(module, name)) for module, name in ORIGINALS]
        self.tmp = tempfile.mkdtemp(prefix="defnett-tahap1-")
        db.DB_PATH = os.path.join(self.tmp, "evidence", "events.sqlite3")
        collector.DB_PATH = db.DB_PATH
        approvals.APPROVAL_TTL_SECONDS = 3600
        operator_auth.AUTH_FILE = os.path.join(self.tmp, "ops", "operator_auth.json")
        reset_auth_cache()
        collector.DEMO_REPAIR_HOST = "di-dalam-lab-tidak-ada"
        collector.DEMO_REPAIR_DELAY_SECONDS = 0
        collector.TRAFFIC_PROBE_ENABLED = False
        collector.API_TOKEN = ""
        collector.EXECUTOR_TOKEN = ""
        collector.APPROVAL_TEST_ADAPTER = approvals
        executor.APPROVAL_TEST_ADAPTER = approvals
        db.initialize(db.DB_PATH)

    def tearDown(self):
        for module, name, value in self.previous:
            setattr(module, name, value)
        operator_auth._sessions.clear()
        operator_auth.login_tracker.reset("127.0.0.1")
        shutil.rmtree(self.tmp, ignore_errors=True)


def reset_auth_cache():
    operator_auth._file_cache.update({"mtime": None, "users": None, "failures": ""})


def base_event(event_type="file_modified", path="/etc/kunci1.dat", content_signal=False,
               indicator=None, old_hash=None, new_hash=None, host_id="server-a"):
    event = {
        "host_id": host_id,
        "source": "agent",
        "event_type": event_type,
        "path": path,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "old_hash": old_hash,
        "new_hash": new_hash,
    }
    if content_signal is not None:
        event["content_signal"] = content_signal
    if indicator:
        event["indicator"] = indicator
    return event


def latest_approval():
    items = approvals.list_approvals(1)
    return items[0] if items else None


def run_stage_keys(event_id):
    with db.connect() as connection:
        row = connection.execute(
            "SELECT step_history, status FROM remediation_runs WHERE event_id = ?", (event_id,)
        ).fetchone()
    if row is None:
        return []
    history = json.loads(row["step_history"])
    return [step["stage"] for step in history]


class PasswordUpgradeTests(TahapBase):
    def setUp(self):
        super().setUp()
        provision_operators.add_operator(
            operator_auth.AUTH_FILE, "admin", "operator", "kunci-rahasia-pengaman-9"
        )

    def test_store_file_is_hashed_and_mode_600(self):
        stat_result = os.stat(operator_auth.AUTH_FILE)
        self.assertTrue(stat_result.st_mode & 0o600)
        raw = json.loads(Path(operator_auth.AUTH_FILE).read_text(encoding="utf-8"))
        record = raw["operators"]["admin"]
        self.assertEqual(record["role"], "operator")
        self.assertGreaterEqual(record["iterations"], operator_auth.MIN_ITERATIONS)

    def test_authenticate_ok_dan_gagal(self):
        profile = operator_auth.authenticate("admin", "kunci-rahasia-pengaman-9")
        self.assertEqual(profile, {"username": "admin", "role": "operator"})
        self.assertIsNone(operator_auth.authenticate("admin", "salah-total"))
        self.assertIsNone(operator_auth.authenticate("pengintip", "kunci-rahasia-pengaman-9"))

    def test_hash_lama_diverifikasi_lalu_rehash(self):
        password = "sandi-lama-amankkk12"
        salt = secrets.token_hex(16)
        Path(operator_auth.AUTH_FILE).write_text(json.dumps({"version": 1, "operators": {
            "lama": {"salt": salt, "hash": operator_auth.hash_password(password, salt, 100_000),
                     "iterations": 100_000, "role": "operator"},
        }}), encoding="utf-8")
        self.assertEqual(operator_auth.authenticate("lama", password), {"username": "lama", "role": "operator"})
        self.assertTrue(operator_auth.maybe_rehash("lama", password))
        upgraded = json.loads(Path(operator_auth.AUTH_FILE).read_text(encoding="utf-8"))["operators"]["lama"]
        self.assertEqual(upgraded["iterations"], operator_auth.DEFAULT_ITERATIONS)
        self.assertEqual(operator_auth.authenticate("lama", password), {"username": "lama", "role": "operator"})

    def test_role_matriks_persetujuan(self):
        provision_operators.add_operator(operator_auth.AUTH_FILE, "baca", "viewer", "pembaca-tetap-ygz-1")
        sesi_admin = operator_auth.create_session(*operator_auth.authenticate("admin", "kunci-rahasia-pengaman-9").values())
        sesi_baca = operator_auth.create_session(*operator_auth.authenticate("baca", "pembaca-tetap-ygz-1").values())
        self.assertTrue(operator_auth.authorize(sesi_baca, "viewer"))
        self.assertFalse(operator_auth.authorize(sesi_baca, "operator"))
        self.assertTrue(operator_auth.authorize(sesi_admin, "operator"))

    def test_session_expired(self):
        session = operator_auth.create_session("admin", "operator")
        self.assertGreaterEqual(len(session["session_id"]), 40)
        operator_auth._sessions[session["session_id"]]["expires"] = time.monotonic() - 1
        self.assertIsNone(operator_auth.get_session(session["session_id"]))

    def test_login_lockout(self):
        tracker = operator_auth.LoginTracker()
        for _ in range(5):
            tracker.record_failure("pejabat-uji")
        self.assertGreater(tracker.locked("pejabat-uji"), 0)
        self.assertEqual(tracker.locked("sumber-lain"), 0)
        tracker.reset("pejabat-uji")
        self.assertEqual(tracker.locked("pejabat-uji"), 0)


class PolicyGateTests(unittest.TestCase):
    def test_canary_dan_kunci_wajib_approval(self):
        canary = base_event(
            path="/data/DEFNETT-LAB-CANARY.txt", content_signal=True,
            indicator="DEFNETT_LAB_CANARY", new_hash="b" * 64,
        )
        decision = policy_gate.decide(canary, 0.99, 2.0, 3, "operator_approval_containment")
        self.assertEqual(decision["category"], policy_gate.CATEGORY_PENDING_APPROVAL)
        self.assertEqual(decision["action"], "CONTAIN_CANARY")
        self.assertIn(policy_gate.RULE_APPROVAL_REQUIRED, decision["reasons"])

        kunci = base_event(path="/etc/kunci2.dat", new_hash="c" * 64)
        decision = policy_gate.decide(kunci, 0.99, 2.0, 3, "operator_approval_restore_keys")
        self.assertEqual(decision["action"], "RESTORE_KEYS")

    def test_restore_confirmed_bukan_ancaman(self):
        kunci = base_event(path="/etc/kunci1.dat", new_hash="a" * 64)
        decision = policy_gate.decide(
            kunci, 0.99, 2.0, 3, "operator_approval_restore_keys",
            restored_hashes={("server-a", "etc/kunci1.dat"): "a" * 64},
        )
        self.assertEqual(decision["category"], policy_gate.CATEGORY_INFORMATIONAL)
        self.assertEqual(decision["action"], policy_gate.DEFAULT_ACTION)
        self.assertIn(policy_gate.RULE_RESTORE_CONFIRMED, decision["reasons"])
        self.assertNotIn(policy_gate.RULE_APPROVAL_REQUIRED, decision["reasons"])

    def test_event_biasa_tak_eksekusi(self):
        decision = policy_gate.decide(
            base_event(path="/apps/index.php", new_hash="b" * 64), 0.55, 1.1, 2, "operator_review"
        )
        self.assertEqual(decision["category"], policy_gate.CATEGORY_WARNING)
        self.assertEqual(decision["action"], policy_gate.DEFAULT_ACTION)

    def test_gate_tidak_menyentuh_eksekusi(self):
        modul = [univers for univers in dir(policy_gate) if univers.lower().find("execut") >= 0]
        self.assertEqual(modul, [], f"policy_gate tidak boleh punya fungsi eksekusi: {modul}")


class TrajectoryTests(TahapBase):
    def event(self, path, seconds, old_hash=None, new_hash=None, host="server-a"):
        value = base_event(path=path, old_hash=old_hash, new_hash=new_hash, host_id=host)
        value["timestamp"] = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
        return value

    def test_hash_continuity_creates_strong_link_and_stable_trajectory(self):
        first = collector.store_event(self.event("/var/log/app.log", 0, new_hash="a" * 64))
        second = collector.store_event(self.event(
            "/var/log/app.log", 10, old_hash="a" * 64, new_hash="b" * 64,
        ))
        self.assertEqual(first["trajectory_id"], second["trajectory_id"])
        self.assertEqual(second["relationships"][0]["relation"], "STRONG_CORRELATION")
        self.assertEqual(second["relationships"][0]["confidence"], 0.9)
        self.assertEqual(collector.verify_evidence()["status"], "ok")
        with db.connect() as connection:
            rows = connection.execute("SELECT * FROM event_relationships").fetchall()
        self.assertEqual(len(rows), 1)

    def test_same_host_time_but_different_path_does_not_merge(self):
        first = collector.store_event(self.event("/var/log/app-a.log", 0, new_hash="a" * 64))
        second = collector.store_event(self.event(
            "/var/log/app-b.log", 1, old_hash="a" * 64, new_hash="b" * 64,
        ))
        self.assertNotEqual(first["trajectory_id"], second["trajectory_id"])
        self.assertEqual(second["relationships"], [])

    def test_same_path_without_hash_chain_needs_short_window(self):
        first = collector.store_event(self.event("/var/log/app.log", 0, new_hash="a" * 64))
        near = collector.store_event(self.event("/var/log/app.log", 45, new_hash="z" * 64))
        later = collector.store_event(self.event("/var/log/app.log", 120, new_hash="y" * 64))
        self.assertEqual(first["trajectory_id"], near["trajectory_id"])
        self.assertEqual(near["relationships"][0]["relation"], "MEDIUM_CORRELATION")
        self.assertNotEqual(near["trajectory_id"], later["trajectory_id"])

    def test_trajectory_has_bounded_lifetime(self):
        first = collector.store_event(self.event("/var/log/app.log", 0, new_hash="a" * 64))
        middle = collector.store_event(self.event("/var/log/app.log", 50, new_hash="b" * 64))
        after_limit = collector.store_event(self.event("/var/log/app.log", 650, new_hash="c" * 64))
        self.assertEqual(first["trajectory_id"], middle["trajectory_id"])
        self.assertNotEqual(middle["trajectory_id"], after_limit["trajectory_id"])

    def test_hash_match_from_other_host_does_not_correlate(self):
        first = collector.store_event(self.event("/var/log/app.log", 0, new_hash="a" * 64, host="server-a"))
        second = collector.store_event(self.event(
            "/var/log/app.log", 1, old_hash="a" * 64, new_hash="b" * 64, host="server-b",
        ))
        self.assertNotEqual(first["trajectory_id"], second["trajectory_id"])
        self.assertEqual(second["relationships"], [])

class IngestionWajibTests(TahapBase):
    def test_canary_langsung_pending_tanpa_eksekusi(self):
        event = base_event(
            path="/data/DEFNETT-LAB-CANARY.txt", content_signal=True,
            indicator="DEFNETT_LAB_CANARY", old_hash="a" * 64, new_hash="b" * 64,
        )
        result = collector.store_event(event)
        self.assertEqual(result["mode"], "PENDING_APPROVAL")
        self.assertEqual(result["policy_action"], "CONTAIN_CANARY")
        self.assertTrue(result["approval_id"])
        approval = approvals.get(result["approval_id"])
        self.assertEqual(approval["approval_status"], approvals.STATUS_PENDING)
        self.assertEqual(approval["execution_status"], approvals.EXECUTION_NONE)
        self.assertEqual(run_stage_keys(result["event_id"]), ["DETECTED"])
        with db.connect() as connection:
            row = connection.execute(
                "SELECT mode, response_action, policy_category, approval_id FROM events WHERE id = ?",
                (result["event_id"],),
            ).fetchone()
        self.assertEqual(row["mode"], "PENDING_APPROVAL")
        self.assertEqual(row["approval_id"], result["approval_id"])
        self.assertIn("pending_approval:", row["response_action"])
        self.assertIn(result["approval_id"], row["response_action"])

    def test_kunci_tampered_langsung_pending(self):
        result = collector.store_event(base_event(old_hash="d" * 64, new_hash="b" * 64))
        approval = approvals.get(result["approval_id"])
        self.assertEqual(approval["action"], "RESTORE_KEYS")
        self.assertEqual(approval["parameters"]["artifact"], "kunci")

    def test_event_biasa_tanpa_approval(self):
        result = collector.store_event(base_event(path="/apps/shop.php", old_hash=None, new_hash="b" * 64))
        self.assertEqual(result["mode"], "OPERATIONAL")
        self.assertIsNone(result["approval_id"])
        self.assertIsNone(latest_approval())
        self.assertEqual(run_stage_keys(result["event_id"]), [])

    def test_angka_eksternal_diolirkan(self):
        event = base_event(path="/apps/shop.php", new_hash="b" * 64)
        event["ml_score"] = 0.01
        event["p_attack_ml"] = 0.01
        event["risk_override"] = 0.01
        result = collector.store_event(event)
        # File_modified di TAHAP 0: p=0.55 dikali impact 2.0 -> risiko 1.1 dan level 2.
        self.assertEqual(result["risk"], round(0.55 * collector.IMPACT, 3))
        self.assertEqual(result["level"], 2)
        self.assertEqual(result["policy_category"], policy_gate.CATEGORY_WARNING)

    def test_restore_confirmed_tanpa_approval_baru(self):
        first = collector.store_event(base_event(new_hash="b" * 64))
        approvals.approve(first["approval_id"], "operator:penguji")
        approvals.claim(first["approval_id"], "executor:uji")
        approvals.complete(
            first["approval_id"], approvals.EXECUTION_DONE, "selesai",
            parameters_update={"restored": [{"path": "etc/kunci1.dat", "sha256": "b" * 64}]},
        )
        second = collector.store_event(base_event(new_hash="b" * 64))
        self.assertEqual(second["mode"], "OPERATIONAL")
        self.assertIsNone(second["approval_id"])
        self.assertEqual(second["policy_category"], policy_gate.CATEGORY_INFORMATIONAL)
        with db.connect() as connection:
            row = connection.execute(
                "SELECT policy_reasons, policy_category FROM events WHERE id = ?", (second["event_id"],)
            ).fetchone()
        self.assertIn("rule:restore_hash_same_as_recorded", json.loads(row["policy_reasons"]))
        self.assertEqual(row["policy_category"], policy_gate.CATEGORY_INFORMATIONAL)

    def test_integritas_rantai_berganti_belakang(self):
        result = collector.store_event(base_event(path="/var/log/x.log", new_hash="b" * 64))
        verified = collector.verify_evidence()
        self.assertEqual(verified["status"], "ok")
        self.assertGreaterEqual(verified["events"], 1)
        self.assertGreaterEqual(verified["fully_verified"], 1)
        self.assertTrue(result["integrity_hash"])


class ApprovalLifecycleTests(TahapBase):
    def make(self, action="RESTORE_KEYS", host="server-a", path="etc/kunci1.dat"):
        return approvals.create(
            action, host, path, {"artifact": "kunci", "survivor": "server-b"}, event_id=None,
        )

    def test_validasi_input(self):
        with self.assertRaises(approvals.ApprovalError):
            approvals.create("TUKAN_DUPLIKAT", "server-a", "etc/kunci1.dat", {})
        with self.assertRaises(approvals.ApprovalError):
            approvals.create("RESTORE_KEYS", "server-c", "etc/kunci1.dat", {})
        with self.assertRaises(approvals.ApprovalError):
            approvals.create("RESTORE_KEYS", "server-a", "", {})

    def test_context_koneksi_sqlite_menutup_descriptor(self):
        with db.connect() as connection:
            connection.execute("SELECT 1").fetchone()
        with self.assertRaises(sqlite3.ProgrammingError):
            connection.execute("SELECT 1")

    def test_approve_reject_claim_sekali_pakai(self):
        approval = self.make()
        self.assertEqual(approval["approval_status"], approvals.STATUS_PENDING)
        with self.assertRaises(approvals.ApprovalError):
            approvals.claim(approval["id"])  # belum disetujui
        approvals.approve(approval["id"], "operator:admin")
        with self.assertRaises(approvals.ApprovalError):
            approvals.approve(approval["id"], "operator:admin")
        claimed = approvals.claim(approval["id"], "executor awal")
        self.assertEqual(claimed["execution_status"], approvals.EXECUTION_CLAIMED)
        with self.assertRaises(approvals.ApprovalError):
            approvals.claim(approval["id"])

    def test_audit_transaksi_claim_dan_execution_terminal(self):
        approval = self.make()
        approvals.approve(approval["id"], "operator:admin")
        approvals.claim(approval["id"], "executor:test")
        approvals.complete(approval["id"], approvals.EXECUTION_DONE, "selesai")
        with db.connect() as connection:
            rows = connection.execute(
                "SELECT action, outcome FROM operator_audit WHERE detail LIKE ? ORDER BY id",
                (f"%{approval['id']}%",),
            ).fetchall()
        transitions = [(row["action"], row["outcome"]) for row in rows]
        self.assertEqual(transitions, [
            ("approval_create", approvals.STATUS_PENDING),
            ("approval_approve", approvals.STATUS_APPROVED),
            ("approval_claim", approvals.EXECUTION_CLAIMED),
            ("approval_complete", approvals.EXECUTION_DONE),
        ])
        with self.assertRaises(approvals.ApprovalError):
            approvals.complete(approval["id"], approvals.EXECUTION_FAILED, "hasil berbeda")

    def test_reject_membatalkan_tautan_event(self):
        peristiwa = collector.store_event(base_event(new_hash="b" * 64))
        approval = approvals.get(peristiwa["approval_id"])
        approvals.reject(approval["id"], "operator:admin", "pengujian")
        self.assertEqual(approvals.get(approval["id"])["approval_status"], approvals.STATUS_REJECTED)
        with db.connect() as connection:
            row = connection.execute("SELECT approval_id FROM events WHERE id = ?", (peristiwa["event_id"],)).fetchone()
        self.assertIsNone(row["approval_id"])

    def test_kedaluwarsa_sebelum_klaim(self):
        approval = self.make()
        approvals.approve(approval["id"], "operator:admin", ttl_seconds=10)
        with db.connect() as connection:
            connection.execute(
                "UPDATE operator_approvals SET expires_at = ? WHERE id = ?",
                ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), approval["id"]),
            )
        with self.assertRaises(approvals.ApprovalError) as caught:
            approvals.claim(approval["id"])
        self.assertEqual(str(caught.exception), "approval_expired")
        self.assertEqual(approvals.get(approval["id"])["approval_status"], approvals.STATUS_EXPIRED)

    def test_expiry_malformed_ditolak_fail_closed(self):
        approval = self.make()
        approvals.approve(approval["id"], "operator:admin")
        with db.connect() as connection:
            connection.execute(
                "UPDATE operator_approvals SET expires_at = ? WHERE id = ?",
                ("bukan-waktu", approval["id"]),
            )
        with self.assertRaises(approvals.ApprovalError) as caught:
            approvals.claim(approval["id"])
        self.assertEqual(str(caught.exception), "approval_expired")
        self.assertEqual(approvals.get(approval["id"])["approval_status"], approvals.STATUS_EXPIRED)

    def test_complete_dan_restore_hash(self):
        approval = self.make()
        approvals.approve(approval["id"], "operator:admin")
        approvals.claim(approval["id"])
        updated = approvals.complete(
            approval["id"], approvals.EXECUTION_DONE, "pulih",
            parameters_update={"restored": [
                {"path": "etc/kunci1.dat", "sha256": "c" * 64},
                {"path": "etc/kunci2.dat", "sha256": "d" * 64},
            ]},
        )
        self.assertEqual(updated["approval_status"], approvals.STATUS_APPROVED)
        mapping = approvals.restored_hashes()
        self.assertEqual(
            mapping,
            {("server-a", "etc/kunci1.dat"): "c" * 64, ("server-a", "etc/kunci2.dat"): "d" * 64},
        )
        # dan tidak dikenali event lain host berbeda
        self.assertNotIn(("server-b", "etc/kunci1.dat"), mapping)

    def test_pending_count(self):
        self.assertEqual(approvals.pending_count(), 0)
        self.make()
        self.assertEqual(approvals.pending_count(), 1)
        second = self.make(path="etc/kunci2.dat")
        approvals.approve(second["id"], "operator:admin")
        self.assertEqual(approvals.pending_count(), 1)


class FakeHAProxy:
    """Runtime HAProxy palsu: tahu disable/enable dan melaporkan status CSV."""

    def __init__(self, states=None, stuck=frozenset()):
        self.backends = {"server-a": "UP", "server-b": "UP"}
        self.backends.update(states or {})
        self.stuck = set(stuck)
        self.commands = []
        self.sock = None
        self.thread = None
        self.port = None
        self._running = False

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self._running = False
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept_loop(self):
        while self._running:
            try:
                connection, _ = self.sock.accept()
            except OSError:
                return
            try:
                data = connection.recv(4096).decode("utf-8", errors="replace")
                self.commands.append(data.strip())
                connection.sendall(self._answer(data.strip()).encode("utf-8"))
            except OSError:
                pass
            finally:
                try:
                    connection.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                connection.close()

    def _answer(self, command):
        first = command.split("\n")[0].strip()
        if first.startswith("show stat"):
            rows = ["# pxname,svname,status"]
            for name in sorted(self.backends):
                rows.append(f"defnett_servers,{name},{self.backends[name]}")
            return "\n".join(rows) + "\n"
        parts = first.split()
        if len(parts) >= 3 and parts[0] in ("disable", "enable"):
            name = parts[-1].rsplit("/", 1)[-1]
            if name in self.stuck:
                return "OK\n"
            if parts[0] == "disable":
                self.backends[name] = "MAINT"
            else:
                self.backends[name] = "UP"
            return "OK\n"
        return "ERROR unknown command\n"


class FakeRemediator:
    """Remediator tes jaringan: balasan per-test, mencatat badan permintaan."""

    def __init__(self):
        self.requests = []
        self.trusted = True
        self.reply = (200, {"status": "RESTORED_KEYS", "quarantine_path": "server-a-uji-KEYS-RESTORE.json",
                            "restored": [{"path": "etc/kunci1.dat", "sha256": "c" * 64}], "quarantined": []})
        self.httpd = None
        self.thread = None
        self.port = None

    def start(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def respond(self, status, payload):
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/healthz":
                    return self.respond(200, {"status": "ok"})
                if self.path == "/v1/trust":
                    return self.respond(200 if outer.trusted else 409, {"trusted": outer.trusted})
                return self.respond(404, {"error": "not_found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                outer.requests.append(json.loads(self.rfile.read(length)) if length else {})
                return self.respond(outer.reply[0], outer.reply[1])

            def log_message(self, *args):
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ContainmentBase(TahapBase):
    """Playbook executor lengkap dengan HAProxy + remediator palsu."""

    def setUp(self):
        super().setUp()
        self.haproxy = FakeHAProxy()
        self.remediator = FakeRemediator()
        self.haproxy.start()
        base_url = self.remediator.start()
        executor.HAPROXY_HOST = "127.0.0.1"
        executor.HAPROXY_RUNTIME_PORT = self.haproxy.port
        executor.REMEDIATOR_URLS = {
            "server-a": f"{base_url}/v1/repair",
            "server-b": f"{base_url}/v1/repair",
        }
        executor._sleep = lambda seconds: None

    def tearDown(self):
        self.haproxy.stop()
        self.remediator.stop()
        super().tearDown()

    def new_approval(self, host="server-a", path="etc/kunci1.dat"):
        approval = approvals.create(
            "RESTORE_KEYS", host, path, {"artifact": "kunci", "survivor": "server-b"},
            event_id=None, created_by="penguji",
        )
        approvals.approve(approval["id"], "operator:penguji")
        return approvals.claim(approval["id"], "executor:uji")


class ExecutorPlaybookTests(ContainmentBase):
    def make_rejoin(self, host="server-a", recovery_host=None, status="REPAIRED", trust=True):
        recovery_key = f"recovery-{host}"
        db.record_stage(recovery_key, status, "uji recovery", recovery_host or host,
                        "etc/kunci1.dat", complete=True)
        self.remediator.trusted = trust
        approval = approvals.create(
            "REJOIN_BACKEND", host, "haproxy", {"recovery_run_key": recovery_key},
            created_by="penguji",
        )
        approvals.approve(approval["id"], "operator:penguji")
        return approvals.claim(approval["id"], "executor:uji")

    def test_rejoin_tanpa_recovery_valid_gagal_tanpa_enable(self):
        approval = approvals.create("REJOIN_BACKEND", "server-a", "haproxy", {}, created_by="penguji")
        approvals.approve(approval["id"], "operator:penguji")
        claimed = approvals.claim(approval["id"], "executor:uji")
        executor.run_approval(claimed)
        self.assertEqual(approvals.get(approval["id"])["execution_detail"], "recovery_state_invalid")
        self.assertFalse(any(command.startswith("enable") for command in self.haproxy.commands))

    def test_rejoin_tolak_recovery_host_salah_dan_status_salah(self):
        for recovery_host, state in (("server-b", "REPAIRED"), ("server-a", "REPAIR_FAILED")):
            claimed = self.make_rejoin(recovery_host=recovery_host, status=state)
            executor.run_approval(claimed)
            self.assertEqual(approvals.get(claimed["id"])["execution_detail"], "recovery_state_invalid")
        self.assertFalse(any(command.startswith("enable") for command in self.haproxy.commands))

    def test_rejoin_master_tidak_tepercaya_gagal_tanpa_enable(self):
        claimed = self.make_rejoin(trust=False)
        executor.run_approval(claimed)
        self.assertEqual(approvals.get(claimed["id"])["execution_detail"], "master_untrusted_or_unavailable")
        self.assertFalse(any(command.startswith("enable") for command in self.haproxy.commands))

    def test_rejoin_health_check_gagal_diisolasi_kembali(self):
        self.haproxy.backends["server-a"] = "MAINT"
        self.haproxy.stuck.add("server-a")
        claimed = self.make_rejoin()
        executor.run_approval(claimed)
        self.assertEqual(approvals.get(claimed["id"])["execution_detail"], "backend_not_healthy_after_enable")
        self.assertEqual(self.haproxy.backends["server-a"], "MAINT")
        self.assertEqual(self.haproxy.commands[-1], "disable server defnett_servers/server-a")

    def test_rejoin_pulih_tepercaya_dan_health_check_lolos(self):
        self.haproxy.backends["server-a"] = "MAINT"
        claimed = self.make_rejoin()
        executor.run_approval(claimed)
        self.assertEqual(approvals.get(claimed["id"])["execution_status"], approvals.EXECUTION_DONE)
        self.assertEqual(self.haproxy.backends["server-a"], "UP")

    def test_isolasi_tidak_terkonfirmasi(self):
        fake = FakeHAProxy(stuck={"server-a"})
        fake.start()
        port_lama, sleep_lama = executor.HAPROXY_RUNTIME_PORT, executor._sleep
        executor.HAPROXY_RUNTIME_PORT = fake.port
        try:
            claimed = self.new_approval()
            executor.run_approval(claimed)
            stages = run_stage_keys(f"approval:{claimed['id']}")
            self.assertIn("ISOLATION_UNCONFIRMED", stages)
            self.assertEqual(stages[-1], "EXECUTION_FAILED")
            updated = approvals.get(claimed["id"])
            self.assertEqual(updated["approval_status"], approvals.STATUS_APPROVED)
            self.assertEqual(updated["execution_status"], approvals.EXECUTION_FAILED)
            # target tetap di-disable dua kali (percobaan + paksa)
            self.assertEqual(
                [command for command in fake.commands if command.startswith("disable")],
                ["disable server defnett_servers/server-a"] * 2,
            )
        finally:
            fake.stop()
            executor.HAPROXY_RUNTIME_PORT = port_lama
            executor._sleep = sleep_lama


    def test_pulih_sukses_full_playbook(self):
        claimed = self.new_approval()
        executor.run_approval(claimed)
        updated = approvals.get(claimed["id"])
        self.assertEqual(updated["approval_status"], approvals.STATUS_APPROVED)
        self.assertEqual(updated["execution_status"], approvals.EXECUTION_DONE)
        stages = run_stage_keys(f"approval:{claimed['id']}")
        self.assertEqual(stages[-1], "REPAIRED")
        self.assertIn("ISOLATION_CONFIRMED", stages)
        self.assertIn("VERIFYING", stages)
        self.assertIn("REJOINING", stages)
        self.assertNotIn("EXECUTION_FAILED", stages)
        mapping = approvals.restored_hashes()
        self.assertEqual(mapping.get(("server-a", "etc/kunci1.dat")), "c" * 64)
        self.assertIn("enable server defnett_servers/server-a",
                      " ; ".join(self.haproxy.commands))
        self.assertEqual(self.remediator.requests[0]["kind"], "kunci")

    def test_master_untrusted_ditolak(self):
        self.remediator.reply = (409, {"error": "repair_rejected", "detail": "master_untrusted:etc/kunci1.dat"})
        claimed = self.new_approval()
        executor.run_approval(claimed)
        updated = approvals.get(claimed["id"])
        self.assertEqual(updated["execution_status"], approvals.EXECUTION_FAILED)
        self.assertEqual(updated["execution_detail"], "master_untrusted_recovery_rejected")
        stages = run_stage_keys(f"approval:{claimed['id']}")
        self.assertIn("MASTER_UNTRUSTED", stages)
        self.assertEqual(stages[-1], "EXECUTION_FAILED")
        # Target tetap terisolasi: perintah terakhir adalah disable.
        self.assertEqual(self.haproxy.commands[-1], "disable server defnett_servers/server-a")

    def test_repair_ditolak_biasa(self):
        self.remediator.reply = (409, {"error": "repair_rejected", "detail": "keys_already_pristine"})
        claimed = self.new_approval()
        executor.run_approval(claimed)
        updated = approvals.get(claimed["id"])
        self.assertEqual(updated["execution_status"], approvals.EXECUTION_FAILED)
        stages = run_stage_keys(f"approval:{claimed['id']}")
        self.assertIn("REPAIR_FAILED", stages)
        self.assertNotIn("MASTER_UNTRUSTED", stages)
        self.assertEqual(stages[-1], "EXECUTION_FAILED")

    def test_survivor_tidak_sehat_tanpa_menyentuh(self):
        self.haproxy.backends["server-b"] = "DOWN"
        claimed = self.new_approval()
        executor.run_approval(claimed)
        updated = approvals.get(claimed["id"])
        self.assertEqual(updated["execution_status"], approvals.EXECUTION_FAILED)
        self.assertEqual(updated["execution_detail"], "survivor_not_healthy:server-b")
        self.assertEqual(run_stage_keys(f"approval:{claimed['id']}")[-1], "EXECUTION_FAILED")
        self.assertEqual(self.remediator.requests, [])
        disable_usaha = [c for c in self.haproxy.commands if c.startswith("disable")]
        self.assertEqual(disable_usaha, [])




class ExecutorServiceTests(TahapBase):
    def setUp(self):
        super().setUp()
        executor.EXECUTOR_TOKEN = "runit-token"
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), executor.Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def post(self, path, body, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            self.base + path, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def get(self, path, token=None):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(self.base + path, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_m2m_token_wajib(self):
        status, body = self.get("/v1/haproxy-states")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "unauthorized")
        status, body = self.get("/v1/haproxy-states", token="runit-token")
        self.assertEqual(status, 200)
        self.assertEqual(sorted(body["backends"]), ["server-a", "server-b"])
        self.assertEqual(body["workers"]["server-a"], "unavailable")

    def test_execute_klaim_dan_eksekusi_1x(self):
        approval = approvals.create(
            "REJOIN_BACKEND", "server-b", "haproxy", {"survivor": "server-a"}, created_by="penguji",
        )
        approvals.approve(approval["id"], "operator:penguji")
        status, body = self.post("/v1/execute", {"approval_id": approval["id"]}, token="runit-token")
        self.assertEqual(status, 202)
        self.assertTrue(body["accepted"])
        status, body = self.post("/v1/execute", {"approval_id": approval["id"]}, token="runit-token")
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "approval_already_used")

    def test_execute_token_salah(self):
        approval = approvals.create("REJOIN_BACKEND", "server-b", "haproxy", {"survivor": "server-a"})
        approvals.approve(approval["id"], "operator:penguji")
        status, body = self.post("/v1/execute", {"approval_id": approval["id"]}, token="bukan-token")
        self.assertEqual(status, 401)
        self.assertEqual(approvals.get(approval["id"])["execution_status"], approvals.EXECUTION_NONE)


class CollectorHTTPTests(TahapBase):
    def setUp(self):
        super().setUp()
        provision_operators.add_operator(operator_auth.AUTH_FILE, "admin", "operator", "kunci-rahasia-pengaman-9")
        provision_operators.add_operator(operator_auth.AUTH_FILE, "baca", "viewer", "pembaca-tetap-ygz-1")
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), collector.Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.port}"
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def request(self, method, path, payload=None, csrf=None, statuses=frozenset()):
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers[operator_auth.CSRF_HEADER] = csrf
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=5) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            except (json.JSONDecodeError, UnicodeDecodeError):
                return error.code, {}
            finally:
                error.close()

    def login(self, username, password):
        return self.request("POST", "/v1/operator/login", {"username": username, "password": password})

    def test_viewer_can_read_trajectory_endpoint(self):
        self.assertEqual(self.login("baca", "pembaca-tetap-ygz-1")[0], 200)
        status, body = self.request("GET", "/v1/trajectories")
        self.assertEqual(status, 200)
        self.assertEqual(body["trajectories"], [])

    def canary_approval(self):
        result = collector.store_event(base_event(
            path="/data/DEFNETT-LAB-CANARY.txt", content_signal=True,
            indicator="DEFNETT_LAB_CANARY", new_hash="b" * 64,
        ))
        return result["approval_id"]

    def test_whoami_get_mengembalikan_csrf_setelah_muat_ulang(self):
        # Dashboard memanggil GET whoami saat halaman dimuat ulang untuk mengambil CSRF.
        status, body = self.request("GET", "/v1/operator/whoami")
        self.assertEqual((status, body["authenticated"]), (200, False))
        _, login = self.login("admin", "kunci-rahasia-pengaman-9")
        status, body = self.request("GET", "/v1/operator/whoami")
        self.assertEqual(status, 200)
        self.assertTrue(body["authenticated"])
        self.assertEqual(body["csrf"], login["csrf"])

    def test_dashboard_wajib_sesi(self):
        status, body = self.request("GET", "/v1/dashboard")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "unauthorized")

    def test_login_gagal_dan_sukses(self):
        status, body = self.login("admin", "salah-banget")
        self.assertEqual(status, 401)
        self.assertEqual(body["error"], "kredensial_tidak_sah")
        status, body = self.login("admin", "kunci-rahasia-pengaman-9")
        self.assertEqual(status, 200)
        self.assertTrue(body["csrf"])
        self.assertTrue(any(cookie.name == operator_auth.SESSION_COOKIE for cookie in self.jar))
        status, body = self.request("GET", "/v1/dashboard")
        self.assertEqual(status, 200)
        self.assertEqual(body["analysis"]["approvals_required"], True)
        self.assertEqual(body["analysis"]["auto_repair_enabled"], False)

    def test_login_lockout_http(self):
        for _ in range(5):
            status, _ = self.login("admin", "salah-banget")
            self.assertEqual(status, 401)
        status, body = self.login("admin", "kunci-rahasia-pengaman-9")
        self.assertEqual(status, 429)
        self.assertEqual(body["error"], "too_many_failures")

    def test_logout_wajib_csrf_dan_restart_menghapus_sesi(self):
        status, login = self.login("admin", "kunci-rahasia-pengaman-9")
        self.assertEqual(status, 200)
        cookie = next(item for item in self.jar if item.name == operator_auth.SESSION_COOKIE)
        self.assertFalse(cookie.secure)  # HTTP only; deployment limitation is documented.
        self.assertIn("HttpOnly", cookie._rest)
        self.assertEqual(cookie._rest.get("SameSite"), "Strict")
        status, body = self.request("POST", "/v1/operator/logout")
        self.assertEqual(status, 403)
        status, body = self.request("POST", "/v1/operator/logout", csrf=login["csrf"])
        self.assertEqual(status, 200)
        self.assertFalse(operator_auth.get_session(cookie.value))

        self.login("admin", "kunci-rahasia-pengaman-9")
        active = next(item for item in self.jar if item.name == operator_auth.SESSION_COOKIE)
        operator_auth._sessions.clear()  # Simulasi restart collector (sesi hanya di memori).
        self.assertFalse(operator_auth.get_session(active.value))

    def test_viewer_tak_boleh_menyetujui(self):
        status, body = self.login("baca", "pembaca-tetap-ygz-1")
        self.assertEqual(status, 200)
        approval_id = self.canary_approval()
        status, body = self.request("POST", f"/v1/approvals/{approval_id}/approve")
        self.assertEqual(status, 401)


    def test_operator_setujui_dgn_csrf(self):
        status, login_data = self.login("admin", "kunci-rahasia-pengaman-9")
        csrf = login_data["csrf"]
        approval_id = self.canary_approval()
        status, body = self.request("POST", f"/v1/approvals/{approval_id}/approve", csrf=csrf)
        self.assertEqual(status, 202)  # executor tidak terjangkau: approval tetap APPROVED, submit ditunda
        self.assertEqual(body["approval"]["approval_status"], approvals.STATUS_APPROVED)
        self.assertIn("note", body)
        # tanpa CSRF ditolak kencang
        approval_id = self.canary_approval()
        status, body = self.request("POST", f"/v1/approvals/{approval_id}/approve")
        self.assertEqual(status, 403)

    def test_csrf_wajib_untuk_tindakan_post(self):
        status, login_data = self.login("admin", "kunci-rahasia-pengaman-9")
        csrf = login_data["csrf"]
        approval_id = self.canary_approval()
        status, body = self.request("POST", f"/v1/approvals/{approval_id}/reject", {"reason": "t"}, csrf="bukan-csrf")
        self.assertEqual(status, 403)
        status, body = self.request("POST", f"/v1/approvals/{approval_id}/reject", {"reason": "pengujian"}, csrf=csrf)
        self.assertEqual(status, 200)
        self.assertEqual(body["approval"]["approval_status"], approvals.STATUS_REJECTED)

    def test_tolak_menutup_insiden_agar_host_tidak_terkunci(self):
        _, login_data = self.login("admin", "kunci-rahasia-pengaman-9")
        approval_id = self.canary_approval()
        event_id = approvals.get(approval_id)["event_id"]
        status, _ = self.request("POST", f"/v1/approvals/{approval_id}/reject", {"reason": "uji"}, csrf=login_data["csrf"])
        self.assertEqual(status, 200)
        run = next(r for r in collector.remediation_rows(20) if r["event_id"] == event_id)
        self.assertEqual(run["status"], "REJECTED")
        self.assertIsNotNone(run["completed_at"])
        self.assertEqual([s["stage"] for s in run["steps"]], ["DETECTED", "REJECTED"])

    def test_operator_minta_syarangan_lab(self):
        status, login_data = self.login("admin", "kunci-rahasia-pengaman-9")
        csrf = login_data["csrf"]
        status, body = self.request("POST", "/v1/lab/attack/server-c?vector=web", csrf=csrf)
        self.assertEqual(status, 404)
        status, body = self.request("POST", "/v1/lab/attack/server-a?vector=nb", csrf=csrf)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "unknown_vector")
        status, body = self.request("POST", "/v1/lab/attack/server-a?vector=web", csrf=csrf)
        self.assertEqual(status, 202)
        self.assertEqual(body["approval_status"], "APPROVED")
        approval = approvals.get(body["approval_id"])
        self.assertEqual(approval["action"], "SIMULATE_LAB_ATTACK")
        self.assertTrue(approval["created_by"].startswith("operator:"))
        self.assertEqual(approval["approval_status"], approvals.STATUS_APPROVED)

    def test_technical_401_untuk_tanpa_sesi_serangan(self):
        status, body = self.request("POST", "/v1/lab/attack/server-a?vector=web")
        self.assertEqual(status, 401)
        status, approval = self.request("GET", "/v1/approvals")
        self.assertEqual(status, 401)




class MasterTrustTests(TahapBase):
    def setUp(self):
        super().setUp()
        self.master = Path(self.tmp) / "master"
        self.manifest = Path(self.tmp) / "manifest" / "keys.json"
        remediator.MASTER = self.master
        remediator.MANIFEST_PATH = self.manifest
        remediator.TARGET = Path(self.tmp) / "target"
        remediator.QUARANTINE = Path(self.tmp) / "quarantine"

    def seed_master(self):
        source = Path(self.tmp) / "source"
        (source / "etc").mkdir(parents=True, exist_ok=True)
        (source / "etc" / "kunci1.dat").write_bytes(b"SECRET kunci1 (host-lab)\n")
        (source / "etc" / "kunci2.dat").write_bytes(b"SECRET kunci2 (host-lab)\n")
        provision_master.provision(source, self.master, self.manifest)
        return b"SECRET kunci1 (host-lab)\n", b"SECRET kunci2 (host-lab)\n"

    def seed_target(self, konten1, konten2):
        target = remediator.TARGET
        (target / "etc").mkdir(parents=True, exist_ok=True)
        (target / "etc" / "kunci1.dat").write_bytes(konten1)
        (target / "etc" / "kunci2.dat").write_bytes(konten2)

    def test_cli_main_menulis_master_dan_manifes(self):
        source = Path(self.tmp) / "source-cli"
        (source / "etc").mkdir(parents=True)
        (source / "etc" / "kunci1.dat").write_bytes(b"SECRET kunci1 (cli)\n")
        (source / "etc" / "kunci2.dat").write_bytes(b"SECRET kunci2 (cli)\n")
        rc = provision_master.main(["--source", str(source), "--master", str(self.master),
                                    "--manifest", str(self.manifest), "--force"])
        self.assertEqual(rc, 0)
        self.assertEqual((self.master / "kunci1.dat").read_bytes(), b"SECRET kunci1 (cli)\n")
        self.assertIn("kunci2.dat", json.loads(self.manifest.read_text())["files"])

    def test_provision_menulis_manifes_ok(self):
        self.seed_master()
        entries = json.loads(self.manifest.read_text(encoding="utf-8"))["files"]
        for name, konten in (("kunci1.dat", b"SECRET kunci1 (host-lab)\n"), ("kunci2.dat", b"SECRET kunci2 (host-lab)\n")):
            self.assertEqual(
                entries[name]["sha256"],
                hashlib.sha256((self.master / name).read_bytes()).hexdigest(),
            )
        verified = remediator.verify_masters()
        self.assertEqual(verified["etc/kunci1.dat"], b"SECRET kunci1 (host-lab)\n")

    def test_tanpa_manifes_tolak(self):
        self.manifest.unlink(missing_ok=True)
        with self.assertRaises(ValueError) as caught:
            remediator.verify_masters()
        self.assertIn("master_untrusted:manifest_missing", str(caught.exception))

    def test_manifes_invalid_tolak(self):
        self.seed_master()
        self.manifest.write_text(json.dumps({"version": 2, "files": {}}), encoding="utf-8")
        with self.assertRaises(ValueError) as caught:
            remediator.verify_masters()
        self.assertIn("master_untrusted:manifest_invalid", str(caught.exception))

    def test_provision_tidak_menimpa_master_lama_otomatis(self):
        self.seed_master()
        original = (self.master / "kunci1.dat").read_bytes()
        source = Path(self.tmp) / "source" / "etc" / "kunci1.dat"
        source.write_bytes(b"SECRET kunci1 baseline yang lain\n")
        with self.assertRaises(SystemExit):
            provision_master.provision(source.parents[1], self.master, self.manifest)
        self.assertEqual((self.master / "kunci1.dat").read_bytes(), original)

    def test_master_tampered_tolak(self):
        self.seed_master()
        (self.master / "kunci1.dat").write_bytes(b"SECRET kunci1 diganti penyusup\n")
        with self.assertRaises(ValueError) as caught:
            remediator.verify_masters()
        self.assertEqual(str(caught.exception), "master_untrusted:etc/kunci1.dat")

    def test_remadiator_tanpa_seed_oto(self):
        self.assertFalse(hasattr(remediator, "ensure_masters"))

    def test_quarantine_keys_pulih_dari_master_tepercaya(self):
        master1, master2 = self.seed_master()
        tampered = b"SECRET kunci1 (host-lab)\nDEFNETT-LAB-ATTACK-SIM scribble\n"
        self.seed_target(tampered, master2)
        result = remediator.quarantine_keys()
        self.assertEqual(result["status"], "RESTORED_KEYS")
        self.assertEqual(result["restored"], [{"path": "etc/kunci1.dat", "sha256": hashlib.sha256(master1).hexdigest(), "bytes": len(master1)}])
        self.assertEqual((remediator.TARGET / "etc" / "kunci1.dat").read_bytes(), master1)
        self.assertEqual((remediator.TARGET / "etc" / "kunci2.dat").read_bytes(), master2)
        evidence = Path(self.tmp) / result["quarantine_path"]
        self.assertTrue(evidence.exists())
        lines = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(lines["restored"][0]["path"], "etc/kunci1.dat")

    def test_quarantine_kunci_sudah_asli_tolak(self):
        master1, master2 = self.seed_master()
        self.seed_target(master1, master2)
        with self.assertRaises(ValueError) as caught:
            remediator.quarantine_keys()
        self.assertEqual(str(caught.exception), "keys_already_pristine")

    def test_master_tidak_percaya_tanpa_benarkan_target(self):
        self.seed_master()
        tampered = b"SECRET kunci1 master musuh\n"
        self.seed_target(tampered, b"SECRET kunci2 apa-apa\n")
        (self.master / "kunci1.dat").write_bytes(b"SECRET kunci1 HEHEHE\n")
        with self.assertRaises(ValueError) as caught:
            remediator.quarantine_keys()
        self.assertEqual(str(caught.exception), "master_untrusted:etc/kunci1.dat")
        # target tidak ditulis (pun tak disentuh karantina).
        self.assertEqual((remediator.TARGET / "etc" / "kunci1.dat").read_bytes(), tampered)
        self.assertFalse(list(remediator.QUARANTINE.iterdir()) if remediator.QUARANTINE.exists() else False)




class RiskEngineTests(unittest.TestCase):
    def test_missing_critical_inputs_is_insufficient(self):
        result = risk_engine.assess({}, threat_indicator_strength=80, evidence_confidence=80)
        self.assertEqual(result["risk_level"], "INSUFFICIENT_EVIDENCE")
        self.assertIsNone(result["risk_score"])
        self.assertIn("telemetry_quality", result["missing_evidence"])

    def test_reproducible_and_explicit_not_probability(self):
        values = dict(threat_indicator_strength=65, asset_impact=70, evidence_confidence=75,
                      telemetry_quality=70, correlation_strength=40, operational_context=20)
        first = risk_engine.assess({}, **values)
        second = risk_engine.assess({}, **values)
        self.assertEqual(first, second)
        self.assertEqual(first["score_type"], "weighted_ordinal_not_probability")
        self.assertEqual(first["risk_level"], "HIGH")

    def test_weight_configuration_rejects_unexpected_keys(self):
        with self.assertRaises(ValueError):
            risk_engine.assess({}, threat_indicator_strength=20, weights={"unexpected": 1})


class ModbusVerticalSliceTests(TahapBase):
    def setUp(self):
        super().setUp()
        self.old_token = collector.OT_API_TOKEN
        self.old_device = collector.OT_ALLOWED_DEVICE_ID
        self.old_gateway_host = collector.OT_GATEWAY_HOST
        self.old_gateway_port = collector.OT_GATEWAY_PORT
        collector.OT_API_TOKEN = "ot-test-token"
        collector.OT_ALLOWED_DEVICE_ID = "OT-SIM-01"
        self.collector_http = ThreadingHTTPServer(("127.0.0.1", 0), collector.Handler)
        self.collector_port = self.collector_http.server_address[1]
        self.collector_thread = threading.Thread(target=self.collector_http.serve_forever, daemon=True)
        self.collector_thread.start()
        self.outbox = modbus_lab.Outbox(
            os.path.join(self.tmp, "ot", "outbox.sqlite3"),
            f"http://127.0.0.1:{self.collector_port}", "ot-test-token",
        )
        self.policy = {
            "device_id": "OT-SIM-01", "unit_ids": [1], "read_ranges": [[100, 110]],
            "write_registers": [120], "initial_registers": {100: 42, 120: 0},
            "policy_id": "test-policy", "asset_impact": 55,
        }
        self.gateway = modbus_lab.ModbusLabServer(
            ("127.0.0.1", 0), self.policy, [ipaddress.ip_network("127.0.0.1/32")],
            dict(self.policy["initial_registers"]), self.outbox,
        )
        self.gateway_thread = threading.Thread(target=self.gateway.serve_forever, daemon=True)
        self.gateway_thread.start()
        self.port = self.gateway.server_address[1]
        collector.OT_GATEWAY_HOST = "127.0.0.1"
        collector.OT_GATEWAY_PORT = self.port

    def tearDown(self):
        self.gateway.shutdown()
        self.gateway.server_close()
        self.outbox.close()
        self.collector_http.shutdown()
        self.collector_http.server_close()
        collector.OT_API_TOKEN = self.old_token
        collector.OT_ALLOWED_DEVICE_ID = self.old_device
        collector.OT_GATEWAY_HOST = self.old_gateway_host
        collector.OT_GATEWAY_PORT = self.old_gateway_port
        super().tearDown()

    def wait_events(self, count):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if len(collector.event_rows(100)) >= count:
                return collector.event_rows(100)
            time.sleep(0.05)
        self.fail(f"collector did not receive {count} OT events")

    def test_real_tcp_read_allowed_write_denied_and_unknown_unit(self):
        read_response = modbus_lab.client_transaction("127.0.0.1", self.port, 3, 100, 1)
        self.assertEqual(read_response[-4:], bytes([3, 2, 0, 42]))
        allowed_write = modbus_lab.client_transaction("127.0.0.1", self.port, 6, 120, 7)
        self.assertEqual(allowed_write[-5:], modbus_lab.encode_request(1, 1, 6, 120, 7)[7:])
        denied_write = modbus_lab.client_transaction("127.0.0.1", self.port, 6, 121, 9)
        self.assertEqual(denied_write[-2:], bytes([0x86, 2]))
        unknown_unit = modbus_lab.client_transaction("127.0.0.1", self.port, 3, 100, 1, unit_id=2)
        self.assertEqual(unknown_unit[-2:], bytes([0x83, 1]))
        rows = self.wait_events(4)
        self.assertEqual(collector.ot_sensor_state()["status"], "LIVE_LAB_TELEMETRY")
        ot_rows = [r for r in rows if r["event_type"].startswith("OT_")]
        self.assertEqual(len(ot_rows), 4)
        denial = next(r for r in ot_rows if json.loads(r["canonical_json"])["policy_reason"] == "write_register_out_of_policy")
        self.assertEqual(denial["policy_category"], policy_gate.CATEGORY_WARNING)
        self.assertEqual(denial["response_action"], "none")
        self.assertTrue(json.loads(denial["canonical_json"])["evidence_reference"].startswith("sha256:"))
        self.assertIsNotNone(denial["risk_assessment_json"])
        self.assertEqual(collector.verify_evidence()["status"], "ok")

    def test_duplicate_request_is_idempotent_in_evidence_ledger(self):
        modbus_lab.client_transaction("127.0.0.1", self.port, 3, 100, 1)
        self.wait_events(1)
        modbus_lab.client_transaction("127.0.0.1", self.port, 3, 100, 1)
        time.sleep(0.4)
        self.assertEqual(len(collector.event_rows(100)), 1)
        self.assertEqual(collector.verify_evidence()["status"], "ok")

    def test_unknown_source_is_denied_and_recorded(self):
        request = modbus_lab.encode_request(77, 1, 3, 100, 1)
        try:
            conn = socket.create_connection(("127.0.0.1", self.port), timeout=2, source_address=("127.0.0.2", 0))
        except OSError:
            # macOS hanya memasang 127.0.0.1 di loopback; Linux memakai seluruh 127/8.
            self.skipTest("alamat sumber 127.0.0.2 tidak tersedia di host ini")
        with conn as sock:
            sock.sendall(request)
            response = sock.recv(260)
        self.assertEqual(response[-2:], bytes([0x83, 1]))
        rows = self.wait_events(1)
        self.assertEqual(json.loads(rows[0]["canonical_json"])["policy_reason"], "source_not_allowlisted")

    def test_unsupported_function_is_denied_and_recorded(self):
        pdu = bytes([16, 0, 100, 0, 1])
        request = struct.pack(">HHHB", 81, 0, len(pdu) + 1, 1) + pdu
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.sendall(request)
            response = sock.recv(260)
        self.assertEqual(response[-2:], bytes([0x90, 1]))
        rows = self.wait_events(1)
        self.assertEqual(json.loads(rows[0]["canonical_json"])["policy_reason"], "function_code_not_allowed")

    def test_denial_relationship_requires_matching_ot_context(self):
        modbus_lab.client_transaction("127.0.0.1", self.port, 6, 120, 7, transaction_id=41)
        self.wait_events(1)
        self.gateway.policy["write_registers"].clear()
        response = modbus_lab.client_transaction("127.0.0.1", self.port, 6, 120, 8, transaction_id=42)
        self.assertEqual(response[-2:], bytes([0x86, 2]))
        rows = self.wait_events(2)
        self.assertEqual(rows[0]["trajectory_id"], rows[1]["trajectory_id"])
        with db.connect(collector.DB_PATH) as connection:
            edge = connection.execute("SELECT relation,reason FROM event_relationships").fetchone()
        self.assertIsNotNone(edge)
        self.assertEqual(edge["relation"], "MEDIUM_CORRELATION")
        self.assertEqual(edge["reason"], "same_device_source_unit_register_with_policy_denial")

    def test_cross_domain_context_is_not_correlated_by_time_alone(self):
        it_event = {
            "host_id": "server-a", "source": "agent", "event_type": "file_modified",
            "path": "etc/example", "timestamp": modbus_lab.utc_now(),
            "old_hash": "a" * 64, "new_hash": "b" * 64,
        }
        collector.store_event(it_event)
        modbus_lab.client_transaction("127.0.0.1", self.port, 6, 121, 7, transaction_id=43)
        self.wait_events(2)
        with db.connect(collector.DB_PATH) as connection:
            ids = connection.execute("SELECT trajectory_id,event_type FROM events ORDER BY rowid").fetchall()
        it = next(row for row in ids if row["event_type"] == "file_modified")
        ot = next(row for row in ids if row["event_type"] == "OT_MODBUS_TRANSACTION")
        self.assertNotEqual(it["trajectory_id"], ot["trajectory_id"])
        with db.connect(collector.DB_PATH) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM event_relationships").fetchone()[0], 0)

    def test_malformed_mbap_is_rejected_and_recorded(self):
        malformed = struct.pack(">HHHB", 9, 0, 1, 1)
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.sendall(malformed)
        rows = self.wait_events(1)
        self.assertEqual(rows[0]["event_type"], "OT_FRAME_REJECTED")
        self.assertEqual(json.loads(rows[0]["canonical_json"])["telemetry_quality"], 15)

    def test_simulator_unavailable_is_a_connection_failure(self):
        with socket.socket() as probe:
            with self.assertRaises(OSError):
                probe.connect(("127.0.0.1", 1))

    def test_ot_endpoint_requires_dedicated_token(self):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.collector_port}/v1/ot/events", data=b"{}",
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=2)
        try:
            self.assertEqual(caught.exception.code, 401)
        finally:
            caught.exception.close()

if __name__ == "__main__":
    unittest.main()
