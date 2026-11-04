"""Executor: satu-satunya proses yang memegang akses HAProxy runtime dan remediator.

Semua eksekusi diambil dari approval yang telah disetujui operator di tabel
operator_approvals dan diklaim dengan pembaruan atomik (satu kali, kedaluwarsa).
Fail-closed: kegagalan tahap tidak pernah dilaporkan sukses, dan target yang
gagal pemulihannya tetap diisolasi di HAProxy. Proses ini tidak menyentuh teks
analitik, tidak membuat approval sendiri, dan tidak punya sertifikat agen.
"""
import csv
import hmac
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import approvals
import authority_client
import db
import tls_support

HTTP_PORT = int(os.environ.get("EXECUTOR_PORT", "8092"))
HTTP_HOST = os.environ.get("EXECUTOR_BIND_HOST", "0.0.0.0")
EXECUTOR_TOKEN = os.environ.get("EXECUTOR_API_TOKEN", "")
APPROVAL_EXECUTOR_TOKEN = authority_client.EXECUTOR_TOKEN
APPROVAL_TEST_ADAPTER = None
REMEDIATOR_TOKEN = os.environ.get("LAB_API_TOKEN", "")
HAPROXY_HOST = os.environ.get("HAPROXY_HOST", "haproxy")
HAPROXY_RUNTIME_PORT = int(os.environ.get("HAPROXY_RUNTIME_PORT", "9999"))
REMEDIATOR_URLS = {
    "server-a": os.environ.get("REMEDIATOR_URL_SERVER_A", "http://remediator-a:8091/v1/repair"),
    "server-b": os.environ.get("REMEDIATOR_URL_SERVER_B", "http://remediator-b:8091/v1/repair"),
}
DEMO_REPAIR_HOST = os.environ.get("DEMO_REPAIR_HOST", "server-a")
POLL_SECONDS = max(0.2, float(os.environ.get("EXECUTOR_POLL_SECONDS", "1")))
ATTACK_ENTRY_SECONDS = 5
LAB_ATTACK_PORTS = {"ssh": 22, "web": 80}

_sleep = time.sleep


def authority_approval(path, payload=None, method="POST"):
    if APPROVAL_TEST_ADAPTER is not None:
        if path == "/internal/claim":
            return {"approval": APPROVAL_TEST_ADAPTER.claim(payload["approval_id"], "executor")}
        if path == "/internal/get":
            return {"approval": APPROVAL_TEST_ADAPTER.get(payload["approval_id"])}
        if path == "/internal/complete":
            return {"approval": APPROVAL_TEST_ADAPTER.complete(
                payload["approval_id"], payload["outcome"], payload["detail"], payload.get("parameters_update")
            )}
        if path == "/internal/pending":
            return {"approval_ids": [item["id"] for item in APPROVAL_TEST_ADAPTER.list_approvals(200)
                                     if item["approval_status"] == approvals.STATUS_APPROVED
                                     and item["execution_status"] == approvals.EXECUTION_NONE]}
        raise approvals.ApprovalError("authority_endpoint_not_found")
    status, result, _ = authority_client.request(
        path, method=method, payload=payload, token=APPROVAL_EXECUTOR_TOKEN, timeout=4,
    )
    if status < 200 or status >= 300:
        raise approvals.ApprovalError(str(result.get("error", f"authority_http_{status}")))
    return result


def complete_approval(approval_id, outcome, detail, parameters_update=None):
    result = authority_approval("/internal/complete", {
        "approval_id": approval_id, "outcome": outcome, "detail": detail,
        "parameters_update": parameters_update,
    })
    return result["approval"]


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def format_duration(seconds):
    return f"{seconds // 60} menit" if seconds >= 60 and seconds % 60 == 0 else f"{seconds} detik"


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
            return row.get("status", "").strip() == "UP"
    return False


def wait_for_backend(server_name, expected_up, attempts=10):
    for _ in range(attempts):
        if backend_is_up(server_name) is expected_up:
            return True
        _sleep(0.5)
    return False


def backend_states():
    result = {"server-a": "UNKNOWN", "server-b": "UNKNOWN"}
    try:
        lines = haproxy_command("show stat").splitlines()
        if not lines:
            return result
        header = lines[0].lstrip("# ").split(",")
        for row in csv.DictReader(lines[1:], fieldnames=header):
            name = row.get("svname")
            if row.get("pxname") == "defnett_servers" and name in result:
                result[name] = row.get("status", "UNKNOWN")
    except (OSError, socket.timeout, UnicodeError, ValueError):
        pass
    return result


def remediator_health(host_id):
    url = REMEDIATOR_URLS.get(host_id, "").rsplit("/", 2)[0] + "/healthz"
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            return "ready" if response.status == 200 else "unavailable"
    except (OSError, urllib.error.URLError, TimeoutError, ValueError) as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        return "unavailable"


def remediator_trusted(host_id):
    """Periksa ulang master + manifest di worker sebelum mengaktifkan backend."""
    base = REMEDIATOR_URLS.get(host_id, "").rsplit("/", 2)[0]
    request = urllib.request.Request(base + "/v1/trust", headers=internal_headers())
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            payload = json.loads(response.read())
            return response.status == 200 and payload.get("trusted") is True
    except (OSError, urllib.error.URLError, TimeoutError, ValueError) as error:
        if isinstance(error, urllib.error.HTTPError):
            error.close()
        return False


def worker_states():
    return {host: remediator_health(host) for host in sorted(db.ALLOWED_HOSTS)}


def internal_headers():
    headers = {"Content-Type": "application/json"}
    if REMEDIATOR_TOKEN:
        headers["Authorization"] = f"Bearer {REMEDIATOR_TOKEN}"
    return headers


def request_remediation(host_id, kind, run_key):
    """Minta worker host target menjalankan karantina/pemulihan. Tolak balasan
    yang tidak lengkap: status wajib sesuai kind dan jalur karantina wajib ada."""
    payload = json.dumps({"host_id": host_id, "event_id": run_key, "kind": kind}).encode("utf-8")
    request = urllib.request.Request(
        REMEDIATOR_URLS[host_id], data=payload, headers=internal_headers(), method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status != 200:
                raise RuntimeError(f"remediator_returned_http_{response.status}")
            result = json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read())
        except (ValueError, UnicodeDecodeError):
            body = {}
        finally:
            error.close()
        raise RuntimeError(str(body.get("detail") or body.get("error") or f"remediator_http_{error.code}")) from None
    expected_status = "RESTORED_KEYS" if kind == "kunci" else "QUARANTINED_CANARY"
    if result.get("status") != expected_status or not result.get("quarantine_path"):
        raise RuntimeError(str(result.get("detail", "remediation_not_verified")))
    return result


def request_lab_attack(host_id):
    request = urllib.request.Request(
        REMEDIATOR_URLS[host_id].rsplit("/", 1)[0] + "/lab/attack",
        data=json.dumps({"host_id": host_id}).encode("utf-8"),
        headers=internal_headers(),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read())
    except urllib.error.HTTPError as error:
        try:
            body = json.loads(error.read())
        except (ValueError, UnicodeDecodeError):
            body = {}
        finally:
            error.close()
        raise RuntimeError(str(body.get("detail") or body.get("error") or "attack_rejected")) from None
    if result.get("status") != "ATTACK_SIMULATED":
        raise RuntimeError(str(result.get("detail", "attack_not_verified")))
    return result


def set_stage(run_key, host_id, path, status, detail, quarantine_path=None, complete=False, parameters=None):
    db.record_stage(
        run_key, status, detail,
        host_id=host_id, path=path,
        quarantine_path=quarantine_path,
        complete=complete,
        detect_seconds=parameters.get("detect_seconds") if parameters else None,
        entry=parameters.get("entry") if parameters else None,
    )


def _update_event(approval, response_action):
    if approval.get("event_id"):
        db.update_event_response(approval["event_id"], "OPERATIONAL", response_action)


def run_containment(approval):
    """Playbook isolasi, karantina/pemulihan, verifikasi, dan rejoin."""
    payload = approval.get("parameters", {})
    host_id = approval["host_id"]
    artifact = "kunci" if payload.get("artifact") == "kunci" else "canary"
    kind = "kunci" if artifact == "kunci" else "canary"
    survivor = "server-b" if host_id == "server-a" else "server-a"
    run_key = approval.get("event_id") or f"approval:{approval['id']}"
    delay = payload.get("delay_seconds")
    delay = delay if isinstance(delay, int) and not isinstance(delay, bool) and delay >= 0 else None
    failure_detail = None

    set_stage(run_key, host_id, approval["path"], "EXECUTING",
              f"Approval {approval['id'][:8]} disetujui operator; playbook respons dimulai.",
              parameters=payload)
    _update_event(approval, f"execution_started:{approval['id']}")
    try:
        if not backend_is_up(survivor):
            set_stage(run_key, host_id, approval["path"], "EXECUTION_FAILED",
                      f"{survivor} tidak sehat; {host_id} tidak diubah agar layanan tetap tersedia.",
                      complete=True, parameters=payload)
            complete_approval(approval["id"], approvals.EXECUTION_FAILED, f"survivor_not_healthy:{survivor}")
            _update_event(approval, f"survivor_not_healthy:{survivor}")
            return
        set_stage(run_key, host_id, approval["path"], "EXECUTING",
                  f"Mengeluarkan {host_id} saja dari rotasi HAProxy.", parameters=payload)
        haproxy_command(f"disable server defnett_servers/{host_id}")
        if not wait_for_backend(host_id, False):
            set_stage(run_key, host_id, approval["path"], "ISOLATION_UNCONFIRMED",
                      f"HAProxy belum mengonfirmasi isolasi {host_id}; memaksa mati kembali.",
                      parameters=payload)
            haproxy_command(f"disable server defnett_servers/{host_id}")
            set_stage(run_key, host_id, approval["path"], "EXECUTION_FAILED",
                      f"Isolasi {host_id} tidak terverifikasi; host tidak diubah lebih jauh.", complete=True, parameters=payload)
            complete_approval(approval["id"], approvals.EXECUTION_FAILED, f"target_isolation_not_confirmed:{host_id}")
            _update_event(approval, f"target_isolation_not_confirmed:{host_id}")
            return
        set_stage(run_key, host_id, approval["path"], "ISOLATION_CONFIRMED",
                  f"{host_id} terisolasi; {survivor} tetap aktif dan tidak diubah.", parameters=payload)
        if delay:
            set_stage(run_key, host_id, approval["path"], "REPAIRING",
                      f"Demo: perbaikan {host_id} berlangsung {format_duration(delay)}; host tetap terisolasi.",
                      parameters=payload)
            _sleep(delay)
        else:
            set_stage(run_key, host_id, approval["path"], "REPAIRING",
                      f"Worker {host_id} mengarantina artefak {artifact} pada host itu saja.", parameters=payload)
        repair = request_remediation(host_id, kind, run_key)
        set_stage(run_key, host_id, approval["path"], "VERIFYING",
                  f"{'Kunci' if artifact == 'kunci' else 'Canary'} {host_id} dipulihkan; menunggu health check.",
                  quarantine_path=repair["quarantine_path"], parameters=payload)
        haproxy_command(f"enable server defnett_servers/{host_id}")
        set_stage(run_key, host_id, approval["path"], "REJOINING",
                  f"HAProxy memeriksa {host_id} sebelum menerima trafik.", parameters=payload)
        if not wait_for_backend(host_id, True, attempts=20):
            haproxy_command(f"disable server defnett_servers/{host_id}")
            set_stage(run_key, host_id, approval["path"], "HEALTH_CHECK_FAILED",
                      f"Health check gagal; {host_id} tetap terisolasi.", parameters=payload)
            set_stage(run_key, host_id, approval["path"], "EXECUTION_FAILED",
                      f"Playbook berhenti dari HEALTH_CHECK_FAILED; {host_id} tetap diisolasi.", complete=True, parameters=payload)
            complete_approval(approval["id"], approvals.EXECUTION_FAILED, f"health_check_failed:{host_id}_remains_isolated")
            _update_event(approval, f"health_check_failed:{host_id}")
            return
        restored = repair.get("restored") or []
        set_stage(run_key, host_id, approval["path"], "REPAIRED",
                  f"Health check {host_id} lolos; {host_id} aktif kembali. {survivor} tidak diubah.",
                  quarantine_path=repair["quarantine_path"], complete=True, parameters=payload)
        complete_approval(
            approval["id"], approvals.EXECUTION_DONE, f"auto_repaired_and_rejoined_{host_id}",
            parameters_update={"restored": restored, "quarantine_path": repair["quarantine_path"]},
        )
        _update_event(approval, f"AUTO_REPAIRED_AND_REJOINED_{host_id.upper().replace('-', '_')}")
    except Exception as error:  # noqa: BLE001 - fail-closed: semua kegagalan jadi EXECUTION_FAILED
        detail = str(error) or type(error).__name__
        try:
            haproxy_command(f"disable server defnett_servers/{host_id}")
        except (OSError, socket.timeout, UnicodeError):
            pass
        if "master_untrusted:" in detail:
            set_stage(run_key, host_id, approval["path"], "MASTER_UNTRUSTED",
                      f"Master tidak cocok manifes; pemulihan ditolak: {detail}", parameters=payload)
        else:
            failure_detail = detail
            set_stage(run_key, host_id, approval["path"], "REPAIR_FAILED",
                      f"Perbaikan {host_id} gagal: {detail}; host tetap diisolasi.", parameters=payload)
        set_stage(run_key, host_id, approval["path"], "EXECUTION_FAILED",
                  f"Playbook berhenti: {type(error).__name__}; {host_id} tetap diisolasi, {survivor} tidak diubah.",
                  complete=True, parameters=payload)
        tag = "master_untrusted_recovery_rejected" if "master_untrusted:" in detail else (f"repair_failed:{host_id}:{detail[:96]}")
        complete_approval(approval["id"], approvals.EXECUTION_FAILED, tag)
        _update_event(approval, f"repair_failed:{host_id}:{type(error).__name__}")


def run_simulate(approval):
    """Simulasi pencurian lab untuk persetujuan operator: mengarantina tidak diperlukan.

    Gagal pemeriksaan awal atau permintaan worker berarti approval FAILED dan
    tidak ada pengubahan file kunci."""
    payload = approval.get("parameters", {})
    host_id = approval["host_id"]
    survivor = "server-b" if host_id == "server-a" else "server-a"
    vector = payload.get("vector")
    if vector is not None and vector not in LAB_ATTACK_PORTS:
        vector = None
    try:
        if not backend_is_up(host_id):
            complete_approval(approval["id"], approvals.EXECUTION_FAILED, "target_not_up")
            return
        if not backend_is_up(survivor):
            complete_approval(approval["id"], approvals.EXECUTION_FAILED, f"survivor_not_healthy:{survivor}")
            return
        if vector is not None:
            db.store_patrol_event({
                "type": "alert", "actor": "police", "action": "login", "host_id": host_id,
                "path": f"simulasi-{vector}", "severity": "suspicious", "status": "allowed",
                "port": LAB_ATTACK_PORTS[vector],
            })
            _sleep(ATTACK_ENTRY_SECONDS)
        result = request_lab_attack(host_id)
        complete_approval(approval["id"], approvals.EXECUTION_DONE, str(result.get("action") or "ATTACK_SIMULATED"))
    except Exception as error:  # noqa: BLE001
        complete_approval(approval["id"], approvals.EXECUTION_FAILED, str(error)[:160] or type(error).__name__)


def run_rejoin(approval):
    host_id = approval["host_id"]
    enable_attempted = False
    try:
        recovery_key = approval.get("parameters", {}).get("recovery_run_key")
        with db.connect() as connection:
            recovery = connection.execute(
                """SELECT event_id, host_id, status, completed_at FROM remediation_runs
                   WHERE host_id = ? AND status IN
                     ('REPAIRED', 'REPAIR_FAILED', 'EXECUTION_FAILED', 'MASTER_UNTRUSTED', 'HEALTH_CHECK_FAILED')
                   ORDER BY updated_at DESC LIMIT 1""",
                (host_id,),
            ).fetchone()
        if (recovery is None or recovery["event_id"] != str(recovery_key or "")
                or recovery["host_id"] != host_id
                or recovery["status"] != "REPAIRED" or not recovery["completed_at"]):
            complete_approval(approval["id"], approvals.EXECUTION_FAILED, "recovery_state_invalid")
            return
        if not remediator_trusted(host_id):
            complete_approval(approval["id"], approvals.EXECUTION_FAILED, "master_untrusted_or_unavailable")
            return
        if backend_is_up(host_id):
            complete_approval(approval["id"], approvals.EXECUTION_FAILED, "backend_already_enabled")
            return
        enable_attempted = True
        haproxy_command(f"enable server defnett_servers/{host_id}")
        if not wait_for_backend(host_id, True):
            haproxy_command(f"disable server defnett_servers/{host_id}")
            complete_approval(approval["id"], approvals.EXECUTION_FAILED, "backend_not_healthy_after_enable")
            return
        complete_approval(approval["id"], approvals.EXECUTION_DONE, f"backend_up_{host_id}")
    except Exception as error:  # noqa: BLE001
        if enable_attempted:
            try:
                haproxy_command(f"disable server defnett_servers/{host_id}")
            except (OSError, socket.timeout, UnicodeError):
                pass
        complete_approval(approval["id"], approvals.EXECUTION_FAILED, str(error)[:160] or type(error).__name__)


RUNNERS = {
    "CONTAIN_CANARY": run_containment,
    "RESTORE_KEYS": run_containment,
    "SIMULATE_LAB_ATTACK": run_simulate,
    "REJOIN_BACKEND": run_rejoin,
}


def run_approval(approval):
    runner = RUNNERS.get(approval["action"])
    if runner is None:
        complete_approval(approval["id"], approvals.EXECUTION_FAILED, f"unknown_action:{approval['action']}")
        return
    try:
        fresh = authority_approval("/internal/get", {"approval_id": approval["id"]})["approval"]
        if fresh is None or fresh.get("approval_status") != approvals.STATUS_APPROVED or fresh.get("execution_status") != approvals.EXECUTION_CLAIMED:
            raise RuntimeError("approval_authority_state_changed")
        approval = dict(approval)
        approval["parameters"] = fresh.get("parameters", {})
        runner(approval)
    except Exception as error:  # noqa: BLE001
        print(f"executor run failed: {type(error).__name__}: {error}", flush=True)


def claim_and_execute(approval_id, actor="executor"):
    """Klaim satu approval dan mulai eksekusi di thread baru.

    Kembalikan ('claimed', id) bila berhasil; ('rejected', alasan) bila gagal.
    Kegagalan klaim pada event berjalan menuliskan tahap EXECUTION_FAILED di
    runs yang sudah ada supaya timeline tidak menggantung.
    """
    try:
        approval = authority_approval("/internal/claim", {"approval_id": approval_id})["approval"]
    except approvals.ApprovalError as error:
        reason = str(error)
        try:
            known = authority_approval("/internal/get", {"approval_id": approval_id})["approval"]
        except approvals.ApprovalError:
            known = None
        if known is not None and reason == "approval_expired":
            db.record_stage(
                known.get("event_id") or f"approval:{approval_id}",
                "EXECUTION_FAILED",
                "Persetujuan kedaluwarsa sebelum diklaim executor; tidak ada eksekusi.",
                host_id=known["host_id"], path=known["path"], complete=True,
            )
        return ("rejected", reason)
    print(f"executor claimed approval {approval['id']} action={approval['action']} host={approval['host_id']}", flush=True)
    thread = threading.Thread(target=run_approval, args=(approval,), name=f"approve-{approval_id[:8]}", daemon=True)
    thread.start()
    return ("claimed", approval["id"])


def poll_pending():
    try:
        return authority_approval("/internal/pending", method="GET")["approval_ids"]
    except (approvals.ApprovalError, OSError, urllib.error.URLError) as error:
        print(f"executor approval-authority poll failed: {type(error).__name__}", flush=True)
        return []


def poll_loop():
    while True:
        for approval_id in poll_pending():
            claim_and_execute(approval_id)
        _sleep(POLL_SECONDS)


def check_m2m(headers):
    if not EXECUTOR_TOKEN:
        return False
    return hmac.compare_digest(headers.get("Authorization", ""), f"Bearer {EXECUTOR_TOKEN}")


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_body(self, maximum=4096):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > maximum:
            raise ValueError("invalid_body_size")
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        if self.path == "/healthz":
            return self.respond(200, {"status": "ok", "executor": True})
        if self.path == "/v1/haproxy-states":
            if not check_m2m(self.headers):
                return self.respond(401, {"error": "unauthorized"})
            return self.respond(200, {
                "generated_at": utc_now(),
                "backends": backend_states(),
                "workers": worker_states(),
            })
        return self.respond(404, {"error": "not_found"})

    def do_POST(self):
        if self.path == "/v1/execute":
            if not EXECUTOR_TOKEN:
                return self.respond(503, {"error": "executor_http_disabled"})
            if not check_m2m(self.headers):
                return self.respond(401, {"error": "unauthorized"})
            try:
                payload = self.read_body()
                approval_id = str(payload.get("approval_id", ""))
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                return self.respond(400, {"error": "invalid_body"})
            outcome, detail = claim_and_execute(approval_id, actor="m2m")
            if outcome == "claimed":
                return self.respond(202, {"accepted": True, "approval_id": detail})
            return self.respond(409, {"error": detail})
        return self.respond(404, {"error": "not_found"})

    def log_message(self, format_string, *args):
        print(f"executor {self.address_string()} {format_string % args}", flush=True)


if __name__ == "__main__":
    if (not EXECUTOR_TOKEN or not APPROVAL_EXECUTOR_TOKEN
            or EXECUTOR_TOKEN.startswith("GANTI-") or APPROVAL_EXECUTOR_TOKEN.startswith("GANTI-")):
        raise SystemExit("EXECUTOR_API_TOKEN and APPROVAL_EXECUTOR_TOKEN are required")
    db.initialize()
    threading.Thread(target=poll_loop, name="approval-poll", daemon=True).start()
    print(f"executor siap di :{HTTP_PORT}; mengikuti approval yang disetujui", flush=True)
    server = ThreadingHTTPServer((HTTP_HOST, HTTP_PORT), Handler)
    if os.environ.get("APPROVAL_TLS_REQUIRED", "true").lower() != "true":
        raise SystemExit("executor HTTP transport forbidden")
    context = tls_support.server_context(
        os.environ.get("TLS_CERT_FILE", ""), os.environ.get("TLS_KEY_FILE", ""),
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
