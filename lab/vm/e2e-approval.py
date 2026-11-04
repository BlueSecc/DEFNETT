#!/usr/bin/env python3
"""Uji E2E alur persetujuan di lab VM, dijalankan dari Mac oleh operator.

Kata sandi diminta lewat prompt dan tidak disimpan. Tiap insiden:
Serang! -> file kunci berubah -> persetujuan RESTORE_KEYS muncul -> disetujui ->
server keluar dari HAProxy -> kunci dipulihkan -> server kembali UP.
Selama uji, blog di gateway diminta terus-menerus untuk mengukur kelangsungan layanan.

Pemakaian: python3 lab/vm/e2e-approval.py [--runs 6] [--user admin] [--out hasil.json]
"""
import argparse
import getpass
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

COLLECTOR = "https://192.168.56.20:8443"
BLOG = "http://192.168.56.10:8080/"
CA = os.path.expanduser("~/.config/defnett-vm-lab/tls/ca.crt")
PLAN = [("server-a", "ssh"), ("server-b", "web"), ("server-a", "web"),
        ("server-b", "ssh"), ("server-a", "ssh"), ("server-b", "web")]


class Session:
    def __init__(self):
        self.context = ssl.create_default_context(cafile=CA)
        self.cookie = ""
        self.csrf = ""

    def call(self, path, method="GET", payload=None):
        headers = {"Content-Type": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.csrf and method != "GET":
            headers["X-DEFNETT-CSRF"] = self.csrf
        data = None if payload is None else json.dumps(payload).encode()
        if method == "POST" and data is None:
            data = b"{}"
        request = urllib.request.Request(COLLECTOR + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=8) as response:
                return response.status, json.loads(response.read() or b"{}"), response.headers
        except urllib.error.HTTPError as error:
            body = error.read()
            error.close()
            try:
                return error.code, json.loads(body or b"{}"), error.headers
            except json.JSONDecodeError:
                return error.code, {"raw": body[:200].decode(errors="replace")}, error.headers
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as error:
            # Koneksi terputus atau balasan rusak dicatat sebagai status 0, uji tetap berjalan.
            return 0, {"error": type(error).__name__}, {}

    def login(self, username, password):
        status, body, headers = self.call("/v1/operator/login", "POST", {"username": username, "password": password})
        if status != 200:
            raise SystemExit(f"login gagal: HTTP {status} {body}")
        raw = headers.get("Set-Cookie", "")
        self.cookie = raw.split(";", 1)[0]
        self.csrf = body["csrf"]
        return raw


class BlogProbe(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.total = 0
        self.ok = 0
        self.by_server = {"SERVER A": 0, "SERVER B": 0}
        self.failures = []

    def run(self):
        while not self.stop.is_set():
            started = time.time()
            try:
                with urllib.request.urlopen(BLOG, timeout=3) as response:
                    body = response.read().decode(errors="replace")
                    with self.lock:
                        self.total += 1
                        self.ok += response.status == 200
                        for name in self.by_server:
                            if name in body:
                                self.by_server[name] += 1
                                break
            except (urllib.error.URLError, OSError) as error:
                with self.lock:
                    self.total += 1
                    self.failures.append(f"{datetime.now(timezone.utc).isoformat()} {type(error).__name__}")
            time.sleep(max(0.0, 0.33 - (time.time() - started)))


def utc(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (AttributeError, ValueError):
        return 0.0


def wait_for(predicate, timeout, interval=0.5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(interval)
    return None


def run_incident(session, host, vector):
    record = {"host": host, "vector": vector, "result": "FAIL"}

    def dashboard():
        status, body, _ = session.call("/v1/dashboard")
        return body if status == 200 else {}

    if not wait_for(lambda: all(v == "UP" for v in dashboard().get("backends", {}).values()), 90):
        record["error"] = "backend belum UP semua sebelum serangan"
        return record
    started = time.time()
    status, body, _ = session.call(f"/v1/lab/attack/{host}?vector={vector}", "POST")
    record["attack_http"] = status
    if status != 202:
        record["error"] = f"serangan ditolak: {body}"
        return record

    def pending_restore():
        for item in dashboard().get("approvals", []):
            if (item.get("host_id") == host and item.get("action") == "RESTORE_KEYS"
                    and item.get("approval_status") == "PENDING" and utc(item.get("created_at")) >= started - 5):
                return item
        return None

    approval = wait_for(pending_restore, 60)
    if not approval:
        record["error"] = "persetujuan RESTORE_KEYS tidak muncul dalam 60 detik"
        return record
    record["pending_after_attack_s"] = round(time.time() - started, 2)
    state = dashboard()
    record["backend_before_approval"] = state.get("backends", {}).get(host)
    approved_at = time.time()
    status, body, _ = session.call(f"/v1/approvals/{approval['id']}/approve", "POST")
    record["approve_http"] = status
    if status not in (200, 202):
        record["error"] = f"persetujuan ditolak: {body}"
        return record

    isolated = wait_for(lambda: dashboard().get("backends", {}).get(host) not in (None, "UP"), 30, 0.2)
    record["isolated_after_approve_s"] = round(time.time() - approved_at, 2) if isolated else None

    def repaired():
        state = dashboard()
        for run in state.get("remediations", []):
            if run.get("host_id") == host and utc(run.get("started_at") or run.get("updated_at")) >= started - 5:
                if run.get("status") in ("EXECUTION_FAILED", "REPAIR_FAILED", "MASTER_UNTRUSTED", "HEALTH_CHECK_FAILED"):
                    return {"failed": run}
                if run.get("status") == "REPAIRED" and state.get("backends", {}).get(host) == "UP":
                    return {"run": run}
        return None

    outcome = wait_for(repaired, 120)
    if not outcome:
        record["error"] = "server tidak kembali UP dalam 120 detik"
        return record
    if "failed" in outcome:
        record["error"] = f"playbook gagal: {outcome['failed'].get('status')} {outcome['failed'].get('detail')}"
        return record
    record["up_after_approve_s"] = round(time.time() - approved_at, 2)
    record["metrics"] = outcome["run"].get("metrics")
    record["entry"] = outcome["run"].get("entry")
    record["result"] = "PASS"
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--runs", type=int, default=6)
    parser.add_argument("--user", default="admin")
    parser.add_argument("--out", default="e2e-hasil.json")
    args = parser.parse_args()
    if not os.path.isfile(CA):
        raise SystemExit(f"CA lab tidak ditemukan: {CA}")

    session = Session()
    raw_cookie = session.login(args.user, getpass.getpass(f"Kata sandi operator {args.user}: "))
    checks = {
        "cookie_secure_httponly_samesite": all(flag in raw_cookie for flag in ("Secure", "HttpOnly", "SameSite=Strict")),
    }
    anonymous = Session()
    checks["dashboard_tanpa_login"] = anonymous.call("/v1/dashboard")[0]
    no_csrf = Session()
    no_csrf.cookie = session.cookie
    checks["serang_tanpa_csrf"] = no_csrf.call("/v1/lab/attack/server-a?vector=ssh", "POST")[0]
    try:
        urllib.request.urlopen(COLLECTOR + "/", timeout=5)
        checks["https_tanpa_ca"] = "DITERIMA"
    except (urllib.error.URLError, ssl.SSLError):
        checks["https_tanpa_ca"] = "DITOLAK"
    print("pemeriksaan:", json.dumps(checks))

    probe = BlogProbe()
    probe.start()
    results = []
    for index in range(args.runs):
        host, vector = PLAN[index % len(PLAN)]
        print(f"[{index + 1}/{args.runs}] {host} lewat {vector} ...", flush=True)
        record = run_incident(session, host, vector)
        results.append(record)
        metrics = record.get("metrics") or {}
        print(f"    {record['result']}  deteksi={metrics.get('detect')}s  isolasi={metrics.get('isolate')}s  "
              f"pulih-tanpa-jeda={metrics.get('recover_without_hold')}s  "
              f"setuju->UP={record.get('up_after_approve_s')}s  {record.get('error', '')}", flush=True)
        time.sleep(5)
    time.sleep(2)
    probe.stop.set()
    probe.join(5)
    evidence = session.call("/v1/evidence/verify")[1]

    summary = {
        "tested_at": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "incidents": results,
        "passed": sum(r["result"] == "PASS" for r in results),
        "blog": {"total": probe.total, "http_200": probe.ok, "by_server": probe.by_server,
                 "failures": probe.failures[:20]},
        "evidence": evidence,
    }
    with open(args.out, "w", encoding="utf-8") as stream:
        json.dump(summary, stream, indent=2, ensure_ascii=False)
    print(f"\nINSIDEN LULUS: {summary['passed']}/{len(results)}")
    print(f"BLOG: {probe.ok}/{probe.total} HTTP 200, {probe.by_server}")
    print(f"BUKTI: {evidence.get('status')}")
    print(f"hasil lengkap: {os.path.abspath(args.out)}")
    return 0 if summary["passed"] == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
