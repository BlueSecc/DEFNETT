#!/usr/bin/env python3
"""Uji TLS, token, dan batas jaringan lab VM dari Mac (host 192.168.56.1), tanpa sudo.

Setiap uji mencatat expected, actual, dan status. Sertifikat kedaluwarsa dibuat
khusus di folder sementara; sertifikat deployment tidak disentuh.
Uji dari dalam VM memakai akun SSH biasa (malas), bukan UID layanan.

Pemakaian: python3 lab/vm/vm-checks-host.py --out hasil.json
"""
import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
import tls_support  # noqa: E402

CA = os.path.expanduser("~/.config/defnett-vm-lab/tls/ca.crt")
COLLECTOR = "192.168.56.20"
RESULTS = []


def record(test_id, name, expected, actual, passed):
    RESULTS.append({"id": test_id, "test": name, "expected": expected, "actual": actual,
                    "status": "PASS" if passed else "FAIL"})
    print(f"{test_id:<6} {'PASS' if passed else 'FAIL'}  {name}: {actual}", flush=True)


def https_get(url, context, server_hostname=None, method="GET", data=None, headers=None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, context=context, timeout=5) as response:
            return f"HTTP {response.status}"
    except urllib.error.HTTPError as error:
        error.close()
        return f"HTTP {error.code}"
    except urllib.error.URLError as error:
        return f"{type(error.reason).__name__}: {str(error.reason)[:90]}"
    except OSError as error:
        return f"{type(error).__name__}: {str(error)[:90]}"


def tls_handshake(host, port, context, server_hostname):
    try:
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
                return f"handshake OK {tls.version()}"
    except ssl.SSLCertVerificationError as error:
        return f"ditolak: {error.verify_message}"
    except (ssl.SSLError, OSError) as error:
        return f"{type(error).__name__}: {str(error)[:90]}"


def tcp(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "TERHUBUNG"
    except socket.timeout:
        return "TIMEOUT (difilter)"
    except ConnectionRefusedError:
        return "DITOLAK (refused)"
    except OSError as error:
        return f"{type(error).__name__}"


def ssh(host, command):
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", f"malas@{host}", command],
                            capture_output=True, text=True, timeout=30)
    return (result.stdout + result.stderr).strip()


def expired_certificate_test():
    """Klien DEFNETT (tls_support.client_context) harus menolak sertifikat kedaluwarsa."""
    work = Path(tempfile.mkdtemp(prefix="defnett-expired-"))
    run = lambda *args: subprocess.run(["openssl", *args], check=True, capture_output=True, cwd=work)
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
        "-subj", "/CN=DEFNETT Expired Test CA", "-days", "30",
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=localhost")
    (work / "ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                              "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n")
    run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
        "-not_before", "20250101000000Z", "-not_after", "20250102000000Z", "-extfile", "ext", "-out", "leaf.crt")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.socket = tls_support.server_context(str(work / "leaf.crt"), str(work / "leaf.key")).wrap_socket(
        server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    client = tls_support.client_context(ca_file=str(work / "ca.crt"))
    actual = tls_handshake("127.0.0.1", server.server_address[1], client, "localhost")
    server.shutdown()
    return actual


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="vm-checks-host.json")
    args = parser.parse_args()
    trusted = ssl.create_default_context(cafile=CA)
    system = ssl.create_default_context()
    base = f"https://{COLLECTOR}:8443"

    # TLS
    actual = https_get(base + "/", trusted)
    record("TLS-01", "Dashboard HTTPS dengan CA lab", "HTTP 200", actual, actual == "HTTP 200")
    actual = tls_handshake(COLLECTOR, 8443, system, COLLECTOR)
    record("TLS-02", "CA tidak dikenal (trust store sistem)", "ditolak", actual, actual.startswith("ditolak"))
    actual = tls_handshake(COLLECTOR, 8443, trusted, "salah.defnett.lab")
    record("TLS-03", "Hostname salah", "ditolak hostname mismatch", actual,
           actual.startswith("ditolak") and "mismatch" in actual.lower())
    actual = expired_certificate_test()
    record("TLS-04", "Sertifikat kedaluwarsa (sertifikat uji khusus)", "ditolak certificate has expired",
           actual, "expired" in actual)
    actual = https_get(f"http://{COLLECTOR}:8443/", None)
    record("TLS-05", "HTTP polos ke port HTTPS 8443", "bukan HTTP 200", actual, actual != "HTTP 200")
    actual = tcp(COLLECTOR, 8090)
    record("TLS-06", "Port dashboard lama 8090", "tidak terhubung", actual, actual != "TERHUBUNG")

    # Token dan sesi
    body = json.dumps({"host_id": "server-a"}).encode()
    actual = https_get(base + "/v1/agent/heartbeat", trusted, method="POST", data=body,
                       headers={"Content-Type": "application/json"})
    record("TOK-01", "Heartbeat agent tanpa token", "HTTP 401", actual, actual == "HTTP 401")
    actual = https_get(base + "/v1/events", trusted, method="POST", data=b"{}",
                       headers={"Content-Type": "application/json", "Authorization": "Bearer salah"})
    record("TOK-02", "Event agent dengan token salah", "HTTP 401", actual, actual == "HTTP 401")
    actual = https_get(base + "/v1/dashboard", trusted)
    record("TOK-03", "API dashboard tanpa sesi", "HTTP 401", actual, actual == "HTTP 401")
    actual = https_get(base + "/v1/lab/attack/server-a?vector=ssh", trusted, method="POST", data=b"{}")
    record("TOK-04", "Serang tanpa sesi", "HTTP 401", actual, actual == "HTTP 401")
    actual = https_get(base + "/v1/operator/login", trusted, method="POST",
                       data=json.dumps({"username": "tidak-ada", "password": "x" * 12}).encode(),
                       headers={"Content-Type": "application/json"})
    record("TOK-05", "Login akun tidak dikenal", "HTTP 401", actual, actual == "HTTP 401")

    # Jaringan dari host admin (192.168.56.1)
    for test_id, name, host, port, expect_open in [
        ("NET-01", "Host -> Approval Authority :8093", COLLECTOR, 8093, False),
        ("NET-02", "Host -> Executor :8092", COLLECTOR, 8092, False),
        ("NET-03", "Host -> HAProxy runtime :9999", "192.168.56.10", 9999, False),
        ("NET-04", "Host -> Remediator A :8091", "192.168.56.11", 8091, False),
        ("NET-05", "Host -> Remediator B :8091", "192.168.56.12", 8091, False),
        ("NET-06", "Host -> Blog lewat HAProxy :8080", "192.168.56.10", 8080, True),
    ]:
        actual = tcp(host, port)
        record(test_id, name, "TERHUBUNG" if expect_open else "tidak terhubung", actual,
               (actual == "TERHUBUNG") == expect_open)

    # Dari dalam VM, sebagai user SSH biasa (bukan UID executor)
    probe = ("python3 -c 'import socket,sys\n"
             "try:\n socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=3).close();print(\"TERHUBUNG\")\n"
             "except socket.timeout: print(\"TIMEOUT (difilter)\")\n"
             "except ConnectionRefusedError: print(\"DITOLAK (refused)\")\n"
             "except OSError as e: print(type(e).__name__)' ")
    for test_id, name, vm, host, port, expect_open in [
        ("ISO-01", "Collector (UID non-executor) -> HAProxy runtime :9999", COLLECTOR, "192.168.56.10", 9999, False),
        ("ISO-02", "Collector (UID non-executor) -> Remediator A :8091", COLLECTOR, "192.168.56.11", 8091, False),
        ("ISO-03", "Collector (UID non-executor) -> Remediator B :8091", COLLECTOR, "192.168.56.12", 8091, False),
        ("ISO-04", "Server A -> Remediator B :8091 (lateral)", "192.168.56.11", "192.168.56.12", 8091, False),
        ("ISO-05", "Server A -> HAProxy runtime :9999", "192.168.56.11", "192.168.56.10", 9999, False),
        ("ISO-06", "Server B -> Remediator A :8091 (lateral)", "192.168.56.12", "192.168.56.11", 8091, False),
        ("ISO-07", "Server A -> Approval Authority :8093", "192.168.56.11", COLLECTOR, 8093, False),
        ("ISO-08", "Server A -> Collector HTTPS :8443 (telemetri)", "192.168.56.11", COLLECTOR, 8443, True),
    ]:
        actual = ssh(vm, probe + f"{host} {port}")
        record(test_id, name, "TERHUBUNG" if expect_open else "tidak terhubung", actual,
               (actual == "TERHUBUNG") == expect_open)

    actual = ssh(COLLECTOR, "ls /var/lib/defnett-approval 2>&1 | head -1")
    record("ISO-09", "User biasa membaca direktori database Authority", "Permission denied", actual,
           "Permission denied" in actual)
    actual = ssh(COLLECTOR, "cat /etc/defnett/approval-authority.env /etc/defnett/executor.env 2>&1 | head -2 | tr '\\n' ' '")
    record("ISO-10", "User biasa membaca env token Authority/Executor", "Permission denied", actual,
           actual.count("Permission denied") == 2)
    actual = ssh(COLLECTOR, "curl -s -o /dev/null -w '%{http_code}' --cacert /etc/defnett/tls/ca.crt "
                            "https://127.0.0.1:8093/internal/approvals")
    record("ISO-11", "Authority API internal tanpa token service", "401", actual, actual == "401")
    actual = ssh(COLLECTOR, "curl -s -o /dev/null -w '%{http_code}' --cacert /etc/defnett/tls/ca.crt "
                            "-H 'Authorization: Bearer salah' https://127.0.0.1:8093/internal/approvals")
    record("ISO-12", "Authority API internal dengan token salah", "401", actual, actual == "401")
    actual = ssh(COLLECTOR, "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8093/healthz")
    record("ISO-13", "Authority lewat HTTP polos", "bukan 200", actual, actual != "200")

    summary = {"tested_at": datetime.now(timezone.utc).isoformat(), "results": RESULTS,
               "passed": sum(r["status"] == "PASS" for r in RESULTS), "total": len(RESULTS)}
    Path(args.out).write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n{summary['passed']}/{summary['total']} PASS -> {args.out}")


if __name__ == "__main__":
    main()
