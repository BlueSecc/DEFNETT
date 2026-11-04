"""Process/API boundary tests against an actual TLS authority process."""
import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
import provision_operators  # noqa: E402


class AuthorityProcessBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.mkdtemp(prefix="defnett-authority-process-")
        cls.tls = Path(cls.temp) / "tls"
        subprocess.run(["sh", str(LAB / "provision-lab-tls.sh"), str(cls.tls)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.auth_file = Path(cls.temp) / "ops.json"
        provision_operators.add_operator(str(cls.auth_file), "operator", "operator", "a-long-operator-password")
        provision_operators.add_operator(str(cls.auth_file), "viewer", "viewer", "a-long-viewer-password")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            cls.port = probe.getsockname()[1]
        env = os.environ.copy()
        env.update({
            "DB_PATH": str(Path(cls.temp) / "authority.sqlite3"),
            "OPERATOR_AUTH_FILE": str(cls.auth_file),
            "APPROVAL_COLLECTOR_TOKEN": "collector-process-token",
            "APPROVAL_EXECUTOR_TOKEN": "executor-process-token",
            "APPROVAL_PORT": str(cls.port),
            "TLS_CERT_FILE": str(cls.tls / "approval-authority.crt"),
            "TLS_KEY_FILE": str(cls.tls / "approval-authority.key"),
            "TLS_CA_FILE": str(cls.tls / "ca.crt"),
        })
        cls.process = subprocess.Popen(
            [sys.executable, str(LAB / "approval_authority.py")], cwd=LAB, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cls.base = f"https://localhost:{cls.port}"
        cls.context = ssl.create_default_context(cafile=str(cls.tls / "ca.crt"))
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if cls.process.poll() is not None:
                raise RuntimeError("approval authority child exited during startup")
            try:
                cls.call("/healthz")
                break
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        else:
            raise RuntimeError("approval authority child did not become ready")

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "process", None) and cls.process.poll() is None:
            cls.process.terminate()
            try:
                cls.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.process.kill()
                cls.process.wait(timeout=3)
        shutil.rmtree(getattr(cls, "temp", "/tmp/nonexistent-defnett-authority"), ignore_errors=True)

    @classmethod
    def call(cls, path, method="GET", payload=None, token=None, cookie=None, csrf=None, context=None):
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if cookie:
            headers["Cookie"] = cookie
        if csrf:
            headers["X-DEFNETT-CSRF"] = csrf
        body = None if payload is None else json.dumps(payload).encode()
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(cls.base + path, data=body, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=3, context=context or cls.context)
        except urllib.error.HTTPError as error:
            response = error
        try:
            return response.status, json.loads(response.read() or b"{}"), response.headers.get("Set-Cookie")
        finally:
            response.close()

    @classmethod
    def login(cls, user, password):
        status, body, cookie = cls.call("/v1/operator/login", "POST", {"username": user, "password": password})
        return status, body, cookie.split(";", 1)[0]

    def create_approval(self):
        status, body, _ = self.call(
            "/internal/approvals", "POST",
            {"action": "CONTAIN_CANARY", "host_id": "server-a", "path": "DEFNETT-LAB-CANARY.txt",
             "parameters": {"artifact": "canary"}, "reason": "test"},
            token="collector-process-token",
        )
        self.assertEqual(status, 201)
        return body["approval"]["id"]

    def test_tls_valid_unknown_ca_and_plain_http(self):
        status, body, _ = self.call("/healthz")
        self.assertEqual((status, body["approval_authority"]), (200, True))
        status, _, cookie = self.call("/v1/operator/login", "POST", {
            "username": "viewer", "password": "a-long-viewer-password",
        })
        self.assertEqual(status, 200)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Secure", cookie)
        bad = ssl.create_default_context()
        with self.assertRaises(urllib.error.URLError):
            self.call("/healthz", context=bad)
        with self.assertRaises((OSError, urllib.error.URLError)):
            urllib.request.urlopen(f"http://localhost:{self.port}/healthz", timeout=2)
        with self.assertRaises(urllib.error.URLError):
            urllib.request.urlopen(f"https://127.0.0.2:{self.port}/healthz", timeout=2,
                                   context=self.context)

    def test_vm_certificate_subject_alternative_names(self):
        for certificate, expected in (
            ("collector-vm.crt", "IP Address:192.168.56.20"),
            ("executor-vm.crt", "IP Address:127.0.0.1"),
            ("remediator-a-vm.crt", "IP Address:192.168.56.11"),
            ("remediator-b-vm.crt", "IP Address:192.168.56.12"),
        ):
            result = subprocess.run(
                ["openssl", "x509", "-in", str(self.tls / certificate), "-noout", "-ext", "subjectAltName"],
                check=True, capture_output=True, text=True,
            )
            self.assertIn(expected, result.stdout)

    def test_collector_client_reads_large_list_and_restored_hashes(self):
        import authority_client
        import collector
        saved = (authority_client.BASE_URL, authority_client.COLLECTOR_TOKEN, authority_client.CA_FILE,
                 collector.APPROVAL_TEST_ADAPTER)
        authority_client.BASE_URL = self.base
        authority_client.COLLECTOR_TOKEN = "collector-process-token"
        authority_client.CA_FILE = str(self.tls / "ca.crt")
        collector.APPROVAL_TEST_ADAPTER = None
        try:
            for index in range(40):
                status, _, _ = self.call("/internal/approvals", "POST", {
                    "action": "RESTORE_KEYS", "host_id": "server-b", "path": f"etc/kunci{index}.dat",
                    "parameters": {"note": "x" * 600}, "reason": "ukuran daftar di atas 16 KB",
                }, token="collector-process-token")
                self.assertEqual(status, 201)
            self.assertGreaterEqual(len(collector.list_approvals(50)), 40)
            self.assertIsInstance(collector.restored_hashes(), dict)
        finally:
            (authority_client.BASE_URL, authority_client.COLLECTOR_TOKEN, authority_client.CA_FILE,
             collector.APPROVAL_TEST_ADAPTER) = saved

    def test_dashboard_logout_without_body_ends_authority_session(self):
        import threading
        from http.server import ThreadingHTTPServer
        import authority_client
        import collector
        saved = (authority_client.BASE_URL, authority_client.CA_FILE, collector.APPROVAL_TEST_ADAPTER)
        authority_client.BASE_URL = self.base
        authority_client.CA_FILE = str(self.tls / "ca.crt")
        collector.APPROVAL_TEST_ADAPTER = None
        server = ThreadingHTTPServer(("127.0.0.1", 0), collector.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{server.server_address[1]}"

        def post(path, body, headers):
            request = urllib.request.Request(base + path, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    return response.status, json.loads(response.read() or b"{}"), response.headers.get("Set-Cookie")
            except urllib.error.HTTPError as error:
                with error:
                    return error.code, json.loads(error.read() or b"{}"), None

        try:
            status, login, set_cookie = post("/v1/operator/login", json.dumps(
                {"username": "operator", "password": "a-long-operator-password"}).encode(),
                {"Content-Type": "application/json"})
            self.assertEqual(status, 200)
            cookie = set_cookie.split(";", 1)[0]
            # Sama seperti dashboard: fetch POST dengan body "" (Content-Length: 0).
            status, body, _ = post("/v1/operator/logout", b"", {
                "Content-Type": "application/json", "Cookie": cookie, "X-DEFNETT-CSRF": login["csrf"]})
            self.assertEqual((status, body.get("logged_out")), (200, True))
            status, whoami, _ = self.call("/v1/operator/whoami", cookie=cookie)
            self.assertEqual((status, whoami["authenticated"]), (200, False))
        finally:
            server.shutdown()
            server.server_close()
            (authority_client.BASE_URL, authority_client.CA_FILE, collector.APPROVAL_TEST_ADAPTER) = saved

    def test_collector_token_cannot_approve_or_claim_or_retarget(self):
        approval_id = self.create_approval()
        status, body, _ = self.call(
            f"/v1/approvals/{approval_id}/approve", "POST", token="collector-process-token",
        )
        self.assertEqual(status, 401)
        status, body, _ = self.call("/internal/claim", "POST", {"approval_id": approval_id},
                                    token="collector-process-token")
        self.assertEqual(status, 401)
        status, body, _ = self.call("/internal/approvals", "POST", {
            "action": "REJOIN_BACKEND", "host_id": "server-b", "path": "changed",
            "parameters": {}, "reason": "attempted retarget", "approval_id": approval_id,
        }, token="collector-process-token")
        self.assertEqual(status, 201)
        self.assertNotEqual(body["approval"]["id"], approval_id)
        original_status, original, _ = self.call(f"/internal/approval/{approval_id}", token="collector-process-token")
        self.assertEqual(original["approval"]["host_id"], "server-a")
        self.assertEqual(original["approval"]["path"], "DEFNETT-LAB-CANARY.txt")
        self.assertEqual(original["approval"]["approval_status"], "PENDING")

    def test_viewer_unauthenticated_csrf_expiry_and_one_use(self):
        approval_id = self.create_approval()
        status, body, _ = self.call(f"/v1/approvals/{approval_id}/approve", "POST")
        self.assertEqual(status, 401)
        status, viewer, cookie = self.login("viewer", "a-long-viewer-password")
        self.assertEqual(status, 200)
        status, _, _ = self.call(f"/v1/approvals/{approval_id}/approve", "POST", cookie=cookie,
                                 csrf=viewer["csrf"])
        self.assertEqual(status, 401)
        approval_id = self.create_approval()
        status, operator, cookie = self.login("operator", "a-long-operator-password")
        self.assertEqual(status, 200)
        status, _, _ = self.call(f"/v1/approvals/{approval_id}/approve", "POST", cookie=cookie)
        self.assertEqual(status, 403)
        status, approved, _ = self.call(f"/v1/approvals/{approval_id}/approve", "POST", cookie=cookie,
                                        csrf=operator["csrf"])
        self.assertEqual(status, 200)
        self.assertEqual(approved["approval"]["approval_status"], "APPROVED")
        expired_id = self.create_approval()
        status, expired_operator, expired_cookie = self.login("operator", "a-long-operator-password")
        status, _, _ = self.call(f"/v1/approvals/{expired_id}/approve", "POST", cookie=expired_cookie,
                                 csrf=expired_operator["csrf"])
        connection = sqlite3.connect(Path(self.temp) / "authority.sqlite3")
        try:
            with connection:
                connection.execute("UPDATE operator_approvals SET expires_at = ? WHERE id = ?",
                                   ("2000-01-01T00:00:00+00:00", expired_id))
        finally:
            connection.close()
        status, expired, _ = self.call("/internal/claim", "POST", {"approval_id": expired_id},
                                       token="executor-process-token")
        self.assertEqual(status, 409)
        self.assertEqual(expired["error"], "approval_expired")
        status, claimed, _ = self.call("/internal/claim", "POST", {"approval_id": approval_id},
                                       token="executor-process-token")
        self.assertEqual(status, 200)
        status, replay, _ = self.call("/internal/claim", "POST", {"approval_id": approval_id},
                                      token="executor-process-token")
        self.assertEqual(status, 409)
        status, result, _ = self.call("/internal/complete", "POST", {
            "approval_id": approval_id, "outcome": "DONE", "detail": "completed",
        }, token="executor-process-token")
        self.assertEqual(status, 200)
        status, result, _ = self.call("/internal/complete", "POST", {
            "approval_id": approval_id, "outcome": "DONE", "detail": "completed",
        }, token="executor-process-token")
        self.assertEqual(status, 200)
        status, replay, _ = self.call("/internal/claim", "POST", {"approval_id": approval_id},
                                      token="executor-process-token")
        self.assertEqual(status, 409)

    def test_authority_failure_or_wrong_service_token_fails_closed(self):
        approval_id = self.create_approval()
        status, body, _ = self.call("/internal/pending", token="collector-process-token")
        self.assertEqual(status, 401)
        status, body, _ = self.call("/internal/claim", "POST", {"approval_id": approval_id},
                                    token="wrong-token")
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
