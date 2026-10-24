import hashlib
import ipaddress
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
import urllib.error
import urllib.request


HOST_ID = os.environ.get("HOST_ID", "server")
DATA_ROOT = Path("/data").resolve()
DATA_FILE = DATA_ROOT / "index.txt"
COLLECTOR_URL = os.environ.get(
    "PATROL_EVENT_URL", "http://collector:8090/api/patrol/events"
)
PUBLIC_FILES = {
    item.strip().replace("\\", "/")
    for item in os.environ.get("PATROL_PUBLIC_FILES", "index.txt").split(",")
    if item.strip() and not Path(item.strip()).is_absolute() and ".." not in Path(item.strip()).parts
}
SENSITIVE_NAMES = {".env", ".git", ".ssh", "id_rsa", "credentials", "secrets"}
SENSITIVE_SUFFIXES = {".key", ".pem", ".p12", ".pfx"}

ENABLE_LAB_FIXTURE = os.environ.get("ENABLE_LAB_FIXTURE", "false").lower() == "true"
CANARY_FILE_NAME = "DEFNETT-LAB-CANARY.txt"
CANARY_MARKER = "DEFNETT-LAB-MALWARE-CANARY"
NOTE_FILE_NAME = "DEFNETT-LAB-DEMO-NOTE.txt"
MAX_FIXTURE_BYTES = 64 * 1024
RUN_ID_CHARS = set("0123456789abcdef-")


def normalized_ip(value):
    try:
        return str(ipaddress.ip_address(value.strip()))
    except (ValueError, AttributeError):
        return "unknown"


def is_sensitive(path):
    parts = [part.lower() for part in Path(path).parts]
    return any(
        part in SENSITIVE_NAMES or part.startswith(".env.") or part.endswith(tuple(SENSITIVE_SUFFIXES))
        for part in parts
    )


class Handler(BaseHTTPRequestHandler):
    def client_ip(self):
        forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
        return normalized_ip(forwarded or self.client_address[0])

    def lab_origin(self):
        scenario = (self.headers.get("X-Defnett-Scenario") or "").strip()
        if scenario and len(scenario) <= 64 and all(char in RUN_ID_CHARS for char in scenario):
            return "simulation", scenario
        return "live", None

    def record_access(self, path, action, severity, status, old_hash=None, new_hash=None,
                      origin=None, scenario_run=None):
        if origin is None or scenario_run is None:
            request_origin, request_scenario = self.lab_origin()
            origin = origin or request_origin
            scenario_run = scenario_run if scenario_run is not None else request_scenario
        payload = {
            "host_id": HOST_ID,
            "type": "alert" if severity != "safe" or action == "denied" else "access",
            "actor": self.client_ip(),
            "action": action,
            "path": path[:2048],
            "severity": severity,
            "hash_old": old_hash,
            "hash_new": new_hash,
            "status": status,
            "origin": origin,
            "scenario_run": scenario_run,
        }
        request = urllib.request.Request(
            COLLECTOR_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=0.5):
                pass
        except (urllib.error.URLError, TimeoutError, OSError):
            pass

    def do_GET(self):
        request_path = urlsplit(self.path).path
        query = parse_qs(urlsplit(self.path).query)
        if request_path == "/healthz":
            return self.respond(200, b"ok\n", "text/plain; charset=utf-8")

        if request_path == "/":
            relative_path = "index.txt"
            target = DATA_FILE
        elif request_path.startswith("/files/"):
            relative_path = unquote(request_path[len("/files/"):])
            target = (DATA_ROOT / relative_path).resolve()
        else:
            relative_path = request_path.lstrip("/") or "index.txt"
            target = None

        severity = "safe"
        if target is not None:
            try:
                target.relative_to(DATA_ROOT)
            except ValueError:
                severity = "suspicious"
                self.record_access(relative_path, "denied", severity, "blocked")
                return self.respond(403, b"forbidden\n", "text/plain; charset=utf-8")

        if target is not None and relative_path not in PUBLIC_FILES:
            self.record_access(relative_path, "denied", "suspicious", "blocked")
            return self.respond(403, b"forbidden\n", "text/plain; charset=utf-8")

        if is_sensitive(relative_path):
            self.record_access(relative_path, "denied", "suspicious", "blocked")
            return self.respond(403, b"forbidden\n", "text/plain; charset=utf-8")

        if target is None or not target.is_file():
            self.record_access(relative_path, "read", severity, "not_found")
            return self.respond(404, b"not found\n", "text/plain; charset=utf-8")

        try:
            digest = hashlib.sha256()
            content = bytearray()
            with target.open("rb") as stream:
                for chunk in iter(lambda: stream.read(64 * 1024), b""):
                    digest.update(chunk)
                    if len(content) < 1024 * 1024:
                        content.extend(chunk[:1024 * 1024 - len(content)])
        except (PermissionError, OSError):
            self.record_access(relative_path, "denied", "suspicious", "blocked")
            return self.respond(403, b"forbidden\n", "text/plain; charset=utf-8")

        digest = digest.hexdigest()
        action = "download" if query.get("download") == ["1"] else "read"
        body = f"DEFNETT lab response from {HOST_ID}\n".encode() + bytes(content) if relative_path == "index.txt" else bytes(content)
        self.record_access(relative_path, action, severity, "allowed", digest, digest)
        self.respond(
            200,
            body,
            "text/plain; charset=utf-8",
            Path(relative_path).name if action == "download" else None,
        )

    def do_POST(self):
        if self.path == "/lab/fixture/canary":
            return self.receive_lab_fixture("canary")
        if self.path == "/lab/fixture/note":
            return self.receive_lab_fixture("note")
        self.record_access(urlsplit(self.path).path, "modify", "suspicious", "blocked")
        self.respond(405, b"method not allowed\n", "text/plain; charset=utf-8")

    def receive_lab_fixture(self, kind):
        """Fixture lab terkunci: hanya dua file tetap, tanpa path/perintah bebas.

        Tidak menerima nama file, path, atau shell command dari payload; konten
        dibangun di server dan marker sudah ditentukan konstanta di atas.
        """
        if not ENABLE_LAB_FIXTURE:
            return self.respond_json(403, {"error": "lab_fixture_disabled"})
        if len(self.headers.get("X-Defnett-Scenario", "")) > 64:
            return self.respond_json(400, {"error": "invalid_scenario_header"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length > 2048:
            return self.respond_json(413, {"error": "invalid_body_size"})
        if length:
            try:
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    return self.respond_json(400, {"error": "invalid_body"})
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self.respond_json(400, {"error": "invalid_body"})
        written_at = datetime.now(timezone.utc).isoformat()
        if kind == "canary":
            relative = CANARY_FILE_NAME
            content = f"{CANARY_MARKER} {written_at}\n"
        elif kind == "note":
            relative = NOTE_FILE_NAME
            content = f"DEFNETT lab benign scenario note {written_at}\n"
        else:
            return self.respond_json(400, {"error": "unknown_fixture_kind"})
        target = (DATA_ROOT / relative).resolve()
        if target.parent != DATA_ROOT:
            return self.respond_json(400, {"error": "fixture_target_rejected"})
        if len(content.encode("utf-8")) > MAX_FIXTURE_BYTES:
            return self.respond_json(413, {"error": "fixture_too_large"})
        try:
            DATA_ROOT.mkdir(parents=True, exist_ok=True)
            temporary = target.with_suffix(".fixture-tmp")
            temporary.write_text(content, encoding="utf-8")
            temporary.replace(target)
        except OSError as error:
            return self.respond_json(500, {"error": "fixture_write_failed", "detail": type(error).__name__})
        return self.respond_json(201, {
            "accepted": True,
            "kind": kind,
            "path": relative,
            "written_at": written_at,
        })

    def do_PUT(self):
        self.record_access(urlsplit(self.path).path, "modify", "suspicious", "blocked")
        self.respond(405, b"method not allowed\n", "text/plain; charset=utf-8")

    def do_DELETE(self):
        self.record_access(urlsplit(self.path).path, "delete", "suspicious", "blocked")
        self.respond(405, b"method not allowed\n", "text/plain; charset=utf-8")

    def respond_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def respond(self, status, body, content_type, download_name=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if download_name:
            safe_name = "".join(char for char in download_name if char.isalnum() or char in "._-")[:128] or "file"
            self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        print(f"{HOST_ID} {self.address_string()} {format_string % args}", flush=True)


if __name__ == "__main__":
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    if not DATA_FILE.exists():
        DATA_FILE.write_text(f"Sample content on {HOST_ID}\n", encoding="utf-8")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
