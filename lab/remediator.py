import hashlib
import json
import os
import stat
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


TARGET = Path(os.environ.get("TARGET_ROOT", "/target"))
TARGET_HOST_ID = os.environ.get("TARGET_HOST_ID", "server-a")
QUARANTINE = Path(os.environ.get("QUARANTINE_ROOT", f"/quarantine/{TARGET_HOST_ID}"))
CANARY_NAME = "DEFNETT-LAB-CANARY.txt"
CANARY = b"DEFNETT-LAB-MALWARE-CANARY"
MAX_FILE_SIZE = 1024 * 1024


def quarantine_canary():
    source = TARGET / CANARY_NAME
    try:
        metadata = source.lstat()
    except FileNotFoundError:
        raise ValueError("canary_file_missing") from None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_SIZE:
        raise ValueError("canary_file_type_or_size_rejected")

    descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(MAX_FILE_SIZE + 1)
    finally:
        os.close(descriptor)
    if len(content) > MAX_FILE_SIZE or CANARY not in content:
        raise ValueError("canary_marker_not_verified")

    digest = hashlib.sha256(content).hexdigest()
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    name = f"{TARGET_HOST_ID}-{uuid.uuid4().hex}-{CANARY_NAME}"
    temporary = QUARANTINE / f".{name}.tmp"
    destination = QUARANTINE / name
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)

    if hashlib.sha256(temporary.read_bytes()).hexdigest() != digest:
        temporary.unlink(missing_ok=True)
        raise OSError("quarantine_hash_mismatch")
    os.replace(temporary, destination)
    source.unlink()
    if source.exists():
        raise OSError("source_file_still_present")

    return {
        "status": "QUARANTINED_CANARY",
        "action": "MOVE_VERIFIED_CANARY_TO_QUARANTINE",
        "quarantine_path": str(destination.relative_to(QUARANTINE.parent)),
        "sha256": digest,
        "bytes": len(content),
    }


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            return self.respond(200, {"status": "ok"})
        return self.respond(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/v1/repair":
            return self.respond(404, {"error": "not_found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2048:
                return self.respond(413, {"error": "invalid_body_size"})
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or payload.get("host_id") != TARGET_HOST_ID:
                return self.respond(403, {"error": "host_not_allowed"})
            result = quarantine_canary()
            result["event_id"] = str(payload.get("event_id", ""))[:64]
            result["host_id"] = TARGET_HOST_ID
            return self.respond(200, result)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            return self.respond(409, {"error": "repair_rejected", "detail": str(error)})
        except OSError as error:
            return self.respond(500, {"error": "quarantine_failed", "detail": type(error).__name__})

    def log_message(self, format_string, *args):
        print(f"remediator-{TARGET_HOST_ID} {self.address_string()} {format_string % args}", flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8091), Handler).serve_forever()
