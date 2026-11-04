#!/usr/bin/env python3
"""Single-writer approval authority for operator and executor lifecycle."""
import hmac
import json
import os
import stat
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import approvals
import db
import operator_auth
import tls_support

HOST = os.environ.get("APPROVAL_BIND_HOST", "0.0.0.0")
PORT = int(os.environ.get("APPROVAL_PORT", "8093"))
COLLECTOR_TOKEN = os.environ.get("APPROVAL_COLLECTOR_TOKEN", "")
EXECUTOR_TOKEN = os.environ.get("APPROVAL_EXECUTOR_TOKEN", "")
TLS_CERT_FILE = os.environ.get("TLS_CERT_FILE", "")
TLS_KEY_FILE = os.environ.get("TLS_KEY_FILE", "")
TLS_CA_FILE = os.environ.get("TLS_CA_FILE", "")
MAX_BODY = 8192


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, payload, headers=None):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY:
            raise ValueError("invalid_body_size")
        data = json.loads(self.rfile.read(length))
        if not isinstance(data, dict):
            raise ValueError("invalid_body")
        return data

    def internal(self, token):
        expected = f"Bearer {token}" if token else ""
        return bool(expected) and hmac.compare_digest(self.headers.get("Authorization", ""), expected)

    def session(self):
        raw = self.headers.get("Cookie", "")
        sid = None
        for item in raw.split(";"):
            if "=" in item:
                name, value = item.split("=", 1)
                if name.strip() == operator_auth.SESSION_COOKIE:
                    sid = value.strip()
                    break
        return operator_auth.get_session(sid)

    def csrf(self, session):
        provided = self.headers.get(operator_auth.CSRF_HEADER, "")
        return bool(session) and hmac.compare_digest(provided, session.get("csrf", ""))

    def do_GET(self):
        if self.path == "/healthz":
            return self.respond(200, {"status": "ok", "approval_authority": True})
        if self.path == "/v1/operator/whoami":
            session = self.session()
            if not session:
                return self.respond(200, {"authenticated": False})
            return self.respond(200, {"authenticated": True, "username": session["username"],
                                      "role": session["role"], "csrf": session["csrf"]})
        if self.path == "/v1/approvals":
            session = self.session()
            if not operator_auth.authorize(session, "viewer"):
                return self.respond(401, {"error": "unauthorized"})
            approvals.expired_pending()
            return self.respond(200, {"approvals": approvals.list_approvals(50)})
        if self.path == "/internal/approvals":
            if not self.internal(COLLECTOR_TOKEN):
                return self.respond(401, {"error": "unauthorized"})
            approvals.expired_pending()
            return self.respond(200, {"approvals": approvals.list_approvals(50)})
        if self.path.startswith("/internal/approval/"):
            if not self.internal(COLLECTOR_TOKEN):
                return self.respond(401, {"error": "unauthorized"})
            approval_id = self.path.rsplit("/", 1)[-1]
            result = approvals.get(approval_id)
            return self.respond(200 if result else 404, {"approval": result})
        if self.path == "/internal/pending":
            if not self.internal(EXECUTOR_TOKEN):
                return self.respond(401, {"error": "unauthorized"})
            pending = [item["id"] for item in approvals.list_approvals(200)
                       if item["approval_status"] == approvals.STATUS_APPROVED
                       and item["execution_status"] == approvals.EXECUTION_NONE]
            return self.respond(200, {"approval_ids": pending[:10]})
        return self.respond(404, {"error": "not_found"})

    def do_POST(self):
        try:
            if self.path == "/v1/operator/login":
                data = self.body()
                source = self.client_address[0]
                wait = operator_auth.login_tracker.locked(source)
                if wait:
                    return self.respond(429, {"error": "too_many_failures", "retry_seconds": max(1, wait)})
                profile = operator_auth.authenticate(data.get("username"), data.get("password"))
                if profile is None:
                    operator_auth.login_tracker.record_failure(source)
                    return self.respond(401, {"error": "kredensial_tidak_sah"})
                operator_auth.login_tracker.reset(source)
                try:
                    operator_auth.maybe_rehash(data.get("username"), data.get("password"))
                except Exception as error:  # Login remains available if optional rehash cannot be persisted.
                    print(f"operator password rehash failed: {type(error).__name__}", flush=True)
                session = operator_auth.create_session(profile["username"], profile["role"])
                cookie = (f"{operator_auth.SESSION_COOKIE}={session['session_id']}; Path=/; HttpOnly; "
                          f"SameSite=Strict{'; Secure' if os.environ.get('COOKIE_SECURE', 'true') == 'true' else ''}")
                return self.respond(200, {"approved": True, "username": session["username"],
                                          "role": session["role"], "csrf": session["csrf"]},
                                    {"Set-Cookie": cookie})

            if self.path == "/v1/operator/logout":
                session = self.session()
                if session and not self.csrf(session):
                    return self.respond(403, {"error": "csrf_required"})
                if session:
                    operator_auth.destroy_session(session["session_id"])
                cookie = f"{operator_auth.SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{'; Secure' if os.environ.get('COOKIE_SECURE', 'true') == 'true' else ''}"
                return self.respond(200, {"logged_out": True}, {"Set-Cookie": cookie})

            if self.path.startswith("/v1/approvals/"):
                path = urlsplit(self.path).path.split("/")
                if len(path) != 5 or path[-1] not in {"approve", "reject"}:
                    return self.respond(404, {"error": "not_found"})
                session = self.session()
                if not operator_auth.authorize(session, "operator"):
                    return self.respond(401, {"error": "unauthorized"})
                if not self.csrf(session):
                    return self.respond(403, {"error": "csrf_required"})
                data = self.body() if path[-1] == "reject" else {}
                actor = f"operator:{session['username']}"
                result = (approvals.approve(path[-2], actor) if path[-1] == "approve"
                          else approvals.reject(path[-2], actor, str(data.get("reason") or "operator_rejected")))
                return self.respond(200, {"approval": result})

            if self.path == "/internal/approvals":
                if not self.internal(COLLECTOR_TOKEN):
                    return self.respond(401, {"error": "unauthorized"})
                data = self.body()
                result = approvals.create(
                    data.get("action"), data.get("host_id"), data.get("path"),
                    data.get("parameters"), event_id=data.get("event_id"),
                    created_by="collector:policy_gate", reason=str(data.get("reason") or ""),
                )
                return self.respond(201, {"approval": result})

            if self.path == "/internal/claim":
                if not self.internal(EXECUTOR_TOKEN):
                    return self.respond(401, {"error": "unauthorized"})
                data = self.body()
                result = approvals.claim(str(data.get("approval_id", "")), "executor")
                return self.respond(200, {"approval": result})

            if self.path == "/internal/complete":
                if not self.internal(EXECUTOR_TOKEN):
                    return self.respond(401, {"error": "unauthorized"})
                data = self.body()
                result = approvals.complete(str(data.get("approval_id", "")), data.get("outcome"),
                                            str(data.get("detail", "")), data.get("parameters_update"))
                return self.respond(200, {"approval": result})

            if self.path == "/internal/get":
                if not self.internal(EXECUTOR_TOKEN):
                    return self.respond(401, {"error": "unauthorized"})
                data = self.body()
                result = approvals.get(str(data.get("approval_id", "")))
                return self.respond(200 if result else 404, {"approval": result})

            if self.path == "/internal/restored-hashes":
                if not self.internal(COLLECTOR_TOKEN):
                    return self.respond(401, {"error": "unauthorized"})
                return self.respond(200, {"restored_hashes": [
                    {"host_id": host, "path": path, "sha256": digest}
                    for (host, path), digest in approvals.restored_hashes().items()
                ]})
        except approvals.ApprovalError as error:
            return self.respond(409, {"error": str(error)})
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
            return self.respond(400, {"error": str(error) or "invalid_request"})
        except Exception as error:  # Do not leak database or credential details to clients.
            print(f"approval authority request failed: {type(error).__name__}", flush=True)
            return self.respond(503, {"error": "authority_unavailable"})
        return self.respond(404, {"error": "not_found"})

    def log_message(self, fmt, *args):
        print(f"approval-authority {self.client_address[0]} {fmt % args}", flush=True)


if __name__ == "__main__":
    if (not COLLECTOR_TOKEN or not EXECUTOR_TOKEN
            or COLLECTOR_TOKEN.startswith("GANTI-") or EXECUTOR_TOKEN.startswith("GANTI-")):
        raise SystemExit("approval authority requires separate collector and executor service tokens")
    if os.environ.get("APPROVAL_TLS_REQUIRED", "true").lower() != "true":
        raise SystemExit("approval authority requires TLS")
    db.initialize()
    os.chmod(db.DB_PATH, stat.S_IRUSR | stat.S_IWUSR)
    print(f"approval authority listening on {HOST}:{PORT}", flush=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    context = tls_support.server_context(TLS_CERT_FILE, TLS_KEY_FILE, ca_file=TLS_CA_FILE)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
