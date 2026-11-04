"""Small stdlib client for the isolated approval authority API."""
import json
import os
import ssl
import urllib.error
import urllib.request

BASE_URL = os.environ.get("APPROVAL_AUTHORITY_URL", "http://approval-authority:8093").rstrip("/")
COLLECTOR_TOKEN = os.environ.get("APPROVAL_COLLECTOR_TOKEN", "")
EXECUTOR_TOKEN = os.environ.get("APPROVAL_EXECUTOR_TOKEN", "")
CA_FILE = os.environ.get("APPROVAL_CA_FILE", "")
CLIENT_CERT_FILE = os.environ.get("APPROVAL_CLIENT_CERT_FILE", "")
CLIENT_KEY_FILE = os.environ.get("APPROVAL_CLIENT_KEY_FILE", "")
# Daftar 50 persetujuan beserta parameternya bisa jauh di atas 16 KB.
MAX_RESPONSE_BYTES = 1024 * 1024


def request(path, *, method="GET", payload=None, token=None, cookie=None, csrf=None, timeout=3):
    body = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["X-DEFNETT-CSRF"] = csrf
    req = urllib.request.Request(BASE_URL + path, data=body, headers=headers, method=method)
    try:
        context = None
        if BASE_URL.startswith("https://"):
            from tls_support import client_context
            context = client_context(ca_file=CA_FILE, cert_file=CLIENT_CERT_FILE, key_file=CLIENT_KEY_FILE)
        elif os.environ.get("APPROVAL_TLS_REQUIRED", "false").lower() == "true":
            raise ssl.SSLError("plain HTTP approval-authority connection forbidden")
        response = urllib.request.urlopen(req, timeout=timeout, context=context)
    except urllib.error.HTTPError as error:
        response = error
    try:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        try:
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ValueError("authority response too large")
            result = json.loads(raw) if raw else {}
        except (ValueError, UnicodeDecodeError):
            result = {"error": "invalid_authority_response"}
        return response.status, result, response.headers.get("Set-Cookie")
    finally:
        response.close()


def require(path, *, method="GET", payload=None, token=None, cookie=None, csrf=None, timeout=3):
    status, result, set_cookie = request(
        path, method=method, payload=payload, token=token, cookie=cookie,
        csrf=csrf, timeout=timeout,
    )
    if status < 200 or status >= 300:
        raise RuntimeError(f"approval_authority_http_{status}:{result.get('error', 'request_failed')}")
    return result, set_cookie
