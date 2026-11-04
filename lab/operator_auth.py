"""Otentikasi operator: kredensial PBKDF2 dari berkas terkunci, sesi dalam memori.

Fail-closed: tanpa berkas operator (atau berkas rusak) semua login ditolak.
Sesi tidak disimpan di disk; cookie HttpOnly, dan setiap POST operator wajib
membawa header CSRF yang dikeluarkan saat login.
"""
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

AUTH_FILE = os.environ.get("OPERATOR_AUTH_FILE", "/ops/operator_auth.json")
SESSION_TTL_SECONDS = max(60, int(os.environ.get("OPERATOR_SESSION_TTL_SECONDS", "43200")))
SESSION_COOKIE = "defnett_session"
CSRF_HEADER = "X-DEFNETT-CSRF"
DEFAULT_ITERATIONS = 600_000
MIN_ITERATIONS = 50_000
MAX_ITERATIONS = 5_000_000
ROLES = {"viewer": 1, "operator": 2}
MAX_LOGIN_FAILURES = 5
LOGIN_LOCK_SECONDS = 60

_lock = threading.Lock()
_sessions = {}
_file_cache = {"mtime": None, "users": None, "failures": ""}


class AuthUnavailable(RuntimeError):
    """Berkas operator tidak terbaca atau tidak valid; semua login ditolak."""


def hash_password(password, salt_hex, iterations=DEFAULT_ITERATIONS):
    raw = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
    )
    return raw.hex()


def _sanitize_users(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("operators"), dict) or not raw["operators"]:
        raise AuthUnavailable("operator_file_invalid")
    users = {}
    for username, record in raw["operators"].items():
        if not isinstance(username, str) or not username or len(username) > 64:
            continue
        if not isinstance(record, dict):
            continue
        salt, digest = record.get("salt"), record.get("hash")
        iterations = record.get("iterations", DEFAULT_ITERATIONS)
        role = record.get("role")
        if (
            not isinstance(salt, str) or len(salt) != 32 or any(c not in "0123456789abcdef" for c in salt)
            or not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
            or not isinstance(iterations, int) or isinstance(iterations, bool)
            or not (MIN_ITERATIONS <= iterations <= MAX_ITERATIONS)
            or role not in ROLES
        ):
            continue
        users[username] = {"salt": salt, "hash": digest, "iterations": iterations, "role": role}
    if not users:
        raise AuthUnavailable("operator_file_invalid")
    return users


def load_operators():
    """Baca berkas operator dengan cache mtime; raise AuthUnavailable bila tidak layak."""
    path = Path(AUTH_FILE)
    try:
        stat_result = path.stat()
    except OSError as error:
        raise AuthUnavailable("operator_file_unreadable") from error
    fingerprint = f"{stat_result.st_mtime_ns}:{stat_result.st_size}"
    with _lock:
        if _file_cache["users"] is not None and _file_cache["failures"] == fingerprint:
            return _file_cache["users"]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AuthUnavailable("operator_file_unreadable") from error
    users = _sanitize_users(raw)
    with _lock:
        _file_cache["mtime"] = stat_result.st_mtime_ns
        _file_cache["failures"] = fingerprint
        _file_cache["users"] = users
    return users


def authenticate(username, password):
    """Kembalikan profil operator bila kredensial valid; None bila gagal (fail-closed)."""
    try:
        users = load_operators()
    except AuthUnavailable:
        hash_password("defnett-throttle", secrets.token_hex(16), DEFAULT_ITERATIONS)
        return None
    record = users.get(str(username or ""))
    if record is None:
        hash_password("defnett-throttle-unknown-user", users[next(iter(users))]["salt"], DEFAULT_ITERATIONS)
        return None
    candidate = hash_password(password, record["salt"], record["iterations"])
    if not hmac.compare_digest(candidate, record["hash"]):
        return None
    return {"username": username, "role": record["role"]}


def maybe_rehash(username, password):
    """Angkat rekaman lama ke parameter terbaru SETELAH login sukses.

    Verifikasi ulang kata sandi (jangan percaya pemanggil), salt baru,
    tulis atomik 0600, tanpa menyentuh akun lain. Akun lama tetap bisa
    login walau rehash gagal dismantle; fungsi ini tidak pernah mengunci akun.
    """
    try:
        raw = json.loads(Path(AUTH_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    operators = raw.get("operators") if isinstance(raw, dict) else None
    record = operators.get(username) if isinstance(operators, dict) else None
    if not isinstance(record, dict):
        return False
    salt, digest, iterations = record.get("salt"), record.get("hash"), record.get("iterations")
    if (
        not isinstance(salt, str) or not isinstance(digest, str) or not isinstance(iterations, int)
        or isinstance(iterations, bool) or not (MIN_ITERATIONS <= iterations <= MAX_ITERATIONS)
    ):
        return False
    if not hmac.compare_digest(hash_password(password, salt, iterations), digest):
        return False
    if iterations >= DEFAULT_ITERATIONS:
        return False
    new_salt = secrets.token_hex(16)
    record["salt"] = new_salt
    record["hash"] = hash_password(password, new_salt, DEFAULT_ITERATIONS)
    record["iterations"] = DEFAULT_ITERATIONS
    temporary = f"{AUTH_FILE}.tmp"
    try:
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(raw, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, AUTH_FILE)
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        return False
    with _lock:
        _file_cache.update({"mtime": None, "users": None, "failures": ""})
    return True


def create_session(user, role):
    sid = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    with _lock:
        for expired in [key for key, entry in _sessions.items() if entry["expires"] <= time.monotonic()]:
            _sessions.pop(expired, None)
        _sessions[sid] = {
            "username": user,
            "role": role,
            "csrf": csrf,
            "issued": time.monotonic(),
            "expires": time.monotonic() + SESSION_TTL_SECONDS,
        }
    return {"session_id": sid, "csrf": csrf, "username": user, "role": role}


def get_session(sid):
    if not sid or len(sid) > 128:
        return None
    with _lock:
        entry = _sessions.get(sid)
        if entry is None:
            return None
        if entry["expires"] <= time.monotonic():
            _sessions.pop(sid, None)
            return None
        return {
            "session_id": sid,
            "username": entry["username"],
            "role": entry["role"],
            "csrf": entry["csrf"],
        }


def destroy_session(sid):
    with _lock:
        return _sessions.pop(sid, None) is not None


def authorize(session, required="viewer"):
    if not session:
        return False
    return ROLES.get(session.get("role"), 0) >= ROLES.get(required, ROLES["viewer"])


class LoginTracker:
    """Kunci sementara per sumber setelah beberapa kegagalan login beruntun."""

    def __init__(self):
        self._lock = threading.Lock()
        self._failures = {}

    def locked(self, source, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            stamps = [t for t in self._failures.get(source, []) if now - t < LOGIN_LOCK_SECONDS]
            self._failures[source] = stamps
            if len(stamps) >= MAX_LOGIN_FAILURES:
                return LOGIN_LOCK_SECONDS - int(now - stamps[0]) + 1
            return 0

    def record_failure(self, source, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            stamps = [t for t in self._failures.get(source, []) if now - t < LOGIN_LOCK_SECONDS]
            stamps.append(now)
            self._failures[source] = stamps

    def reset(self, source):
        with self._lock:
            self._failures.pop(source, None)


login_tracker = LoginTracker()
