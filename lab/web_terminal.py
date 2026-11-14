"""Terminal web untuk lab: shell SSH ke server-a / server-b dari dashboard.

Collector hanya menjalankan klien `ssh` di dalam pseudo-terminal dan meneruskan
byte ke browser. Login tetap memakai username + password server itu sendiri:
username diisi di form, password diketik di prompt ssh di dalam terminal. Kunci
SSH tidak dipakai (PubkeyAuthentication=no) dan password tidak disimpan atau dicatat.

Batasan: hanya host di TERMINAL_HOSTS, sesi terikat ke sesi operator yang
membukanya, jumlah sesi dibatasi, dan sesi yang menganggur ditutup otomatis.
"""
import base64
import os
import pty
import re
import secrets
import shutil
import signal
import struct
import subprocess
import threading
import time

try:
    import fcntl
    import termios
except ImportError:  # pragma: no cover - hanya Linux/macOS
    fcntl = termios = None

ENABLED = os.environ.get("WEB_TERMINAL_ENABLED", "1") == "1"
SSH_BINARY = os.environ.get("WEB_TERMINAL_SSH", "/usr/bin/ssh")
SSH_PORT = int(os.environ.get("WEB_TERMINAL_SSH_PORT", "22"))
KNOWN_HOSTS = os.environ.get("WEB_TERMINAL_KNOWN_HOSTS", "/tmp/defnett-terminal-known-hosts")
IDLE_SECONDS = int(os.environ.get("WEB_TERMINAL_IDLE_SECONDS", "900"))
MAX_SESSIONS = int(os.environ.get("WEB_TERMINAL_MAX_SESSIONS", "4"))
MAX_PER_OWNER = int(os.environ.get("WEB_TERMINAL_MAX_PER_OWNER", "2"))
BUFFER_LIMIT = 256 * 1024
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")


def _hosts():
    raw = os.environ.get("TERMINAL_HOSTS", "server-a=192.168.56.11,server-b=192.168.56.12")
    hosts = {}
    for item in raw.split(","):
        name, _, address = item.strip().partition("=")
        if name and address:
            hosts[name.strip()] = address.strip()
    return hosts


TERMINAL_HOSTS = _hosts()


class TerminalError(Exception):
    pass


class Session:
    def __init__(self, owner, host, username, pid, fd, proc=None):
        self.proc = proc
        self.id = secrets.token_urlsafe(18)
        self.owner, self.host, self.username = owner, host, username
        self.pid, self.fd = pid, fd
        self.created = self.last = time.monotonic()
        self.base = 0              # offset absolut byte pertama di buf
        self.buf = bytearray()
        self.closed = False
        self.exit_code = None
        self.cond = threading.Condition()

    @property
    def end(self):
        return self.base + len(self.buf)

    def append(self, data):
        with self.cond:
            self.buf.extend(data)
            if len(self.buf) > BUFFER_LIMIT:
                drop = len(self.buf) - BUFFER_LIMIT
                del self.buf[:drop]
                self.base += drop
            self.cond.notify_all()

    def finish(self):
        with self.cond:
            if self.closed:
                return
            self.closed = True
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.cond.notify_all()


_sessions = {}
_lock = threading.Lock()


def _reader(session):
    while True:
        try:
            data = os.read(session.fd, 4096)
        except OSError:
            break
        if not data:
            break
        session.append(data)
    try:
        if session.proc is not None:
            session.exit_code = session.proc.wait()
        else:
            _, status = os.waitpid(session.pid, 0)
            session.exit_code = os.waitstatus_to_exitcode(status)
    except (ChildProcessError, OSError):
        pass
    session.finish()


def _kill(session):
    try:
        os.kill(session.pid, signal.SIGHUP)
    except (ProcessLookupError, OSError):
        pass
    session.finish()


def _reaper():
    while True:
        time.sleep(15)
        now = time.monotonic()
        with _lock:
            items = list(_sessions.values())
        for session in items:
            if not session.closed and now - session.last > IDLE_SECONDS:
                print(f"terminal {session.host} ditutup karena idle ({session.username})", flush=True)
                _kill(session)
            if session.closed and now - session.last > 120:
                with _lock:
                    _sessions.pop(session.id, None)


threading.Thread(target=_reaper, name="terminal-reaper", daemon=True).start()


def _get(session_id, owner):
    with _lock:
        session = _sessions.get(str(session_id))
    if session is None or not secrets.compare_digest(session.owner, owner):
        raise TerminalError("terminal_not_found")
    return session


def open_session(owner, host, username, rows=24, cols=80):
    if not ENABLED:
        raise TerminalError("terminal_disabled")
    if not owner:
        raise TerminalError("unauthorized")
    address = TERMINAL_HOSTS.get(str(host))
    if not address:
        raise TerminalError("unknown_host")
    username = str(username or "").strip()
    if not USERNAME_RE.fullmatch(username):
        raise TerminalError("invalid_username")
    with _lock:
        live = [s for s in _sessions.values() if not s.closed]
        if len(live) >= MAX_SESSIONS:
            raise TerminalError("too_many_terminals")
        if sum(1 for s in live if s.owner == owner) >= MAX_PER_OWNER:
            raise TerminalError("too_many_terminals_for_operator")
    argv = [
        SSH_BINARY, "-tt", "-F", "/dev/null",
        "-o", "PubkeyAuthentication=no",
        "-o", "PreferredAuthentications=keyboard-interactive,password",
        "-o", "NumberOfPasswordPrompts=3",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o", "ConnectTimeout=8",
        "-o", "ServerAliveInterval=30",
        "-p", str(SSH_PORT), "-l", username, address,
    ]
    env = {
        "PATH": "/usr/bin:/bin", "TERM": "xterm-256color", "LANG": "C.UTF-8",
        "HOME": os.environ.get("WEB_TERMINAL_HOME", "/tmp"),
    }
    pid, fd, proc = _spawn(argv, env)
    session = Session(owner, host, username, pid, fd, proc)
    resize(session, rows, cols)
    with _lock:
        _sessions[session.id] = session
    threading.Thread(target=_reader, args=(session,), name=f"terminal-{host}", daemon=True).start()
    return session


def _spawn(argv, env):
    """Jalankan argv di pseudo-terminal sebagai controlling tty (ssh membaca password dari /dev/tty).

    Di Linux pakai subprocess + `setsid -c` (aman di server multi-thread). Fallback pty.fork
    hanya untuk sistem tanpa setsid (mis. macOS saat uji lokal)."""
    setsid = shutil.which("setsid", path="/usr/bin:/bin")
    if setsid:
        master, slave = os.openpty()
        try:
            proc = subprocess.Popen(
                [setsid, "-w", "-c", *argv], stdin=slave, stdout=slave, stderr=slave,
                env=env, close_fds=True, start_new_session=False,
            )
        finally:
            os.close(slave)
        return proc.pid, master, proc
    pid, fd = pty.fork()
    if pid == 0:  # anak: langsung exec, jangan pernah kembali ke kode server
        try:
            os.execve(argv[0], argv, env)
        finally:
            os._exit(127)
    return pid, fd, None


def resize(session, rows, cols):
    try:
        rows, cols = max(5, min(int(rows), 200)), max(20, min(int(cols), 400))
    except (TypeError, ValueError):
        return
    if fcntl and not session.closed:
        try:
            fcntl.ioctl(session.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass


def read(session_id, owner, offset, wait=10.0):
    session = _get(session_id, owner)
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        offset = 0
    deadline = time.monotonic() + max(0.0, min(float(wait), 20.0))
    with session.cond:
        while offset >= session.end and not session.closed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            session.cond.wait(remaining)
        start = max(offset, session.base)
        data = bytes(session.buf[start - session.base:])
        return {
            "data": base64.b64encode(data).decode("ascii"),
            "offset": session.end,
            "skipped": start > offset,
            "closed": session.closed and start + len(data) >= session.end,
            "exit_code": session.exit_code,
        }


def write(session_id, owner, data_b64):
    session = _get(session_id, owner)
    if session.closed:
        raise TerminalError("terminal_closed")
    try:
        data = base64.b64decode(str(data_b64 or ""), validate=True)
    except (ValueError, TypeError):
        raise TerminalError("invalid_input") from None
    if len(data) > 16384:
        raise TerminalError("input_too_large")
    session.last = time.monotonic()
    view = memoryview(data)
    while view:
        written = os.write(session.fd, view)
        view = view[written:]


def resize_session(session_id, owner, rows, cols):
    session = _get(session_id, owner)
    session.last = time.monotonic()
    resize(session, rows, cols)


def close(session_id, owner):
    session = _get(session_id, owner)
    _kill(session)
