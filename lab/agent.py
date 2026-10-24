import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


HOST_ID = os.environ["HOST_ID"]
WATCH_ROOT = Path(os.environ.get("WATCH_ROOT", "/watched"))
STATE_PATH = Path(os.environ.get("STATE_PATH", "/state/baseline.json"))
COLLECTOR_URL = os.environ.get("COLLECTOR_URL", "http://collector:8090/v1/events")
HEARTBEAT_URL = os.environ.get(
    "HEARTBEAT_URL", COLLECTOR_URL.rsplit("/", 1)[0] + "/agent/heartbeat"
)
POLL_SECONDS = max(1, float(os.environ.get("POLL_SECONDS", "3")))
HEARTBEAT_SECONDS = max(3, float(os.environ.get("HEARTBEAT_SECONDS", "10")))
COLLECTOR_TIMEOUT = max(5, float(os.environ.get("COLLECTOR_TIMEOUT", "45")))
PATROL_SNAPSHOT_URL = os.environ.get(
    "PATROL_SNAPSHOT_URL", COLLECTOR_URL.rsplit("/", 1)[0] + "/patrol/snapshot"
)
CANARY = b"DEFNETT-LAB-MALWARE-CANARY"
AGENT_TOKEN = (os.environ.get("AGENT_TOKEN") or "").encode("utf-8")


def post_json(url, payload, timeout, expect_status=200):
    headers = {"Content-Type": "application/json"}
    if AGENT_TOKEN:
        headers["X-Defnett-Token"] = AGENT_TOKEN.decode("utf-8")
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != expect_status:
            raise RuntimeError(f"collector returned HTTP {response.status}")
        return response.status


def snapshot():
    result = {}
    root = WATCH_ROOT.resolve()
    for path in sorted(WATCH_ROOT.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            path.resolve().relative_to(root)
        except (OSError, ValueError):
            continue
        relative_path = path.relative_to(WATCH_ROOT).as_posix()
        digest = hashlib.sha256()
        canary_match = False
        overlap = b""
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                    if not canary_match and CANARY in overlap + chunk:
                        canary_match = True
                    overlap = (overlap + chunk)[-(len(CANARY) - 1):]
        except (FileNotFoundError, PermissionError, OSError):
            continue
        result[relative_path] = {
            "sha256": digest.hexdigest(),
            "canary_match": canary_match,
        }
    return result


def send_event(event_type, path, old_hash, new_hash, event_signal):
    event = {
        "host_id": HOST_ID,
        "source": "lab-fim-agent",
        "event_type": event_type,
        "path": path,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "content_signal": bool(event_signal),
        "indicator": "DEFNETT_LAB_CANARY" if event_signal else None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    post_json(COLLECTOR_URL, event, COLLECTOR_TIMEOUT, expect_status=201)


def send_heartbeat():
    payload = {
        "host_id": HOST_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    post_json(HEARTBEAT_URL, payload, 5, expect_status=202)


def send_patrol_snapshot(current):
    payload = {
        "host_id": HOST_ID,
        "files": [
            {"path": path, "sha256": state["sha256"]}
            for path, state in sorted(current.items())
        ],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    post_json(PATROL_SNAPSHOT_URL, payload, COLLECTOR_TIMEOUT, expect_status=202)


def load_state():
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def save_state(current):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(current, sort_keys=True), encoding="utf-8")
    temporary.replace(STATE_PATH)


def main():
    previous = load_state()
    if previous is None:
        previous = snapshot()
        save_state(previous)
        try:
            send_patrol_snapshot(previous)
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
            print(f"{HOST_ID}: patrol snapshot failed: {error}", flush=True)
        print(f"{HOST_ID}: initial baseline recorded", flush=True)

    last_heartbeat = 0.0
    while True:
        now = time.monotonic()
        if now - last_heartbeat >= HEARTBEAT_SECONDS:
            try:
                send_heartbeat()
                last_heartbeat = now
            except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
                print(f"{HOST_ID}: heartbeat failed: {error}", flush=True)
        time.sleep(POLL_SECONDS)
        current = snapshot()
        try:
            send_patrol_snapshot(current)
        except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
            print(f"{HOST_ID}: patrol snapshot failed: {error}", flush=True)
        failed = False
        for path in sorted(previous.keys() | current.keys()):
            old_state = previous.get(path)
            new_state = current.get(path)
            if isinstance(old_state, str):
                old_state = {"sha256": old_state, "canary_match": False}
            old_hash = old_state.get("sha256") if old_state else None
            new_hash = new_state.get("sha256") if new_state else None
            if old_hash == new_hash:
                continue
            event_type = (
                "file_created" if old_hash is None else
                "file_deleted" if new_hash is None else
                "file_modified"
            )
            try:
                signal = (
                    new_state.get("canary_match", False) if new_state
                    else old_state.get("canary_match", False)
                )
                send_event(event_type, path, old_hash, new_hash, signal)
                print(f"{HOST_ID}: {event_type} {path}", flush=True)
            except (urllib.error.URLError, TimeoutError, OSError, RuntimeError) as error:
                print(f"{HOST_ID}: send failed: {error}", flush=True)
                failed = True
                break
        if not failed:
            previous = current
            save_state(previous)


if __name__ == "__main__":
    main()
