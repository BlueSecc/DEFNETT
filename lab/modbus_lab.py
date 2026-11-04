"""Instrumented, isolated Modbus TCP simulator for FC03/FC06 lab transactions.

This is an active protocol endpoint with policy enforcement, not a passive IDS.
Only Modbus TCP function codes 03 and 06 are implemented.
"""
import argparse
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import os
import socket
import socketserver
import sqlite3
import struct
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

MAX_MBAP_LENGTH = 254
MAX_ACTIVE_CLIENTS = 16
CLIENT_TIMEOUT_SECONDS = 3
MAX_OUTBOX_EVENTS = 10000


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def load_policy(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    required = {"device_id", "unit_ids", "allowed_sources", "read_ranges", "write_registers", "initial_registers"}
    if not isinstance(data, dict) or not required.issubset(data):
        raise ValueError("invalid_policy_schema")
    if not isinstance(data["device_id"], str) or not data["device_id"] or len(data["device_id"]) > 64:
        raise ValueError("invalid_device_id")
    if not data["unit_ids"] or any(type(v) is not int or not 1 <= v <= 247 for v in data["unit_ids"]):
        raise ValueError("invalid_unit_ids")
    networks = [ipaddress.ip_network(item, strict=False) for item in data["allowed_sources"]]
    ranges = data["read_ranges"]
    if not isinstance(ranges, list) or any(
        not isinstance(r, list) or len(r) != 2 or any(type(v) is not int for v in r)
        or r[0] < 0 or r[1] < r[0] or r[1] > 65535 for r in ranges
    ):
        raise ValueError("invalid_read_ranges")
    writes = data["write_registers"]
    if not isinstance(writes, list) or any(type(v) is not int or not 0 <= v <= 65535 for v in writes):
        raise ValueError("invalid_write_registers")
    initial = data["initial_registers"]
    if not isinstance(initial, dict):
        raise ValueError("invalid_register_map")
    registers = {}
    for raw_address, value in initial.items():
        address = int(raw_address)
        if not 0 <= address <= 65535 or type(value) is not int or not 0 <= value <= 65535:
            raise ValueError("invalid_register_value")
        registers[address] = value
    if "asset_impact" in data and (type(data["asset_impact"]) not in (int, float) or not 0 <= data["asset_impact"] <= 100):
        raise ValueError("invalid_asset_impact")
    return data, networks, registers


def read_exact(sock, length):
    chunks = bytearray()
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise EOFError("truncated_frame")
        chunks.extend(chunk)
    return bytes(chunks)


def parse_frame(frame):
    if not isinstance(frame, bytes) or len(frame) < 8:
        raise ValueError("frame_too_short")
    transaction_id, protocol_id, length = struct.unpack(">HHH", frame[:6])
    if protocol_id != 0:
        raise ValueError("invalid_protocol_id")
    if length < 2 or length > MAX_MBAP_LENGTH:
        raise ValueError("invalid_mbap_length")
    if len(frame) != 6 + length:
        raise ValueError("frame_length_mismatch")
    unit_id = frame[6]
    pdu = frame[7:]
    if not pdu:
        raise ValueError("empty_pdu")
    return transaction_id, unit_id, pdu


def make_response(transaction_id, unit_id, pdu):
    if not 1 <= len(pdu) + 1 <= MAX_MBAP_LENGTH:
        raise ValueError("response_too_large")
    return struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id) + pdu


class Outbox:
    """Small persistent retry queue; successful collector receipt removes item."""

    def __init__(self, path, collector_url, token):
        self.path = path
        self.collector_url = collector_url.rstrip("/") + "/v1/ot/events"
        self.token = token
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS outbox (event_key TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL)")
        self.thread.start()

    def _connect(self):
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        return sqlite3.connect(self.path, timeout=5)

    @contextmanager
    def _db(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def enqueue(self, payload):
        key = payload["dedupe_key"]
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._db() as db:
            count = db.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]
            if count >= MAX_OUTBOX_EVENTS and not db.execute("SELECT 1 FROM outbox WHERE event_key=?", (key,)).fetchone():
                raise RuntimeError("ot_outbox_full")
            db.execute("INSERT OR IGNORE INTO outbox(event_key,payload,created_at) VALUES(?,?,?)", (key, encoded, utc_now()))

    def _run(self):
        delay = 0.5
        while not self.stop_event.is_set():
            with self._db() as db:
                row = db.execute("SELECT event_key,payload FROM outbox ORDER BY created_at LIMIT 1").fetchone()
            if row is None:
                self.stop_event.wait(0.25)
                continue
            request = urllib.request.Request(
                self.collector_url, data=row[1].encode("utf-8"), method="POST",
                headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.token}"},
            )
            try:
                with urllib.request.urlopen(request, timeout=3) as response:
                    if response.status not in (200, 201, 202):
                        raise RuntimeError(f"collector_http_{response.status}")
                with self._db() as db:
                    db.execute("DELETE FROM outbox WHERE event_key=?", (row[0],))
                delay = 0.5
            except (urllib.error.URLError, OSError, TimeoutError, RuntimeError):
                self.stop_event.wait(delay)
                delay = min(10, delay * 2)

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=2)


class ModbusLabServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, policy, networks, registers, outbox, max_clients=MAX_ACTIVE_CLIENTS):
        self.policy, self.networks, self.registers, self.outbox = policy, networks, registers, outbox
        self.register_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(max_clients)
        super().__init__(address, ModbusHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def decision(self, source_ip, destination, unit_id, pdu, raw_frame):
        txn_id = struct.unpack(">H", raw_frame[:2])[0]
        function = pdu[0]
        operation = "READ" if function == 3 else "WRITE" if function == 6 else "UNSUPPORTED"
        register_start = quantity = register_value = None
        raw_digest = hashlib.sha256(raw_frame).hexdigest()
        dedupe = hashlib.sha256(f"{source_ip}|{self.policy['device_id']}|{raw_digest}".encode()).hexdigest()
        reason = "allowed_by_policy"
        decision = "ALLOW"
        exception_code = 1
        response_pdu = bytes([function | 0x80, exception_code])

        if not any(ipaddress.ip_address(source_ip) in network for network in self.networks):
            decision, reason = "DENY", "source_not_allowlisted"
        elif unit_id not in self.policy["unit_ids"]:
            decision, reason = "DENY", "unknown_unit_id"
        elif function == 3:
            if len(pdu) != 5:
                decision, reason, exception_code = "DENY", "malformed_fc03", 3
            else:
                register_start, quantity = struct.unpack(">HH", pdu[1:5])
                end = register_start + quantity - 1
                allowed = 1 <= quantity <= 125 and end <= 65535 and any(
                    low <= register_start and end <= high for low, high in self.policy["read_ranges"]
                )
                if not allowed:
                    decision, reason, exception_code = "DENY", "read_register_out_of_policy", 2
                else:
                    with self.register_lock:
                        values = [self.registers.get(address, 0) for address in range(register_start, end + 1)]
                    body = b"".join(struct.pack(">H", value) for value in values)
                    response_pdu = bytes([3, len(body)]) + body
        elif function == 6:
            if len(pdu) != 5:
                decision, reason, exception_code = "DENY", "malformed_fc06", 3
            else:
                register_start, register_value = struct.unpack(">HH", pdu[1:5])
                if register_start not in self.policy["write_registers"]:
                    decision, reason, exception_code = "DENY", "write_register_out_of_policy", 2
                else:
                    with self.register_lock:
                        self.registers[register_start] = register_value
                    response_pdu = pdu
        else:
            decision, reason = "DENY", "function_code_not_allowed"
        if decision == "DENY":
            response_pdu = bytes([function | 0x80, exception_code])
        event = {
            "event_type": "OT_MODBUS_TRANSACTION", "timestamp": utc_now(),
            "host_id": self.policy["device_id"], "source": "instrumented_modbus_gateway",
            "path": f"modbus://{self.policy['device_id']}/unit/{unit_id}/register/{register_start if register_start is not None else 'unknown'}",
            "protocol": "MODBUS_TCP", "device_id": self.policy["device_id"],
            "source_ip": source_ip, "destination": destination,
            "unit_id": unit_id, "function_code": function, "operation": operation,
            "register_start": register_start, "register_quantity": quantity,
            "register_value": register_value, "policy_id": self.policy.get("policy_id", "modbus-lab-v1"),
            "policy_decision": decision, "policy_reason": reason,
            "response_status": "SUCCESS" if decision == "ALLOW" else "MODBUS_EXCEPTION",
            "exception_code": None if decision == "ALLOW" else exception_code,
            "raw_evidence_sha256": raw_digest, "evidence_reference": f"sha256:{raw_digest}",
            "transaction_id": txn_id, "dedupe_key": dedupe,
            "telemetry_quality": 95, "evidence_confidence": 90,
            "asset_impact": self.policy.get("asset_impact"),
        }
        self.outbox.enqueue(event)
        return make_response(txn_id, unit_id, response_pdu), event

    def record_rejected(self, source_ip, destination, raw_frame, reason):
        digest = hashlib.sha256(raw_frame).hexdigest()
        key = hashlib.sha256(f"{source_ip}|{self.policy['device_id']}|{digest}".encode()).hexdigest()
        self.outbox.enqueue({
            "event_type": "OT_FRAME_REJECTED", "timestamp": utc_now(),
            "host_id": self.policy["device_id"], "source": "instrumented_modbus_gateway",
            "path": f"modbus://{self.policy['device_id']}/invalid-frame",
            "protocol": "MODBUS_TCP", "device_id": self.policy["device_id"],
            "source_ip": source_ip, "destination": destination,
            "unit_id": 0, "function_code": 0, "operation": "UNSUPPORTED",
            "register_start": None, "register_quantity": None, "register_value": None,
            "policy_id": self.policy.get("policy_id", "modbus-lab-v1"),
            "policy_decision": "DENY", "policy_reason": f"malformed_frame:{reason}"[:128],
            "response_status": "MODBUS_EXCEPTION", "exception_code": None,
            "raw_evidence_sha256": digest, "evidence_reference": f"sha256:{digest}",
            "transaction_id": None, "dedupe_key": key,
            "telemetry_quality": 15, "evidence_confidence": 70,
            "asset_impact": self.policy.get("asset_impact"),
        })


class ModbusHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(CLIENT_TIMEOUT_SECONDS)
        local = self.request.getsockname()
        destination = f"{local[0]}:{local[1]}"
        while True:
            try:
                header = read_exact(self.request, 7)
            except (EOFError, OSError, TimeoutError):
                return
            try:
                _, protocol_id, length = struct.unpack(">HHH", header[:6])
                if protocol_id != 0 or length < 2 or length > MAX_MBAP_LENGTH:
                    self.server.record_rejected(self.client_address[0], destination, header, "invalid_mbap_header")
                    return
                tail = read_exact(self.request, length - 1)
                frame = header + tail
                transaction_id, unit_id, pdu = parse_frame(frame)
                response, _event = self.server.decision(self.client_address[0], destination, unit_id, pdu, frame)
            except ValueError as error:
                self.server.record_rejected(self.client_address[0], destination, header, str(error))
                return
            except (EOFError, OSError, TimeoutError):
                return
            try:
                self.request.sendall(response)
            except OSError:
                return


def encode_request(transaction_id, unit_id, function_code, address, value):
    if function_code == 3:
        if type(value) is not int or not 1 <= value <= 125:
            raise ValueError("invalid_register_quantity")
        pdu = struct.pack(">BHH", 3, address, value)
    elif function_code == 6:
        if type(value) is not int or not 0 <= value <= 65535:
            raise ValueError("invalid_register_value")
        pdu = struct.pack(">BHH", 6, address, value)
    else:
        raise ValueError("unsupported_function_code")
    return struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id) + pdu


def client_transaction(host, port, function_code, address, value, unit_id=1, timeout=3, transaction_id=1):
    frame = encode_request(transaction_id, unit_id, function_code, address, value)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(frame)
        header = read_exact(sock, 7)
        _, protocol_id, length = struct.unpack(">HHH", header[:6])
        if protocol_id != 0 or length < 2 or length > MAX_MBAP_LENGTH:
            raise ValueError("invalid_response_mbap")
        response = header + read_exact(sock, length - 1)
    return response


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", default=os.environ.get("OT_POLICY_FILE", "/opt/defnett/ot-policy.json"))
    parser.add_argument("--bind", default=os.environ.get("OT_BIND_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("OT_PORT", "5020")))
    parser.add_argument("--outbox", default=os.environ.get("OT_OUTBOX_PATH", "/state/ot-outbox.sqlite3"))
    parser.add_argument("--collector", default=os.environ.get("OT_COLLECTOR_URL", "http://collector:8090"))
    parser.add_argument("--token", default=os.environ.get("LAB_API_TOKEN", ""))
    parser.add_argument("--client", action="store_true", help="send one real TCP transaction to the configured simulator")
    parser.add_argument("--function", type=int, choices=(3, 6), default=3)
    parser.add_argument("--address", type=int, default=100)
    parser.add_argument("--value", type=int, default=1)
    parser.add_argument("--unit", type=int, default=1)
    args = parser.parse_args()
    if args.client:
        response = client_transaction("127.0.0.1", args.port, args.function, args.address, args.value, args.unit)
        pdu = response[7:]
        denied = bool(pdu and pdu[0] & 0x80)
        result = {"status": "LIVE_LAB_TELEMETRY", "decision": "DENY" if denied else "ALLOW", "response_hex": response.hex()}
        if denied and len(pdu) > 1:
            result["exception_code"] = pdu[1]
        print(json.dumps(result))
        return
    if not args.token:
        raise SystemExit("LAB_API_TOKEN required for OT event forwarding")
    policy, networks, registers = load_policy(args.policy)
    outbox = Outbox(args.outbox, args.collector, args.token)
    server = ModbusLabServer((args.bind, args.port), policy, networks, registers, outbox)
    print(json.dumps({"status": "LIVE_LAB_TELEMETRY", "device_id": policy["device_id"], "bind": args.bind, "port": args.port}), flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        outbox.close()


if __name__ == "__main__":
    main()
