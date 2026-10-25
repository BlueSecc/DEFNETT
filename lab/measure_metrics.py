#!/usr/bin/env python3
"""Pengukuran ketersediaan DEFNETT dengan request HTTP nyata ke HAProxy.

Fase per run:
  baseline     -> request ke layanan sebelum skenario dimulai
  containment  -> sampler 500 ms selama skenario Scenario Driver berjalan
  recovery     -> jeda stabil pasca-run (layanan kembali penuh)

Keluaran di test-results/:
  metrics-raw.csv            (semua fase, semua run)
  metrics-raw-run<N>.csv     (satu run: baseline+containment+recovery, schema sama)
  metrics-run<N>.json        (ladder & metrik run dari collector)
  metrics-api-<N>.json       (snapshot /api/demo/metrics saat itu)

Skema CSV mentah: phase,run_id,ts,http_code,backend_marker
Kode 000 berarti request gagal total (timeout/koneksi).
Perhitungan ringkasan ada di summarize_metrics.py (terpisah).
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.request

COLLECTOR_BASE = os.environ.get("COLLECTOR_BASE", "http://127.0.0.1:8090")
HAPROXY_URL = os.environ.get("HAPROXY_URL", "http://127.0.0.1:8080")
SCENARIO = os.environ.get("SCENARIO", "containment_allowed")
TARGET = os.environ.get("TARGET", "server-a")
SURVIVOR = os.environ.get("SURVIVOR", "server-b")
RUNS = int(os.environ.get("RUNS", "3"))
BASELINE_COUNT = int(os.environ.get("BASELINE_COUNT", "12"))
BASELINE_INTERVAL = float(os.environ.get("BASELINE_INTERVAL", "0.5"))
SAMPLER_INTERVAL = float(os.environ.get("SAMPLER_INTERVAL", "0.5"))
STABILITY_SECONDS = int(os.environ.get("STABILITY_SECONDS", "20"))
RUN_TIMEOUT = int(os.environ.get("RUN_TIMEOUT", "600"))
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTDIR = os.environ.get("OUTDIR", os.path.join(SCRIPT_DIR, "test-results"))
current_run_id = ""


class FlushedWriter:
    """csv.writer yang langsung flush setiap baris agar data selamat."""

    def __init__(self, path: str, append: bool = False) -> None:
        self.file = open(path, "a" if append else "w", newline="", encoding="utf-8")
        self.writer = csv.writer(self.file)

    def write(self, row: tuple) -> None:
        self.writer.writerow(row)
        self.file.flush()

    def close(self) -> None:
        self.file.close()


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def http_get(url: str, timeout: float = 4.0, limit: int = 262_144) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read(limit).decode("utf-8", "replace")
    except Exception:
        return 0, ""


def backend_marker(body: str) -> str:
    if "server-a" in body:
        return "server-a"
    if "server-b" in body:
        return "server-b"
    return "unknown"


class Sampler:
    """Thread sampler: setiap tick kirim 1 request, tulis baris CSV fase aktif."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.phase = "baseline"
        self.stop = threading.Event()
        self.interval = SAMPLER_INTERVAL
        self.writers: list[FlushedWriter] = []
        self.total = 0
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self.stop.is_set():
            start = time.monotonic()
            with self.lock:
                phase = self.phase
                row = None
            code, body = http_get(HAPROXY_URL)
            marker = backend_marker(body) if code == 200 else "no_response"
            row = (phase, current_run_id, now_iso(), str(code), marker)
            with self.lock:
                for writer in self.writers:
                    writer.write(row)
                self.total += 1
            wait = self.interval - (time.monotonic() - start)
            if wait > 0:
                self.stop.wait(wait)

    def start(self) -> None:
        self.thread.start()

    def stop_now(self) -> None:
        self.stop.set()
        self.thread.join(timeout=5)

    def set_phase(self, phase: str) -> None:
        with self.lock:
            self.phase = phase


def wait_collector(timeout_s: int = 30) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        code, _ = http_get(f"{COLLECTOR_BASE}/healthz", 3.0)
        if code == 200:
            return
        print(f"collector belum siap; mencoba lagi…", file=sys.stderr)
        time.sleep(4)
    sys.exit("ERROR: collector tidak siap di " + COLLECTOR_BASE)


def scenario_state(run_id: str) -> str:
    code, body = http_get(f"{COLLECTOR_BASE}/api/demo/scenarios/{run_id}", 5.0)
    if code != 200:
        return "?"
    try:
        return str(json.loads(body).get("state") or "?")
    except json.JSONDecodeError:
        return "?"


TERMINAL = {"COMPLETE", "FAILED", "CANCELLED"}


def main() -> None:  # noqa: C901
    global current_run_id
    os.makedirs(OUTDIR, exist_ok=True)
    raw_path = os.path.join(OUTDIR, "metrics-raw.csv")
    new_raw = not os.path.exists(raw_path)

    sampler = Sampler()
    current_run_id = ""

    def handle_sigint(signum, frame):
        sampler.stop_now()
        sys.exit(130)

    signal.signal(signal.SIGINT, handle_sigint)

    wait_collector()
    sampler.start()

    runs_done = 0
    raw_global = FlushedWriter(raw_path, append=True)
    if new_raw:
        raw_global.write(("phase", "run_id", "ts", "http_code", "backend_marker"))
    # Global writer aktif untuk semua fase (baseline/containment/recovery).
    sampler.writers.append(raw_global)

    n = 0
    while n < RUNS:
        n += 1
        print(f"=== run {n}/{RUNS} ({SCENARIO} target={TARGET}) ===", flush=True, file=sys.stderr)

        run_path = os.path.join(OUTDIR, f"metrics-raw-run{n}.csv")
        run_writer = FlushedWriter(run_path)
        columns = ("phase", "run_id", "ts", "http_code", "backend_marker")
        run_writer.write(columns)
        sampler.writers.append(run_writer)

        # Fase baseline: request murni, tanpa skenario
        sampler.set_phase("baseline")
        for _ in range(BASELINE_COUNT):
            time.sleep(BASELINE_INTERVAL)

        # Mulai skenario melalui Scenario Driver
        payload = json.dumps({"scenario": SCENARIO, "target": TARGET, "survivor": SURVIVOR}).encode()
        request = urllib.request.Request(
            f"{COLLECTOR_BASE}/api/demo/scenarios/start",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as resp:
                data = json.load(resp)
                run_id = str(data.get("run_id") or data.get("run", {}).get("run_id") or "")
        except (urllib.error.URLError, json.JSONDecodeError) as error:
            print(f"Gagal memulai skenario ({error}); lewati run {n}", file=sys.stderr)
            sampler.writers.remove(run_writer)
            run_writer.close()
            continue
        current_run_id = run_id
        run_writer.write(("run_id", current_run_id, now_iso(), "", ""))
        raw_global.write(("run_id", current_run_id, now_iso(), "", ""))

        # Fase containment: sampler tetap 500 ms selama run aktif
        sampler.set_phase("containment")
        waited = 0
        state = "?"
        while waited < RUN_TIMEOUT:
            state = scenario_state(current_run_id)
            if state in TERMINAL:
                break
            time.sleep(3)
            waited += 3
        print(f"state run: {state}", flush=True, file=sys.stderr)

        # Fase recovery: layanan kembali; sampel selama STABILITY_SECONDS
        sampler.set_phase("recovery")
        run_writer.write(("state", current_run_id, now_iso(), "", state))
        for _ in range(STABILITY_SECONDS):
            time.sleep(1)

        sampler.writers.remove(run_writer)
        run_writer.close()

        code, ladder = http_get(f"{COLLECTOR_BASE}/api/demo/scenarios/{current_run_id}", 5.0)
        if code == 200:
            with open(os.path.join(OUTDIR, f"metrics-run{n}.json"), "w", encoding="utf-8") as fh:
                fh.write(ladder)
        code, snapshot = http_get(f"{COLLECTOR_BASE}/api/demo/metrics", 5.0)
        if code == 200:
            with open(os.path.join(OUTDIR, f"metrics-api-{n}.json"), "w", encoding="utf-8") as fh:
                fh.write(snapshot)
        runs_done += 1
        time.sleep(3)

    sampler.stop_now()
    sampler.writers.remove(raw_global)
    raw_global.close()
    print(f"Selesai. {runs_done}/{RUNS} run terekam. Raw: {raw_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
