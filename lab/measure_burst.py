#!/usr/bin/env python3
"""Burst pengukuran pada jendela DRAIN yang DIVERIFIKASI.

Perbedaan dengan measure_metrics.py: request-burst HANYA dikirim SETELAH
ladder skenario mencatat step TARGET_DRAINED (drain terkonfirmasi oleh
collector via runtime API HAProxy) dan berhenti tepat pada step
HEALTH_VERIFICATION (rejoin terkonfirmasi). Setiap request memakai koneksi
baru (urllib urlopen, tanpa pool). Backend yang melayani dicatat dari marker
isi respons.

Keluaran (terpisah dari artefak sebelumnya, tak ditimpa):
  test-results/burst-raw.csv             (semua run, semua fase verifikasi)
  test-results/burst-run<N>.json         (ladder run saat burst)
  test-results/burst-summary.csv         (ringkasan: diajukan in-window, backend marker)

Skema CSV: run_id,ts,http_code,backend_marker,phase
phase: pre_drain (poll sebelum TARGET_DRAINED; hanya meter, bukan bukti) |
       verified_drain (setelah TARGET_DRAINED, sebelum HEALTH_VERIFICATION) |
       post_rejoin (setelah HEALTH_VERIFICATION).
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.request

COLLECTOR_BASE = os.environ.get("COLLECTOR_BASE", "http://127.0.0.1:8090")
HAPROXY_URL = os.environ.get("HAPROXY_URL", "http://127.0.0.1:8080")
SCENARIO = os.environ.get("SCENARIO", "containment_allowed")
TARGET = os.environ.get("TARGET", "server-a")
SURVIVOR = os.environ.get("SURVIVOR", "server-b")
RUNS = int(os.environ.get("RUNS", "3"))
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "0.3"))
BURST_INTERVAL = float(os.environ.get("BURST_INTERVAL", "0.35"))
RUN_TIMEOUT = int(os.environ.get("RUN_TIMEOUT", "600"))
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTDIR = os.environ.get("OUTDIR", os.path.join(SCRIPT_DIR, "test-results"))
PRE_LABEL = "pre_drain"
IN_LABEL = "verified_drain"
POST_LABEL = "post_rejoin"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def http_new_connection(url: str, timeout: float = 3.5) -> tuple[int, str]:
    """Request tunggal dengan koneksi HTTP baru (tidak memakai koneksi persisten)."""
    try:
        req = urllib.request.Request(url, headers={"Connection": "close"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(1024).decode("utf-8", "replace")
            return resp.status, body
    except Exception:
        return 0, ""


def marker_of(body: str, code: int) -> str:
    if code != 200:
        return "no_response"
    if "server-a" in body:
        return "server-a"
    if "server-b" in body:
        return "server-b"
    return "unknown"


def get_json(url: str, timeout: float = 4.0):
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read(200_000).decode("utf-8", "replace"))
    except Exception:
        return None


def wait_collector() -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        code, _ = http_new_connection(f"{COLLECTOR_BASE}/healthz", 3.0)
        if code == 200:
            return
        time.sleep(4)
    sys.exit("collector tidak siap")


def step_time(run: dict, state_name: str):
    for step in run.get("steps") or []:
        if step.get("state") == state_name:
            return step.get("timestamp")
    return None


def main() -> None:
    os.makedirs(OUTDIR, exist_ok=True)
    raw_path = os.path.join(OUTDIR, "burst-raw.csv")
    new_raw = not os.path.exists(raw_path)
    raw_file = open(raw_path, "a", newline="", encoding="utf-8")
    raw = csv.writer(raw_file)
    if new_raw:
        raw.writerow(("phase", "run_id", "ts", "http_code", "backend_marker", "target", "survivor"))
        raw_file.flush()

    wait_collector()
    summary_rows = []

    for n in range(1, RUNS + 1):
        print(f"=== burst run {n}/{RUNS} ({SCENARIO} target={TARGET}) ===", flush=True)
        if n > 1:
            # Jeda cooldown Policy Gate (SCENARIO_COOLDOWN, default lab 20 s)
            # agar run berikutnya tidak ditolak murni karena kecepatan suite.
            cooldown = float(os.environ.get("BURST_COOLDOWN_WAIT", "20"))
            print(f"  tunggu {cooldown:.0f}s (cooldown Policy Gate)…", flush=True)
            time.sleep(cooldown)
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
                run_id = data.get("run_id") or data.get("run", {}).get("run_id") or ""
        except (urllib.error.URLError, json.JSONDecodeError) as error:
            print(f"waktu start gagal ({error}); lewati run {n}", flush=True)
            continue
        if not run_id:
            print(f"start tanpa run_id ({data}); lewati run {n}", flush=True)
            continue

        drain_ft, rejoin_ft = None, None
        in_total = ok_total = a_hits = b_hits = no_response = 0
        run_retried = False
        started = time.monotonic()
        phase = PRE_LABEL
        deadline = started + RUN_TIMEOUT
        while time.monotonic() < deadline:
            run = get_json(f"{COLLECTOR_BASE}/api/demo/scenarios/{run_id}")
            if run is None:
                time.sleep(POLL_SECONDS)
                continue
            if drain_ft is None:
                drain_ft = step_time(run, "TARGET_DRAINED")
                if drain_ft:
                    phase = IN_LABEL
                    survivor_ok = (run.get("steps") or [])
                    survivor_ok = next((s for s in survivor_ok if s.get("state") == "TARGET_DRAINED"), {})
                    survivor_ok = (survivor_ok.get("detail") or {}).get("survivor_state") == "UP"
                    print(f"  TARGET_DRAINED terkonfirmasi ts={drain_ft} survivor_state={survivor_ok}", flush=True)
            if drain_ft and rejoin_ft is None:
                rejoin_ft = step_time(run, "HEALTH_VERIFICATION")
                if rejoin_ft:
                    phase = POST_LABEL
                    state = run.get("state") or "?"
                    print(f"  HEALTH_VERIFICATION (rejoin) terkonfirmasi ts={rejoin_ft} state={state}", flush=True)
                    break
            state_now = run.get("state") or "?"
            if drain_ft is None and state_now in ("COMPLETE", "FAILED", "CANCELLED"):
                codes_failed = []
                for stepx in run.get("steps") or []:
                    if stepx.get("state") == "POLICY_EVALUATION":
                        decision = (stepx.get("detail") or {}).get("decision") or {}
                        codes_failed = [r.get("code") for r in (decision.get("reasons") or []) if not r.get("check")]
                        break
                pace_notes = {"COOLDOWN_ACTIVE", "RATE_LIMIT_REACHED"}
                pace_rejected = bool(codes_failed) and set(codes_failed) <= pace_notes
                if not run_retried and pace_rejected:
                    # Percobaan pertama ditolak pace-guardrail: catat, tunggu, start ulang MAKS 1x.
                    run_retried = True
                    raw.writerow(("REJECTED_PRE_DRAIN_ATTEMPT1", run_id, now_iso(), "POLICY_REJECTED", ",".join(codes_failed), TARGET, SURVIVOR))
                    raw_file.flush()
                    cooldown = float(os.environ.get("BURST_COOLDOWN_WAIT", "20"))
                    print(f"  run ditolak pace-guardrail ({','.join(codes_failed)}); tunggu {cooldown:.0f}s & coba start ulang…", flush=True)
                    time.sleep(cooldown)
                    drain_ft, rejoin_ft = None, None
                    in_total = ok_total = a_hits = b_hits = no_response = 0
                    phase = PRE_LABEL
                    retry_payload = json.dumps({"scenario": SCENARIO, "target": TARGET, "survivor": SURVIVOR}).encode()
                    retry_req = urllib.request.Request(
                        f"{COLLECTOR_BASE}/api/demo/scenarios/start",
                        data=retry_payload,
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    try:
                        with urllib.request.urlopen(retry_req, timeout=8) as resp:
                            retry_data = json.load(resp)
                            run_id = retry_data.get("run_id") or retry_data.get("run", {}).get("run_id") or run_id
                        continue
                    except (urllib.error.URLError, json.JSONDecodeError) as error:
                        print(f"  start ulang gagal ({error}); lewati run {n}", flush=True)
                        raw.writerow(("START_RETRY_FAILED", run_id, now_iso(), "URLError", "", TARGET, SURVIVOR))
                        raw_file.flush()
                        break
                give_up_phase = "REJECTED_AFTER_RETRY" if run_retried and pace_rejected else (
                    "REJECTED_NOT_RETRIED" if not pace_rejected else "START_RETRY_FAILED")
                raw.writerow((give_up_phase, run_id, now_iso(), state_now, ",".join(codes_failed), TARGET, SURVIVOR))
                raw_file.flush()
                print(f"  run terminal tanpa drain (state={state_now}, rejection={','.join(codes_failed) or '-'}) — TIDAK di-retry; lewati run {n}", flush=True)
                break
            if phase == IN_LABEL:
                code, body = http_new_connection(HAPROXY_URL)
                marker = marker_of(body, code)
                in_total += 1
                ok_total += 1 if code == 200 else 0
                if marker == "server-a": a_hits += 1
                elif marker == "server-b": b_hits += 1
                else: no_response += 1
                row = (phase, run_id, now_iso(), str(code), marker, TARGET, SURVIVOR)
                raw.writerow(row)
                raw_file.flush()
            time.sleep(POLL_SECONDS)

        # Tunggu state terminal (max 8 s) agar JSON run tidak tertangkap saat RECOVERY
        fresh = get_json(f"{COLLECTOR_BASE}/api/demo/scenarios/{run_id}") or {}
        for _ in range(16):
            if fresh.get("state") in ("COMPLETE", "FAILED", "CANCELLED"):
                break
            time.sleep(0.5)
            fresh = get_json(f"{COLLECTOR_BASE}/api/demo/scenarios/{run_id}") or {}
        run_file = open(os.path.join(OUTDIR, f"burst-run{n}.json"), "w", encoding="utf-8")
        run_file.write(json.dumps(fresh))
        run_file.close()
        summary_rows.append({
            "run": n, "run_id": run_id,
            "attempts": 2 if run_retried else 1,
            "drain_ts": drain_ft or "", "rejoin_ts": rejoin_ft or "",
            "in_window_requests": in_total, "ok_200": ok_total,
            "to_target": a_hits, "to_survivor": b_hits, "no_response": no_response,
        })
        raw_file.flush()
        time.sleep(3)

    raw_file.close()
    summary_path = os.path.join(OUTDIR, "burst-summary.csv")
    with open(summary_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(summary_rows[0].keys()) if summary_rows else ["run"])
        writer.writeheader()
        for row in summary_rows:
            writer.writerow(row)
    print(f"selesai. ringkasan: {summary_path}", flush=True)


if __name__ == "__main__":
    main()
