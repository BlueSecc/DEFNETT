#!/usr/bin/env python3
"""Ringkasan pengukuran ketersediaan dari artefak measure_metrics.py.

Input: test-results/metrics-raw.csv (+ test-results/metrics-run<N>.json bila ada).
Output: stdout tabel ringkasan per fase + lokasi CSV merangkum per fase
        test-results/metrics-summary.csv.
Bukan klaim: keberhasilan diukur dari kode HTTP nyata (bukan kesehatan container).
"""
from __future__ import annotations

import csv
import datetime as dt
import glob
import json
import os
import statistics
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTDIR = os.environ.get("OUTDIR", os.path.join(SCRIPT_DIR, "test-results"))
SCHEMA = ("phase", "run_id", "ts", "http_code", "backend_marker")


def load_rows(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        return [row for row in csv.DictReader(fh)]


def phase_stats(rows: list[dict], phase: str) -> dict:
    sel = [row for row in rows if row["phase"] == phase and row["http_code"].isdigit()]
    total = len(sel)
    ok = sum(1 for row in sel if row["http_code"] == "200")
    return {
        "phase": phase,
        "total": total,
        "ok_200": ok,
        "fail": total - ok,
        "success_percent": round(100.0 * ok / total, 2) if total else None,
    }


def run_timings(run_json_path: str) -> dict:
    """Ambil deteksi/containment/recovery dari metrik skenario collector (ms)."""
    if not os.path.exists(run_json_path):
        return {}
    with open(run_json_path, encoding="utf-8") as fh:
        data = json.load(fh)
    metrics = data.get("metrics") or {}
    lat = metrics.get("latencies") or {}
    out: dict = {"state": data.get("state")}
    for key in ("detection_ms", "containment_ms", "recovery_ms", "total_ms"):
        value = lat.get(key)
        out[key] = value if isinstance(value, (int, float)) else None
    requests = metrics.get("requests") or {}
    out.update({f"requests_{k}": v for k, v in requests.items() if isinstance(v, (int, float))})
    return out


def backend_windows(rows: list[dict]) -> list[tuple[str, str, str]]:
    """Ringkas periode backend aktif per fase (urutan kronologis berdasarkan ts)."""
    result = []
    for phase in ("baseline", "containment", "recovery"):
        sel = [row for row in rows if row["phase"] == phase and row["http_code"] == "200"]
        if not sel:
            continue
        first_t, last_t = sel[0]["ts"], sel[-1]["ts"]
        duration_s = None
        try:
            t0 = dt.datetime.fromisoformat(first_t)
            t1 = dt.datetime.fromisoformat(last_t)
            duration_s = round((t1 - t0).total_seconds(), 1)
        except ValueError:
            duration_s = None
        share_a = sum(1 for row in sel if row["backend_marker"] == "server-a") / len(sel)
        result.append((phase, f"{first_t[:19]}..{last_t[:19]}", f"durasi≈{duration_s} s; share server-a={share_a:.0%}"))
    return result


def main() -> None:
    raw_path = os.path.join(OUTDIR, "metrics-raw.csv")
    if not os.path.exists(raw_path):
        sys.exit("metrics-raw.csv tidak ada; jalankan measure_metrics.py dulu.")
    rows = load_rows(raw_path)
    summaries = [phase_stats(rows, phase) for phase in ("baseline", "containment", "recovery")]
    fails = [row for row in rows if row["http_code"] not in ("200", "", "run_id") or row["http_code"] == "000"]

    print("=== Ringkasan pengukuran (kode HTTP nyata via HAProxy :8080) ===")
    for summary in summaries:
        print(f"{summary['phase']:>12}: total={summary['total']} ok_200={summary['ok_200']} "
              f"fail={summary['fail']} success%={summary['success_percent']}")

    run_json_paths = sorted(glob.glob(os.path.join(OUTDIR, "metrics-run*.json")))
    timings = [run_timings(path) for path in run_json_paths]
    for path, timing in zip(run_json_paths, timings):
        label = os.path.basename(path)
        if timing:
            lat = {k: v for k, v in timing.items() if v is not None and k.endswith("_ms")}
            lat_text = " ".join(f"{k}={v}" for k, v in lat.items()) or "(tidak ada latensi bertahap)"
            print(f"{label}: state={timing.get('state')} {lat_text}")

    print("\n--- Jendela backend aktif per fase ---")
    for phase, window, detail in backend_windows(rows):
        print(f"{phase:>12}: {window} | {detail}")

    summary_path = os.path.join(OUTDIR, "metrics-summary.csv")
    with open(summary_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["phase", "total", "ok_200", "fail", "success_percent"])
        writer.writeheader()
        for summary in summaries:
            writer.writerow(summary)
    print(f"\nCSV ringkasan: {summary_path}")
    if fails:
        print(f"KEGAGALAN tercatat: {len(fails)} baris (lihat metrics-raw.csv baris http_code=000)")


if __name__ == "__main__":
    main()
