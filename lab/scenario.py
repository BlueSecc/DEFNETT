"""Scenario Driver DEFNETT lab — Cyber Intrusion Patrol.

Pengendali skenario demo di sisi backend. Backend yang menggerakkan cerita:
visualisasi di dashboard hanya mengikuti state yang dibaca dari API lab.

Skenario yang tersedia:
  containment_allowed                    — canary pada host target, Policy Gate
                                           menyetujui, drain, karantina,
                                           verifikasi, rejoin.
  containment_blocked_survivor_down      — survivor tidak sehat; gate WAJIB
                                           menolak dan layanan dipertahankan.
  containment_blocked_evidence_invalid   — file lab yang tidak memenuhi kriteria
                                           canary; gate menolak karena bukti.

Rancangan kontrak (Blueprint v3 bagian 2.3):
  - run_id dibuat server, idempoten: satu run aktif per waktu.
  - pause/resume/cancel hanya menghentikan langkah yang belum dieksekusi;
    backend yang sudah di-drain tidak otomatis diaktifkan kembali.
  - reset demo tidak menghapus bukti historis.
  - semua event dan keputusan tercatat dengan run_id + event_id.
"""

import threading
import time
from datetime import datetime, timezone

SCENARIOS = {
    "containment_allowed": "Containment diizinkan (canary lab terverifikasi)",
    "containment_blocked_survivor_down": "Penolakan: backend survivor tidak sehat",
    "containment_blocked_evidence_invalid": "Penolakan: bukti lab tidak memenuhi syarat",
}

STATE_IDLE = "IDLE"
STATE_PRECHECK = "PRECHECK"
STATE_RECONNAISSANCE = "RECONNAISSANCE"
STATE_CANARY_EVENT = "CANARY_EVENT"
STATE_EVIDENCE_VALIDATION = "EVIDENCE_VALIDATION"
STATE_POLICY_EVALUATION = "POLICY_EVALUATION"
STATE_POLICY_APPROVED = "POLICY_APPROVED"
STATE_TARGET_DRAINED = "TARGET_DRAINED"
STATE_CANARY_QUARANTINED = "CANARY_QUARANTINED"
STATE_HEALTH_VERIFICATION = "HEALTH_VERIFICATION"
STATE_RECOVERY = "RECOVERY"
STATE_POLICY_REJECTED = "POLICY_REJECTED"
STATE_REJECTION_RECORDED = "REJECTION_RECORDED"
STATE_SERVICE_PRESERVED = "SERVICE_PRESERVED"
STATE_COMPLETE = "COMPLETE"
STATE_FAILED = "FAILED"
STATE_CANCELLED = "CANCELLED"

TERMINAL_STATES = {STATE_COMPLETE, STATE_FAILED, STATE_CANCELLED}
FAILED_STATES = {STATE_FAILED, STATE_CANCELLED}

CANCEL_SENTINEL = "SCENARIO_CANCEL_REQUESTED"

TRANSITIONS = {
    STATE_IDLE: {STATE_PRECHECK, STATE_FAILED, STATE_CANCELLED},
    STATE_PRECHECK: {STATE_RECONNAISSANCE, STATE_FAILED, STATE_CANCELLED},
    STATE_RECONNAISSANCE: {STATE_CANARY_EVENT, STATE_FAILED, STATE_CANCELLED},
    STATE_CANARY_EVENT: {STATE_EVIDENCE_VALIDATION, STATE_FAILED, STATE_CANCELLED},
    STATE_EVIDENCE_VALIDATION: {STATE_POLICY_EVALUATION, STATE_FAILED, STATE_CANCELLED},
    STATE_POLICY_EVALUATION: {
        STATE_POLICY_APPROVED, STATE_POLICY_REJECTED, STATE_FAILED, STATE_CANCELLED,
    },
    STATE_POLICY_APPROVED: {STATE_TARGET_DRAINED, STATE_FAILED, STATE_CANCELLED},
    STATE_TARGET_DRAINED: {STATE_CANARY_QUARANTINED, STATE_FAILED, STATE_CANCELLED},
    STATE_CANARY_QUARANTINED: {STATE_HEALTH_VERIFICATION, STATE_RECOVERY, STATE_FAILED, STATE_CANCELLED},
    STATE_HEALTH_VERIFICATION: {STATE_RECOVERY, STATE_FAILED, STATE_CANCELLED},
    STATE_RECOVERY: {STATE_COMPLETE, STATE_FAILED, STATE_CANCELLED},
    STATE_POLICY_REJECTED: {STATE_REJECTION_RECORDED, STATE_FAILED, STATE_CANCELLED},
    STATE_REJECTION_RECORDED: {STATE_SERVICE_PRESERVED, STATE_FAILED, STATE_CANCELLED},
    STATE_SERVICE_PRESERVED: {STATE_COMPLETE, STATE_FAILED, STATE_CANCELLED},
}


def valid_transition(current, nxt):
    if current not in TRANSITIONS:
        return False
    return nxt in TRANSITIONS[current]


def utc_now():
    return datetime.now(timezone.utc)


def iso(dt=None):
    return (dt or utc_now()).isoformat()


def parse_iso(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (TypeError, ValueError):
        return None


class ScenarioError(Exception):
    """Kegagalan yang dieksekusi menjadi state FAILED run."""


class Runner:
    """Orkestrator skenario. Dependensi (I/O lab) disuntik dari collector
    supaya state machine dapat diuji dengan fake tanpa Docker."""

    def __init__(self, deps, config=None):
        self.deps = deps
        self.config = config or {}
        self.wait_seconds = float(self.config.get("step_wait_seconds", 120))
        self.probe_count = max(1, int(self.config.get("probe_count", 4)))
        self.isolated_probe_count = max(1, int(self.config.get("isolated_probe_count", 6)))
        self.recovery_probe_count = max(1, int(self.config.get("recovery_probe_count", 6)))
        self.probe_interval = float(self.config.get("probe_interval_seconds", 0.4))
        self.lock = threading.Lock()

    # ---------- helpers ----------

    def valid_scenario(self, name):
        return name in SCENARIOS

    def survivor_for(self, target):
        return "server-b" if target == "server-a" else "server-a"

    def _probe_service(self, run, phase, count):
        results = []
        for _ in range(max(1, count)):
            results.append(self.deps.service_probe())
            if self.probe_interval:
                time.sleep(self.probe_interval)
        success = sum(1 for item in results if item.get("status") == "allowed")
        backends = sorted({item.get("backend") for item in results if item.get("backend")})
        metrics = self.deps.read_metrics(run["run_id"]) or {}
        requests = metrics.setdefault("requests", {})
        created = parse_iso(run.get("created_at"))
        requests[phase] = {
            "success": success,
            "total": len(results),
            "backends_seen": backends,
            "scenario_wallclock_ms": (
                int((utc_now() - created).total_seconds() * 1000) if created else None
            ),
        }
        self.deps.write_metrics(run["run_id"], metrics)
        return {"success": success, "total": len(results), "backends_seen": backends}

    def _wait_stage(self, run, stages):
        return self.deps.wait_remediation_stage(run["run_id"], stages, self.wait_seconds)

    # ---------- steps ----------

    def step_precheck(self, run):
        states = self.deps.backend_states()
        target, survivor = run["target"], run["survivor"]
        target_state = (states.get(target) or "UNKNOWN").upper()
        if target_state in {"DOWN", "MAINT", "MAINTENANCE", "DRAIN"} or "DOWN" in target_state:
            raise ScenarioError(
                f"Backend target {target} sudah tidak dirotasi ({target_state}); mulai skenario pada backend lain."
            )
        baseline = self._probe_service(run, "baseline", self.probe_count)
        if baseline["success"] < max(1, baseline["total"] // 2):
            raise ScenarioError("Baseline request melalui HAProxy gagal; kondisi lab tidak layak skenario.")
        return {
            "backend_states": states,
            "baseline_requests": baseline,
            "detail": (
                f"Status awal: target={states.get(target)} survivor={states.get(survivor)}; "
                "status aktual diteruskan ke Policy Gate saat evaluasi."
            ),
        }

    def step_reconnaissance(self, run):
        result = self.deps.denied_probe(run)
        if result.get("status") != "denied":
            raise ScenarioError(f"Probe rekognisi tidak sesuai: {result}")
        return {
            "detail": "Penyusup virtual mencoba akses terbatas; app lab menolak dan mencatat event.",
            "path": result.get("path"),
            "status_code": result.get("status_code"),
            "origin": "lab_fixture",
        }

    def step_canary(self, run):
        fixture = self.deps.fixture_write(run)
        if not fixture.get("accepted"):
            raise ScenarioError(f"Fixture lab gagal pada {run['target']}: {fixture.get('detail', 'unknown')}")
        written_at = fixture.get("written_at") or iso()
        event_ref = self.deps.wait_for_canary_event(run, fixture.get("path"), written_at, self.wait_seconds)
        if event_ref is None:
            raise ScenarioError(
                "Event FIM fixture tidak diterima collector sebelum batas waktu; deteksi tidak terbukti."
            )
        self.deps.record_evidence(run["run_id"], event_ref)
        metrics = self.deps.read_metrics(run["run_id"]) or {}
        detection_dt = parse_iso(event_ref.get("timestamp") or event_ref.get("detected_at"))
        written_dt = parse_iso(written_at)
        if detection_dt and written_dt:
            metrics.setdefault("latencies", {})["detection_ms"] = int(
                (detection_dt - written_dt).total_seconds() * 1000
            )
            self.deps.write_metrics(run["run_id"], metrics)
        return {
            "fixture_written_at": written_at,
            "event": event_ref,
            "origin": "lab_fixture",
            "detail": "File canary lab ditulis oleh fixture; agent FIM mendeteksi dan mengirim event.",
        }

    def step_evidence_validation(self, run):
        detail = self.deps.validate_evidence(run)
        self.deps.record_policy_context(run["run_id"], detail)
        return detail

    def step_policy(self, run):
        decision = self.deps.run_policy_gate(run)
        self.deps.record_decision(run["run_id"], decision)
        approved = decision.get("decision") == "approved"
        return {
            "decision": decision,
            "approved": approved,
            "detail": decision.get("reasons"),
        }

    def step_policy_approved(self, run):
        self.deps.mark_remediation_intent(run)
        return {"detail": "Policy Gate menyetujui containment; playbook canary berjalan pada host target."}

    def step_target_drained(self, run):
        result = self._wait_stage(run, {"ISOLATED", "FAILED", "FAILED_ISOLATED"})
        stage = result.get("stage")
        if stage == CANCEL_SENTINEL:
            raise ScenarioError(CANCEL_SENTINEL)
        if stage != "ISOLATED":
            raise ScenarioError(f"Isolasi target tidak terkonfirmasi: {result.get('detail', stage)}")
        during = self._probe_service(run, "during_drain", self.isolated_probe_count)
        survivor_state = (self.deps.backend_states().get(run["survivor"]) or "UNKNOWN").upper()
        return {
            "stage": stage,
            "during_drain_requests": during,
            "survivor_state": survivor_state,
            "detail": (
                f"Backend {run['target']} dikeluarkan dari rotasi HAProxy; "
                f"survivor {run['survivor']} berstatus {survivor_state}."
            ),
        }

    def step_quarantine(self, run):
        first = self._wait_stage(run, {"REPAIRING", "VERIFYING", "REJOINING", "REPAIRED", "FAILED", "FAILED_ISOLATED"})
        if first.get("stage") == CANCEL_SENTINEL:
            raise ScenarioError(CANCEL_SENTINEL)
        deadline = time.time() + self.deps.quarantine_timeout()
        while time.time() < deadline:
            detail = self.deps.remediation_detail(run["run_id"]) or {}
            if detail.get("status") in {"FAILED", "FAILED_ISOLATED"}:
                raise ScenarioError(f"Karantina gagal: {detail.get('detail')}")
            if detail.get("quarantine_path"):
                return {
                    "quarantine_path": detail["quarantine_path"],
                    "detail": "Artefak canary terverifikasi dipindahkan ke volume karantina host target.",
                }
            time.sleep(0.5)
        raise ScenarioError("Path karantina tidak tercatat sebelum batas waktu.")

    def step_health_verification(self, run):
        result = self._wait_stage(run, {"REPAIRED", "FAILED", "FAILED_ISOLATED"})
        stage = result.get("stage")
        if stage == CANCEL_SENTINEL:
            raise ScenarioError(CANCEL_SENTINEL)
        if stage != "REPAIRED":
            raise ScenarioError(f"Verifikasi kesehatan dan rejoin gagal: {result.get('detail', stage)}")
        return {
            "stage": stage,
            "detail": f"Health check {run['target']} lulus; backend diaktifkan kembali oleh playbook.",
        }

    def step_recovery(self, run):
        states = self.deps.backend_states()
        survivor_state = (states.get(run["survivor"]) or "UNKNOWN").upper()
        target_state = (states.get(run["target"]) or "UNKNOWN").upper()
        post = self._probe_service(run, "after_recovery", self.recovery_probe_count)
        detail = {
            "survivor_state": survivor_state,
            "target_state": target_state,
            "after_recovery_requests": post,
        }
        if not survivor_state.startswith("UP"):
            detail["warning"] = f"Survivor berstatus {survivor_state}."
        return detail

    def step_rejection(self, run):
        decision = self.deps.latest_decision(run["run_id"]) or {}
        self.deps.persist_rejection(run["run_id"])
        return {
            "decision": decision,
            "detail": "Alasan penolakan tercatat pada policy_decisions dan bukti tetap tersimpan.",
        }

    def step_service_preserved(self, run):
        result = self._probe_service(run, "after_rejection", self.probe_count)
        return {
            "requests": result,
            "detail": "Tidak ada backend yang di-drain; layanan dipertahankan.",
        }

    def step_evidence_validation_survivor_down(self, run):
        detail = dict(self.step_evidence_validation(run))
        detail["survivor_simulated_down"] = self.deps.prepare_survivor_down(run)
        return detail

    def step_service_preserved_survivor_down(self, run):
        restored = self.deps.restore_survivor(run)
        detail = dict(self.step_service_preserved(run))
        detail["survivor_restored"] = restored
        return detail

    # ---------- plan assembly ----------

    def _prefix_for(self, run):
        evidence_step = (STATE_EVIDENCE_VALIDATION, self.step_evidence_validation)
        if run["scenario"] == "containment_blocked_survivor_down":
            evidence_step = (STATE_EVIDENCE_VALIDATION, self.step_evidence_validation_survivor_down)
        return [
            (STATE_PRECHECK, self.step_precheck),
            (STATE_RECONNAISSANCE, self.step_reconnaissance),
            (STATE_CANARY_EVENT, self.step_canary),
            evidence_step,
            (STATE_POLICY_EVALUATION, self.step_policy),
        ]

    def policy_continuation(self, run, approved):
        """Langkah lanjutan dipilih dari keputusan gate aktual, bukan rencana kaku."""
        if approved and run["scenario"] == "containment_allowed":
            return [
                (STATE_POLICY_APPROVED, self.step_policy_approved),
                (STATE_TARGET_DRAINED, self.step_target_drained),
                (STATE_CANARY_QUARANTINED, self.step_quarantine),
                (STATE_HEALTH_VERIFICATION, self.step_health_verification),
                (STATE_RECOVERY, self.step_recovery),
                (STATE_COMPLETE, lambda _run: {"detail": "Skenario containment selesai."}),
            ]
        if run["scenario"] == "containment_blocked_survivor_down":
            preserved_step = (STATE_SERVICE_PRESERVED, self.step_service_preserved_survivor_down)
        else:
            preserved_step = (STATE_SERVICE_PRESERVED, self.step_service_preserved)
        return [
            (STATE_POLICY_REJECTED, self.step_rejection),
            (STATE_REJECTION_RECORDED, lambda _run: {"detail": "Penolakan direkam; tidak ada aksi pada backend."}),
            preserved_step,
            (STATE_COMPLETE, lambda _run: {"detail": "Skenario penolakan selesai."}),
        ]

    def plan_for(self, run):
        """Full plan untuk skenario selesai dalam urutan approved (unit test)."""
        plan_tail = self.policy_continuation(run, run["scenario"] == "containment_allowed")
        return self._prefix_for(run) + plan_tail

    # ---------- main loop ----------

    def execute(self, run):
        try:
            return self._execute_plan(run)
        finally:
            if run.get("scenario") == "containment_blocked_survivor_down":
                try:
                    self.deps.restore_survivor(run)
                except Exception:
                    pass

    def _execute_plan(self, run):
        plan = self._prefix_for(run)
        last_detail = None
        while plan:
            state, step = plan.pop(0)
            if state.endswith("_POST"):
                continue
            self.deps.enter_state(run["run_id"], state)
            while True:
                if self.deps.cancelled(run["run_id"]):
                    self.deps.enter_state(run["run_id"], STATE_CANCELLED)
                    return {"state": STATE_CANCELLED}
                if self.deps.paused(run["run_id"]):
                    time.sleep(0.4)
                    continue
                try:
                    detail = step(run)
                except ScenarioError as error:
                    if str(error) == CANCEL_SENTINEL:
                        self.deps.enter_state(run["run_id"], STATE_CANCELLED)
                        return {"state": STATE_CANCELLED}
                    self.deps.enter_state(
                        run["run_id"], STATE_FAILED,
                        detail={"detail": str(error), "state_before": state},
                    )
                    return {"state": STATE_FAILED, "detail": str(error)}
                except Exception as error:  # fail-safe: kegagalan tak terduga
                    self.deps.enter_state(
                        run["run_id"], STATE_FAILED,
                        detail={"detail": f"{type(error).__name__}: {error}", "state_before": state},
                    )
                    return {"state": STATE_FAILED, "detail": f"{type(error).__name__}: {error}"}
                if isinstance(detail, dict) and detail.get("retry"):
                    time.sleep(self.config.get("retry_wait_seconds", 2))
                    continue
                self.deps.record_step(run["run_id"], state, detail)
                last_detail = detail
                break
            if state == STATE_POLICY_EVALUATION:
                plan = self.policy_continuation(run, bool(last_detail.get("approved")))
        self.deps.finalize_metrics(run["run_id"])
        return {"state": STATE_COMPLETE}
