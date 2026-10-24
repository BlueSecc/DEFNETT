"""Policy Gate deterministik DEFNETT lab.

Komponen ini memutuskan apakah tindakan containment (drain backend) boleh
dijalankan. Keputusan dibuat dari aturan eksplisit di atas bukti, bukan dari
output LLM. LLM hanya bisa menahan aksi otomatis (HOLD), tidak pernah izin.

Semua pengaturan berasal dari environment variable supaya ambang lab dapat
disederhanakan tanpa mengubah kode.
"""

import os
from datetime import datetime, timezone

DECISION_APPROVED = "approved"
DECISION_REJECTED = "rejected"
DECISION_HELD = "held"

CONFIG_VERSION = "policy-gate-v1"


def env_bool(value, default):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class PolicyConfig:
    """Ambang dan pengaman respons. Semua nilai terpusat di sini."""

    def __init__(self, env=None):
        env = env if env is not None else os.environ
        self.name = CONFIG_VERSION
        self.min_risk = float(env.get("POLICY_MIN_RISK", "1.0"))
        self.survivor_required = env_bool(env.get("POLICY_SURVIVOR_REQUIRED"), True)
        self.capacity_probe_required = env_bool(env.get("POLICY_CAPACITY_PROBE_REQUIRED"), True)
        self.cooldown_seconds = max(0, int(float(env.get("POLICY_COOLDOWN_SECONDS", "20"))))
        self.rate_window_seconds = max(1, int(float(env.get("POLICY_RATE_WINDOW_SECONDS", "300"))))
        self.rate_max_actions = max(1, int(float(env.get("POLICY_RATE_MAX_ACTIONS", "2"))))
        self.max_drained_backends = max(1, int(float(env.get("POLICY_MAX_DRAINED", "1"))))
        self.advisory_hold = env_bool(env.get("POLICY_ADVISORY_HOLD"), True)

    def snapshot(self):
        return {
            "name": self.name,
            "min_risk": self.min_risk,
            "survivor_required": self.survivor_required,
            "capacity_probe_required": self.capacity_probe_required,
            "cooldown_seconds": self.cooldown_seconds,
            "rate_window_seconds": self.rate_window_seconds,
            "rate_max_actions": self.rate_max_actions,
            "max_drained_backends": self.max_drained_backends,
            "advisory_hold": self.advisory_hold,
        }


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _reason(check, code, detail):
    return {"check": check, "code": code, "detail": detail, "passed": check is not False}


def evaluate_containment(context, config=None):
    """Evaluasi prasyarat containment atas satu konteks bukti.

    Konteks diharapkan memiliki kunci:
      event            dict event sumber (bisa None bila evidence tidak ada)
      evidence_valid   bool: bukti lulus kriteria implisit (canary terverifikasi)
      risk             float risiko (heuristik, bukan probabilitas model)
      level            int tingkat risiko 0-3
      target           str host sasaran
      survivor         str host survivor
      backend_states   dict host -> status HAProxy (atau 'UNKNOWN')
      survivor_reachable  bool|None: hasil probe layanan langsung ke survivor
      active_drains    list host yang sedang di-drain saat ini
      last_action_seconds_ago  float|None sejak aksi terakhir untuk host target
      recent_action_count      int jumlah aksi aktif dalam jendela rate
      canary_run_in_progress   bool ada remediasi berjalan untuk host target
      advisor_status   "disabled"|"unavailable"|"valid"|...
      advisor_verdict  enum LLM atau None

    Mengembalikan dict keputusan dengan daftar prasyarat lulus/gagal.
    Keadaan tidak diketahui selalu berujung penolakan (fail-safe).
    """
    config = config or PolicyConfig()
    reasons = []
    approved = True
    verdict = context.get("advisor_verdict") or None
    advisor_status = context.get("advisor_status") or "disabled"

    def fail(code, detail):
        nonlocal approved
        approved = False
        reasons.append(_reason(False, code, detail))

    def ok(code, detail):
        reasons.append(_reason(True, code, detail))

    event = context.get("event") or {}
    target = context.get("target")
    survivor = context.get("survivor")
    backend_states = context.get("backend_states") or {}

    if context.get("evidence_valid"):
        ok("EVIDENCE_VALID", "Bukti canary lab lulus kriteria implisit.")
    else:
        fail("EVIDENCE_INSUFFICIENT", "Bukti tidak memenuhi semua kriteria canary.")

    if not target or not context.get("target_allowed"):
        fail("TARGET_NOT_ALLOWED", f"Target '{target}' di luar allowlist lab.")
    else:
        ok("TARGET_ALLOWED", f"Target {target} terdaftar pada allowlist lab.")

    risk = float(context.get("risk") or 0.0)
    if risk >= config.min_risk:
        ok("RISK_ABOVE_THRESHOLD", f"Risiko {risk:.2f} >= ambang {config.min_risk:.2f}.")
    else:
        fail("RISK_BELOW_THRESHOLD", f"Risiko {risk:.2f} < ambang {config.min_risk:.2f}.")

    survivor_state = (backend_states.get(survivor) or "UNKNOWN").upper() if survivor else "UNKNOWN"
    if config.survivor_required:
        if survivor_state.startswith("UP"):
            ok("SURVIVOR_HEALTHY", f"Backend survivor {survivor} berstatus {survivor_state}.")
        elif survivor_state in {"DOWN", "MAINT", "DRAIN", "MAINTENANCE", "STOPPED"} or "DOWN" in survivor_state:
            fail("SURVIVOR_NOT_HEALTHY", f"Backend survivor {survivor} berstatus {survivor_state}.")
        else:
            fail("SURVIVOR_STATE_UNKNOWN", f"Status survivor {survivor} tidak dapat diverifikasi ({survivor_state}).")

    if config.capacity_probe_required:
        reachable = context.get("survivor_reachable")
        if reachable is True:
            ok("SURVIVOR_CAPACITY_VERIFIED", "Probe layanan langsung ke survivor berhasil.")
        elif reachable is None:
            fail("SURVIVOR_CAPACITY_UNVERIFIED", "Probe kapasitas survivor tidak dapat dijalankan.")
        else:
            fail("SURVIVOR_CAPACITY_FAILED", "Probe layanan langsung ke survivor gagal.")

    target_state = (backend_states.get(target) or "UNKNOWN").upper() if target else "UNKNOWN"
    if target_state and target_state != "UNKNOWN":
        ok("TARGET_STATE_KNOWN", f"Status target {target} terbaca: {target_state}.")
    else:
        fail("TARGET_STATE_UNKNOWN", f"Status backend target {target} tidak diketahui.")

    active_drains = context.get("active_drains") or []
    if len(active_drains) < config.max_drained_backends:
        ok("DRAIN_LIMIT_OK", f"Backend ter-drain saat ini: {len(active_drains)}/{config.max_drained_backends}.")
    else:
        fail("DRAIN_LIMIT_REACHED", f"Sudah ada {len(active_drains)} backend di-drain; maksimum {config.max_drained_backends}.")

    if context.get("canary_run_in_progress"):
        fail("ACTION_IN_PROGRESS", "Masih ada playbook remediasi berjalan untuk host target; menolak duplikasi.")
    else:
        ok("NO_RUNNING_ACTION", "Tidak ada playbook berjalan untuk host target.")

    last_age = context.get("last_action_seconds_ago")
    if last_age is None:
        ok("COOLDOWN_CLEAR", "Belum ada catatan aksi pada host target.")
    elif last_age >= config.cooldown_seconds:
        ok("COOLDOWN_CLEAR", f"Aksi terakhir {last_age:.0f}s lalu melewati cooldown {config.cooldown_seconds}s.")
    else:
        fail("COOLDOWN_ACTIVE", f"Aksi terakhir {last_age:.0f}s lalu; cooldown {config.cooldown_seconds}s belum berlalu.")

    recent = int(context.get("recent_action_count") or 0)
    if recent < config.rate_max_actions:
        ok("RATE_LIMIT_OK", f"Aksi dalam jendela {config.rate_window_seconds}s: {recent}/{config.rate_max_actions}.")
    else:
        fail("RATE_LIMIT_REACHED", f"Aksi dalam jendela {config.rate_window_seconds}s sudah {recent}/{config.rate_max_actions}.")

    if config.advisory_hold and verdict in {"benign", "insufficient_evidence"}:
        if advisor_status in {"valid", "completed"}:
            fail("ADVISOR_HOLD", "Verdict penasihat menahan aksi otomatis dan beralih ke operator.")
        else:
            fail("ADVISOR_OUTPUT_INVALID", "Verdict penasihat tidak valid; aksi otomatis ditahan.")
    else:
        ok(
            "ADVISOR_NO_HOLD",
            "Penasihat tidak menahan keputusan."
            if advisor_status not in {"disabled"}
            else "Penasihat nonaktif; jalur deterministik canary yang berlaku.",
        )

    decision = DECISION_APPROVED if approved else DECISION_REJECTED
    failed_codes = [reason["code"] for reason in reasons if not reason["passed"]]
    if not approved and failed_codes and all(code.startswith("ADVISOR") for code in failed_codes):
        # Hanya penasihat AI yang menahan; prasyarat deterministik semua lulus.
        decision = DECISION_HELD
    return {
        "decision": decision,
        "reasons": reasons,
        "failed_codes": failed_codes,
        "config": config.snapshot(),
        "decided_at": utc_now_iso(),
    }
