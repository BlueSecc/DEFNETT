"""Policy Gate: penentu keputusan tunggal dan deterministik.

Modul ini murni: menerima event bukti dan angka risiko, mengembalikan kategori
keputusan dan tindakan yang diminta. Ia TIDAK pernah menjalankan apa pun dan
tidak membuka jaringan. Satu-satunya yang boleh meminta eksekusi adalah
persetujuan operator (operator_approvals) yang diklaim executor.
"""
from pathlib import Path

KEY_PATHS = ("etc/kunci1.dat", "etc/kunci2.dat")

CATEGORY_INFORMATIONAL = "INFORMATIONAL"
CATEGORY_INVESTIGATE = "INVESTIGATE"
CATEGORY_WARNING = "WARNING"
CATEGORY_PENDING_APPROVAL = "PENDING_APPROVAL"

RULE_CANARY_MATCH = "rule:canary_match"
RULE_KEY_MATCH = "rule:key_match"
RULE_RESTORE_CONFIRMED = "rule:restore_hash_same_as_recorded"
RULE_OPERATOR_REVIEW = "rule:risk_above_operator_threshold"
RULE_ALERT = "rule:risk_above_alert_threshold"
RULE_RECORD = "rule:record_only"
RULE_APPROVAL_REQUIRED = "policy:operator_approval_required"
DEFAULT_ACTION = "none"
CONTAINMENT_ACTIONS = {"CONTAIN_CANARY", "RESTORE_KEYS"}


def is_canary_detection(event):
    return (
        event.get("content_signal") is True
        and event.get("indicator") == "DEFNETT_LAB_CANARY"
        and Path(event.get("path", "")).name == "DEFNETT-LAB-CANARY.txt"
        and event.get("event_type") in {"file_created", "file_modified"}
        and event.get("new_hash") is not None
    )


def is_key_detection(event):
    return (
        str(event.get("path", "")).lstrip("/") in KEY_PATHS
        and event.get("event_type") == "file_modified"
        and event.get("new_hash") is not None
    )


def decide(event, p_attack, risk, level, recommendation, restored_hashes=None):
    """Terjemahkan satu event menjadi keputusan kategori + tindakan.

    restored_hashes: pemetaan (host_id, jalur) -> sha256 yang sudah
    dipulihkan executor; event ile modifier dengan hash sama dianggap
    konfirmasi pemulihan, bukan ancaman ulang.
    """
    event_type = event.get("event_type")
    if is_canary_detection(event):
        return {
            "category": CATEGORY_PENDING_APPROVAL,
            "action": "CONTAIN_CANARY",
            "reasons": [RULE_CANARY_MATCH, RULE_APPROVAL_REQUIRED],
            "parameters": {"artifact": "canary", "event_type": event_type},
        }
    if is_key_detection(event):
        restored = restored_hashes or {}
        restored_hash = restored.get((event.get("host_id"), str(event.get("path", "")).lstrip("/")))
        if restored_hash and restored_hash == event.get("new_hash"):
            return {
                "category": CATEGORY_INFORMATIONAL,
                "action": DEFAULT_ACTION,
                "reasons": [RULE_RESTORE_CONFIRMED],
                "parameters": {"artifact": "kunci", "event_type": event_type},
            }
        return {
            "category": CATEGORY_PENDING_APPROVAL,
            "action": "RESTORE_KEYS",
            "reasons": [RULE_KEY_MATCH, RULE_APPROVAL_REQUIRED],
            "parameters": {"artifact": "kunci", "event_type": event_type},
        }
    if level >= 2:
        return {
            "category": CATEGORY_WARNING,
            "action": DEFAULT_ACTION,
            "reasons": [RULE_OPERATOR_REVIEW, f"rule:{recommendation}"],
            "parameters": {"artifact": None, "event_type": event_type},
        }
    if level >= 1:
        return {
            "category": CATEGORY_INVESTIGATE,
            "action": DEFAULT_ACTION,
            "reasons": [RULE_ALERT, f"rule:{recommendation}"],
            "parameters": {"artifact": None, "event_type": event_type},
        }
    return {
        "category": CATEGORY_INFORMATIONAL,
        "action": DEFAULT_ACTION,
        "reasons": [RULE_RECORD, f"rule:{recommendation}"],
        "parameters": {"artifact": None, "event_type": event_type},
    }
