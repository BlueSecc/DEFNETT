"""Unit test validator LLM advisor (advisory-only, tidak pernah mengizinkan)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import llm_advisor as advisor


def valid_payload():
    return {
        "schema_version": "advisor-response-v1",
        "verdict": "benign",
        "reason_codes": ["CANARY_EVIDENCE"],
        "evidence_ids": ["event-1"],
        "summary": "Canary lab; tidak ada gejala ganda.",
    }


class TestValidResponse(unittest.TestCase):
    def test_valid_payload_accepted(self):
        ok, errors = advisor._valid_response(valid_payload(), {"event-1"})
        self.assertTrue(ok, errors)

    def test_invalid_verdict_rejected(self):
        payload = valid_payload()
        payload["verdict"] = "secretly_fine"
        ok, errors = advisor._valid_response(payload, {"event-1"})
        self.assertFalse(ok)
        self.assertIn("invalid_verdict", errors)

    def test_unknown_reason_code_rejected(self):
        payload = valid_payload()
        payload["reason_codes"] = ["ANSWER_WITH_EVERYTHING"]
        ok, errors = advisor._valid_response(payload, {"event-1"})
        self.assertFalse(ok)
        self.assertIn("invalid_reason_codes", errors)

    def test_unknown_evidence_reference_rejected(self):
        payload = valid_payload()
        payload["evidence_ids"] = ["event-other"]
        ok, errors = advisor._valid_response(payload, {"event-1"})
        self.assertFalse(ok)
        self.assertTrue(any(code.startswith("unknown_evidence_id") for code in errors))

    def test_missing_evidence_rejected(self):
        payload = valid_payload()
        payload["evidence_ids"] = []
        ok, _ = advisor._valid_response(payload, {"event-1"})
        self.assertFalse(ok)

    def test_oversized_summary_rejected(self):
        payload = valid_payload()
        payload["summary"] = "x" * (advisor.MAX_SUMMARY_LENGTH + 1)
        ok, errors = advisor._valid_response(payload, {"event-1"})
        self.assertFalse(ok)
        self.assertIn("invalid_summary", errors)

    def test_non_object_rejected(self):
        ok, errors = advisor._valid_response("benign please", {"event-1"})
        self.assertFalse(ok)
        self.assertEqual(errors, ["response_not_object"])


class TestSanitizePayload(unittest.TestCase):
    def test_only_expected_fields(self):
        sanitized = advisor.sanitize_payload({
            "host_id": "server-a",
            "event_type": "file_modified",
            "path": "DEFNETT-LAB-CANARY.txt",
            "new_hash": "bbb",
            "old_hash": "aaa",
            "canary_signal": True,
            "risk": 1.98,
            "level": 3,
            "content": "isi file rahasia tidak boleh keluar",
        })
        self.assertEqual(
            set(sanitized.keys()),
            {"host_id", "event_type", "path", "hash_changed", "canary_signal", "risk", "level"},
        )
        self.assertTrue(sanitized["hash_changed"])
        self.assertTrue(sanitized["canary_signal"])
        self.assertNotIn("content", sanitized)

    def test_control_characters_replaced(self):
        sanitized = advisor.sanitize_payload({"path": "bad\x00path"})
        self.assertEqual(sanitized["path"], "bad?path")


class TestAdvise(unittest.TestCase):
    def test_off_mode_disabled(self):
        config = advisor.AdviserConfig({"LLM_MODE": "off"})
        result = advisor.advise({}, config=config, evidence_ids=["event-1"])
        self.assertEqual(result["status"], "disabled")
        self.assertIsNone(result["model_used"])

    def test_auto_without_urls_disabled(self):
        config = advisor.AdviserConfig({"LLM_MODE": "auto"})
        result = advisor.advise({}, config=config, evidence_ids=["event-1"])
        self.assertEqual(result["status"], "disabled")

    def test_cloud_valid_response(self):
        config = advisor.AdviserConfig({"LLM_MODE": "cloud", "LLM_CLOUD_URL": "http://example.invalid/v1/chat"})

        def fetch(url, model, payload, timeout):
            assert url == "http://example.invalid/v1/chat"
            return {"choices": [{"message": {"content": __import__("json").dumps(valid_payload())}}]}

        result = advisor.advise({}, config=config, evidence_ids=["event-1"], fetch=fetch)
        self.assertEqual(result["status"], "valid")
        self.assertEqual(result["verdict"], "benign")
        self.assertEqual(result["model_used"], "cloud")

    def test_no_provider_configured(self):
        config = advisor.AdviserConfig({"LLM_MODE": "cloud"})
        result = advisor.advise({}, config=config, evidence_ids=["event-1"])
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("no_provider_configured", result["errors"])

    def test_provider_failure_unavailable(self):
        config = advisor.AdviserConfig({"LLM_MODE": "cloud", "LLM_CLOUD_URL": "http://example.invalid/v1/chat"})

        def fetch(url, model, payload, timeout):
            raise TimeoutError("hung")

        result = advisor.advise({}, config=config, evidence_ids=["event-1"], fetch=fetch)
        self.assertEqual(result["status"], "unavailable")
        self.assertIn("cloud:TimeoutError", result["errors"])


if __name__ == "__main__":
    unittest.main()
