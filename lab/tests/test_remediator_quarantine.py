"""Unit test isolasi quarantine remediator tanpa container."""

import hashlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import remediator


class TestQuarantine(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        target = Path(self.tmp.name) / "target"
        quarantine = Path(self.tmp.name) / "quarantine"
        target.mkdir()
        quarantine.mkdir()
        self._original = (remediator.TARGET, remediator.QUARANTINE, remediator.CANARY_NAME)
        remediator.TARGET = target
        remediator.QUARANTINE = quarantine
        self.target = target
        self.quarantine = quarantine

    def tearDown(self):
        remediator.TARGET, remediator.QUARANTINE, remediator.CANARY_NAME = self._original
        self.tmp.cleanup()

    def write_canary(self, content=remediator.CANARY, name=remediator.CANARY_NAME):
        path = self.target / name
        path.write_bytes(content)
        return path

    def test_valid_canary_quarantined(self):
        self.write_canary()
        result = remediator.quarantine_canary()
        self.assertEqual(result["status"], "QUARANTINED_CANARY")
        self.assertFalse((self.target / remediator.CANARY_NAME).exists())
        archived = [entry for entry in self.quarantine.rglob("*") if entry.is_file()]
        self.assertEqual(len(archived), 1)
        self.assertTrue(archived[0].name.endswith(remediator.CANARY_NAME))

    def test_missing_canary_rejected(self):
        with self.assertRaises(ValueError) as context:
            remediator.quarantine_canary()
        self.assertEqual(str(context.exception), "canary_file_missing")

    def test_wrong_content_rejected(self):
        self.write_canary(content=b"benign note without marker")
        with self.assertRaises(ValueError):
            remediator.quarantine_canary()
        self.assertTrue((self.target / remediator.CANARY_NAME).exists())

    def test_oversized_rejected(self):
        self.write_canary(remediator.CANARY + b"\x00" * (remediator.MAX_FILE_SIZE + 1))
        with self.assertRaises(ValueError):
            remediator.quarantine_canary()
        self.assertTrue((self.target / remediator.CANARY_NAME).exists())

    def test_symlink_rejected(self):
        source = self.target / remediator.CANARY_NAME
        outside = Path(self.tmp.name) / "outside.txt"
        outside.write_bytes(remediator.CANARY)
        source.symlink_to(outside)
        with self.assertRaises(ValueError):
            remediator.quarantine_canary()
        self.assertTrue(source.is_symlink())

    def test_sha256_reported_matches_content(self):
        self.write_canary()
        result = remediator.quarantine_canary()
        expected = hashlib.sha256(remediator.CANARY).hexdigest()
        self.assertEqual(result["sha256"], expected)


if __name__ == "__main__":
    unittest.main()
