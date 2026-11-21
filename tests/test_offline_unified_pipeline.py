import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import run_offline_unified_pipeline as pipeline


class OfflinePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pcap = self.root / "input.pcap"
        self.config = self.root / "suricata.yaml"
        self.rules = self.root / "rules.txt"
        self.pcap.write_bytes(b"test capture bytes")
        self.config.write_text("config", encoding="utf-8")
        self.rules.write_text("rules", encoding="utf-8")
        self.output = self.root / "run"

    def mock_commands(self, command, cwd=None):
        command = [str(value) for value in command]
        if command[0] == "/fake/zeek" and "--version" in command:
            return "zeek version 8.test"
        if command[0] == "/fake/suricata" and "--build-info" in command:
            return "This is Suricata version 8.test"
        if command[0] == "/fake/zeek":
            self.assertEqual(Path(command[command.index("-r") + 1]), self.pcap.resolve())
            return ""
        if command[0] == "/fake/suricata":
            self.assertEqual(Path(command[command.index("-r") + 1]), self.pcap.resolve())
            out = Path(command[command.index("-l") + 1])
            (out / "eve.json").write_text("", encoding="utf-8")
            return ""
        if "detect_network_anomalies.py" in command[1]:
            out = Path(command[command.index("--out") + 1])
            out.mkdir()
            (out / "alerts.json").write_text(json.dumps({
                "tool": "offline-zeek-detection-engine", "input_counts": {"conn": 2},
                "alert_count": 0, "alerts": [],
            }), encoding="utf-8")
            (out / "alerts.csv").write_text("rule_id\n", encoding="utf-8")
            return ""
        if "parse_suricata_eve.py" in command[1]:
            out = Path(command[command.index("--out") + 1])
            out.mkdir()
            (out / "alerts.json").write_text(json.dumps({
                "tool": "suricata-eve-adapter", "event_counts": {"alert": 0},
                "malformed_lines": 0, "invalid_shape_records": 0,
                "invalid_optional_fields": 0, "alert_count": 0, "alerts": [],
            }), encoding="utf-8")
            (out / "alerts.csv").write_text("rule_id\n", encoding="utf-8")
            return ""
        if "merge_detection_alerts.py" in command[1]:
            out = Path(command[command.index("--out") + 1])
            out.mkdir()
            (out / "alerts.json").write_text(json.dumps({
                "tool": "unified-network-detection", "alert_count": 0, "alerts": [],
                "source_metadata": {"zeek": {}, "suricata": {}},
            }), encoding="utf-8")
            (out / "alerts.csv").write_text("source_tool,rule_id\n", encoding="utf-8")
            return ""
        self.fail(f"Unexpected command: {command}")

    def test_orchestrates_both_engines_adapters_and_merge_with_manifest(self):
        with (patch.object(pipeline.shutil, "which", side_effect=lambda name: f"/fake/{name}"),
              patch.object(pipeline, "run", side_effect=self.mock_commands)):
            manifest = pipeline.run_pipeline(self.pcap, self.output, "zeek", "suricata",
                                             self.config, self.rules)
        saved = json.loads((self.output / "run_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "complete")
        self.assertEqual(saved["pcap"]["sha256"], hashlib.sha256(self.pcap.read_bytes()).hexdigest())
        self.assertEqual(saved["tools"]["zeek"], "zeek version 8.test")
        self.assertIn("started_at_utc", saved)
        self.assertIn("finished_at_utc", saved)
        self.assertEqual(saved["alert_counts"], {"zeek": 0, "suricata": 0, "unified": 0})
        for key in ("zeek_alerts_json", "zeek_alerts_csv", "suricata_alerts_json",
                    "suricata_alerts_csv", "unified_json", "unified_csv"):
            artifact = saved["artifacts"][key]
            artifact_path = Path(artifact["path"])
            self.assertEqual(artifact["sha256"], hashlib.sha256(artifact_path.read_bytes()).hexdigest())
            self.assertEqual(artifact["size_bytes"], artifact_path.stat().st_size)
        self.assertTrue((self.output / "unified/alerts.json").is_file())
        self.assertTrue((self.output / "unified/alerts.csv").is_file())

    def test_failed_engine_run_records_failure_manifest_and_stops_pipeline(self):
        def fail_zeek(command, cwd=None):
            if command[0] == "/fake/zeek" and "--version" in command:
                return "zeek version 8.test"
            if command[0] == "/fake/suricata" and "--build-info" in command:
                return "This is Suricata version 8.test"
            raise RuntimeError("mock Zeek failure")

        with (patch.object(pipeline.shutil, "which", side_effect=lambda name: f"/fake/{name}"),
              patch.object(pipeline, "run", side_effect=fail_zeek)):
            with self.assertRaisesRegex(RuntimeError, "mock Zeek failure"):
                pipeline.run_pipeline(self.pcap, self.output, "zeek", "suricata",
                                      self.config, self.rules)
        saved = json.loads((self.output / "run_manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "failed")
        self.assertIn("mock Zeek failure", saved["error"])
        self.assertFalse((self.output / "unified/alerts.json").exists())

    def test_nonempty_output_is_refused_without_overwriting_existing_file(self):
        self.output.mkdir()
        marker = self.output / "keep.txt"
        marker.write_text("preserve", encoding="utf-8")
        with patch.object(pipeline.shutil, "which", side_effect=lambda name: f"/fake/{name}"):
            with self.assertRaisesRegex(ValueError, "Refusing to use non-empty output path"):
                pipeline.run_pipeline(self.pcap, self.output, suricata_config=self.config,
                                     suricata_rules=self.rules)
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_missing_zeek_is_reported_before_output_creation(self):
        with patch.object(pipeline.shutil, "which", side_effect=lambda name: None if name == "zeek" else "/fake/suricata"):
            with self.assertRaisesRegex(ValueError, "zeek"):
                pipeline.run_pipeline(self.pcap, self.output, suricata_config=self.config,
                                      suricata_rules=self.rules)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
