import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.merge_detection_alerts import load_payload, merge_alerts
from scripts.parse_suricata_eve import main as suricata_main


class SuricataShapeValidationTests(unittest.TestCase):
    def make_event(self):
        return {
            "event_type": "alert",
            "timestamp": "2026-11-16T20:00:00Z",
            "src_ip": "10.0.0.5",
            "dest_ip": "192.0.2.10",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature_id": 12,
                "signature": "Test signature",
                "severity": 2,
                "metadata": {"confidence": ["High"]},
            },
        }

    def run_adapter(self, records):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        eve = root / "eve.json"
        output = root / "out"
        eve.write_text("\n".join(records) + "\n", encoding="utf-8")
        with patch("sys.argv", ["parse_suricata_eve", "--eve", str(eve), "--out", str(output)]):
            suricata_main()
        return json.loads((output / "alerts.json").read_text(encoding="utf-8"))

    def test_non_object_json_records_are_counted_and_skipped(self):
        payload = self.run_adapter([
            "[]", "null", '"a string"', json.dumps(self.make_event())
        ])
        self.assertEqual(payload["invalid_shape_records"], 3)
        self.assertEqual(payload["malformed_lines"], 0)
        self.assertEqual(payload["alert_count"], 1)

    def test_invalid_core_alert_is_counted_and_skipped(self):
        event = self.make_event()
        event["alert"] = []
        payload = self.run_adapter([json.dumps(event), json.dumps(self.make_event())])
        self.assertEqual(payload["invalid_shape_records"], 1)
        self.assertEqual(payload["alert_count"], 1)

    def test_missing_null_and_invalid_signature_ids_are_counted_once(self):
        records = []
        for identifier in (None, "12", [], True):
            event = self.make_event()
            if identifier is None:
                event["alert"].pop("signature_id")
            else:
                event["alert"]["signature_id"] = identifier
            event["http"] = []
            records.append(json.dumps(event))
        payload = self.run_adapter(records + [json.dumps(self.make_event())])
        self.assertEqual(payload["invalid_shape_records"], 4)
        self.assertEqual(payload["invalid_optional_fields"], 0)
        self.assertEqual(payload["alert_count"], 1)

    def test_invalid_http_field_does_not_discard_alert(self):
        event = self.make_event()
        event["http"] = []
        payload = self.run_adapter([json.dumps(event)])
        self.assertEqual(payload["alert_count"], 1)
        self.assertEqual(payload["invalid_optional_fields"], 1)
        evidence = json.loads(payload["alerts"][0]["evidence"])
        self.assertEqual(evidence["signature_id"], 12)
        self.assertEqual(evidence["hostname"], "")

    def test_invalid_flow_field_does_not_discard_alert(self):
        event = self.make_event()
        event["flow"] = "invalid"
        payload = self.run_adapter([json.dumps(event)])
        self.assertEqual(payload["alert_count"], 1)
        self.assertEqual(payload["invalid_optional_fields"], 1)
        evidence = json.loads(payload["alerts"][0]["evidence"])
        self.assertIsNone(evidence["flow_bytes_toserver"])

    def test_invalid_metadata_field_does_not_discard_alert(self):
        event = self.make_event()
        event["alert"]["metadata"] = []
        payload = self.run_adapter([json.dumps(event)])
        self.assertEqual(payload["alert_count"], 1)
        self.assertEqual(payload["invalid_optional_fields"], 1)
        self.assertEqual(payload["alerts"][0]["confidence"], "unknown")

    def test_multiple_invalid_optional_fields_preserve_alert_and_valid_evidence(self):
        event = self.make_event()
        event["http"] = []
        event["flow"] = "invalid"
        event["alert"]["metadata"] = []
        event["proto"] = "TCP"
        payload = self.run_adapter([json.dumps(event)])
        self.assertEqual(payload["alert_count"], 1)
        self.assertEqual(payload["invalid_optional_fields"], 3)
        evidence = json.loads(payload["alerts"][0]["evidence"])
        self.assertEqual(evidence["signature_id"], 12)
        self.assertEqual(evidence["protocol"], "TCP")
        self.assertEqual(evidence["hostname"], "")
        self.assertIsNone(evidence["flow_bytes_toserver"])

    def test_valid_optional_evidence_survives_another_invalid_optional_field(self):
        event = self.make_event()
        event["http"] = {"hostname": "example.test", "url": "/path"}
        event["flow"] = {"bytes_toserver": 456}
        event["alert"]["metadata"] = []
        payload = self.run_adapter([json.dumps(event)])
        self.assertEqual(payload["alert_count"], 1)
        evidence = json.loads(payload["alerts"][0]["evidence"])
        self.assertEqual(evidence["hostname"], "example.test")
        self.assertEqual(evidence["http_url"], "/path")
        self.assertEqual(evidence["flow_bytes_toserver"], 456)

    def test_malformed_scalar_optional_fields_do_not_discard_alert(self):
        event = self.make_event()
        event["timestamp"] = 123
        event["src_ip"] = {"unexpected": "object"}
        event["dest_port"] = [443]
        event["proto"] = ["TCP"]
        event["alert"]["signature"] = {"unexpected": "object"}
        event["alert"]["severity"] = []
        payload = self.run_adapter([json.dumps(event)])
        self.assertEqual(payload["alert_count"], 1)
        self.assertEqual(payload["invalid_optional_fields"], 6)
        alert = payload["alerts"][0]
        self.assertEqual(alert["title"], "Suricata SID 12")
        self.assertEqual(alert["timestamp_utc"], "")
        self.assertEqual(alert["src_ip"], "")
        self.assertIsNone(alert["dst_port"])
        self.assertEqual(alert["severity"], "unknown")

    def test_malformed_json_followed_by_valid_record_continues(self):
        payload = self.run_adapter(["{bad json", json.dumps(self.make_event())])
        self.assertEqual(payload["malformed_lines"], 1)
        self.assertEqual(payload["invalid_shape_records"], 0)
        self.assertEqual(payload["alert_count"], 1)


class MergerValidationTests(unittest.TestCase):
    def valid_payload(self, tool="offline-zeek-detection-engine"):
        return {
            "tool": tool,
            "alerts": [{
                "timestamp_utc": "2026-11-16T20:00:00+00:00",
                "rule_id": "NET-001",
                "severity": "high",
                "confidence": "medium",
                "title": "Test alert",
                "src_ip": "10.0.0.5",
                "dst_ip": "192.0.2.10",
                "dst_port": "443",
                "uid": "C1",
                "evidence": "sample evidence",
            }],
        }

    def load_temp_payload(self, payload, expected="Zeek"):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        path = Path(temp.name) / "alerts.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return load_payload(path, expected)

    def test_wrong_or_missing_source_tool_is_rejected(self):
        for tool in ("suricata-eve-adapter", None):
            payload = self.valid_payload(tool)
            with self.subTest(tool=tool), self.assertRaisesRegex(ValueError, "source tool"):
                self.load_temp_payload(payload)

    def test_missing_required_field_is_rejected(self):
        payload = self.valid_payload()
        del payload["alerts"][0]["evidence"]
        with self.assertRaisesRegex(ValueError, "missing required field 'evidence'"):
            self.load_temp_payload(payload)

    def test_invalid_required_field_type_is_rejected(self):
        payload = self.valid_payload()
        payload["alerts"][0]["timestamp_utc"] = 123
        with self.assertRaisesRegex(ValueError, "field 'timestamp_utc' has an invalid type"):
            self.load_temp_payload(payload)

    def test_invalid_severity_and_confidence_are_rejected(self):
        for field, value in (("severity", "critical"), ("confidence", "certain")):
            payload = self.valid_payload()
            payload["alerts"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                self.load_temp_payload(payload)

    def test_valid_zeek_and_suricata_payloads_merge(self):
        zeek_payload = self.valid_payload()
        suricata_payload = self.valid_payload("suricata-eve-adapter")
        _, zeek_alerts = self.load_temp_payload(zeek_payload, "Zeek")
        _, suricata_alerts = self.load_temp_payload(suricata_payload, "Suricata")
        merged = merge_alerts(zeek_alerts, suricata_alerts)
        self.assertEqual([alert["source_tool"] for alert in merged], ["Suricata", "Zeek"])
        self.assertEqual(len(merged), 2)


if __name__ == "__main__":
    unittest.main()
