
import json
import unittest

from scripts.parse_suricata_eve import convert_event


class TestSuricataAdapter(unittest.TestCase):

    def make_event(self, severity=2, signature_severity="Informational"):
        return {
            "event_type": "alert",
            "timestamp": "2026-11-16T20:00:00+02:00",
            "src_ip": "10.0.0.5",
            "dest_ip": "192.0.2.10",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature_id": 2031071,
                "signature": "Test Suricata Alert",
                "severity": severity,
                "metadata": {
                    "signature_severity": signature_severity,
                    "confidence": ["High"]
                }
            }
        }

    def test_numeric_severity_mapping(self):
        expected = {1: "high", 2: "medium", 3: "low"}

        for raw, result in expected.items():
            with self.subTest(raw_severity=raw):
                alert = convert_event(self.make_event(raw))
                self.assertEqual(alert["severity"], result)

    def test_signature_severity_is_preserved_separately(self):
        alert = convert_event(self.make_event(2, "Informational"))
        evidence = json.loads(alert["evidence"])

        self.assertEqual(alert["severity"], "medium")
        self.assertEqual(evidence["signature_severity"], "informational")
        self.assertEqual(evidence["suricata_priority"], 2)

    def test_missing_signature_id_is_ignored(self):
        event = self.make_event()
        event["alert"].pop("signature_id")

        self.assertIsNone(convert_event(event))

    def test_alert_fields_are_mapped(self):
        alert = convert_event(self.make_event())

        self.assertEqual(alert["rule_id"], "SURICATA-2031071")
        self.assertEqual(alert["src_ip"], "10.0.0.5")
        self.assertEqual(alert["dst_ip"], "192.0.2.10")
        self.assertEqual(alert["dst_port"], 443)
        self.assertEqual(alert["confidence"], "high")


if __name__ == "__main__":
    unittest.main()

