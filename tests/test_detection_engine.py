import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detect_network_anomalies import detect  # noqa: E402
from build_incident_report import alert_range, range_gap_seconds  # noqa: E402


class DetectorCorrelationTests(unittest.TestCase):
    def test_multiple_http_requests_on_one_uid_correlate_the_exact_executable_fuid(self):
        http_rows = [
            {
                "ts": 1000.0, "uid": "U1", "id.orig_h": "10.0.0.5",
                "id.resp_h": "203.0.113.10", "id.resp_p": 80,
                "method": "GET", "uri": "/index.html", "status_code": 200,
                "resp_mime_types": "text/html", "user_agent": "test-agent",
                "resp_fuids": "F0",
            },
            {
                "ts": 1001.0, "uid": "U1", "id.orig_h": "10.0.0.5",
                "id.resp_h": "203.0.113.10", "id.resp_p": 80,
                "method": "GET", "uri": "/runner.exe", "status_code": 200,
                "resp_mime_types": "application/x-dosexec", "user_agent": "test-agent",
                "resp_fuids": "F1",
            },
        ]
        file_rows = [
            {
                "ts": 1001.1, "uid": "U1", "fuid": "F1",
                "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.10",
                "id.resp_p": 80, "filename": "runner.exe",
                "mime_type": "application/x-dosexec", "analyzers": "PE",
                "seen_bytes": 1234, "total_bytes": 1234,
            },
            {
                "ts": 1002.0, "uid": "U2", "fuid": "F2",
                "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.11",
                "id.resp_p": 80, "filename": "other.exe",
                "mime_type": "application/x-dosexec", "analyzers": "PE",
                "seen_bytes": 555, "total_bytes": 555,
            },
        ]

        alerts = detect(http_rows, [], [], file_rows)
        downloads = [a for a in alerts if a["rule_id"] == "NET-001"]
        standalone_files = [a for a in alerts if a["rule_id"] == "NET-006"]

        self.assertEqual(len(downloads), 1)
        self.assertEqual(downloads[0]["correlation"], "matched_http_uid_and_response_fuid_and_files_uid")
        self.assertEqual(downloads[0]["related_fuid"], "F1")
        self.assertEqual(downloads[0]["related_uid"], "U1")
        self.assertEqual(len(standalone_files), 1)
        self.assertEqual(standalone_files[0]["uid"], "U2")
        self.assertEqual(standalone_files[0]["fuid"], "F2")

    def test_same_fuid_with_different_files_uid_does_not_correlate_or_suppress(self):
        http_rows = [{
            "ts": 1000.0, "uid": "U1", "id.orig_h": "10.0.0.5",
            "id.resp_h": "203.0.113.10", "id.resp_p": 80,
            "method": "GET", "uri": "/runner.exe", "status_code": 200,
            "resp_mime_types": "application/x-dosexec", "user_agent": "test-agent",
            "resp_fuids": "F1",
        }]
        file_rows = [{
            "ts": 1001.0, "uid": "U2", "fuid": "F1",
            "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.10",
            "id.resp_p": 80, "filename": "runner.exe",
            "mime_type": "application/x-dosexec", "analyzers": "PE",
            "seen_bytes": 1234, "total_bytes": 1234,
        }]
        alerts = detect(http_rows, [], [], file_rows)
        download = next(a for a in alerts if a["rule_id"] == "NET-001")
        standalone = [a for a in alerts if a["rule_id"] == "NET-006"]
        self.assertNotIn("correlation", download)
        self.assertEqual(len(standalone), 1)
        self.assertEqual(standalone[0]["uid"], "U2")

    def test_aggregate_alerts_include_first_and_last_times(self):
        http_rows = []
        for i in range(5):
            http_rows.append({
                "ts": 1000.0 + i, "uid": f"U{i}", "id.orig_h": "10.0.0.5",
                "id.resp_h": "203.0.113.10", "id.resp_p": 80,
                "method": "POST", "host": "example.test", "uri": "/submit",
                "request_body_len": 25000, "status_code": 200,
            })
        alerts = detect(http_rows, [], [], [])
        post = next(a for a in alerts if a["rule_id"] == "NET-002")
        self.assertEqual(post["timestamp_utc"], post["first_seen_utc"])
        self.assertEqual(post["last_seen_utc"], "1970-01-01T00:16:44+00:00")


class IncidentReportRangeTests(unittest.TestCase):
    def test_aggregate_ranges_overlap_without_claiming_event_level_linkage(self):
        post = {
            "first_seen_utc": "2026-10-01T12:00:00+00:00",
            "last_seen_utc": "2026-10-01T12:00:20+00:00",
        }
        periodic = {
            "first_seen_utc": "2026-10-01T12:00:18+00:00",
            "last_seen_utc": "2026-10-01T12:01:00+00:00",
        }
        self.assertEqual(range_gap_seconds(alert_range(post), alert_range(periodic)), 0.0)

    def test_old_aggregate_alert_without_explicit_range_is_not_treated_as_a_range(self):
        self.assertIsNone(alert_range({"timestamp_utc": "2026-10-01T12:00:00+00:00"}))


if __name__ == "__main__":
    unittest.main()
