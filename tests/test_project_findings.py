import sys
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from detect_project_findings import _rows, detect_findings, prepare_output_dir, validate_ioc_document  # noqa: E402
from merge_detection_alerts import merge_alerts  # noqa: E402


class ProjectFindingTests(unittest.TestCase):
    def test_detection_coverage_outputs_evidence_linked_custom_findings(self):
        dns = [{"ts": 1000 + i, "uid": f"D{i}", "id.orig_h": "10.0.0.2",
                "query": f"label{i:02d}.example.test"} for i in range(12)]
        conn = [{"ts": 2000 + i, "uid": f"C{i}", "id.orig_h": "10.0.0.3",
                 "id.resp_h": "10.0.0.4", "id.resp_p": 1000 + i, "proto": "tcp"}
                for i in range(24)]
        http = [{"ts": 3000, "uid": "DOWNLOAD", "id.orig_h": "10.0.0.5",
                 "id.resp_h": "203.0.113.7", "id.resp_p": 80, "status_code": 200,
                 "uri": "/sample.exe", "resp_mime_types": "application/x-dosexec", "resp_fuids": "F1"}]
        files = [{"ts": 3001, "uid": "DOWNLOAD", "fuid": "F1", "id.orig_h": "10.0.0.5",
                  "id.resp_h": "203.0.113.7", "sha256": "a" * 64, "filename": "sample.exe"}]
        follow = {"ts": 3100, "uid": "FOLLOW", "id.orig_h": "10.0.0.5",
                  "id.resp_h": "198.51.100.8", "id.resp_p": 443, "proto": "tcp"}
        logs = {
            "dns": dns, "conn": conn + [follow], "http": http, "files": files,
            "smb_mapping": [{"ts": 4000, "uid": "SMB1", "id.orig_h": "10.0.0.9",
                             "id.resp_h": "10.0.0.10", "path": "\\\\host\\ADMIN$"}],
            "dce_rpc": [{"ts": 4001, "uid": "RPC1", "id.orig_h": "10.0.0.9",
                          "id.resp_h": "10.0.0.10", "operation": "NetrShareEnum"}],
            "smb_files": [{"ts": 4002, "uid": "FILE1", "id.orig_h": "10.0.0.9",
                           "id.resp_h": "10.0.0.10", "path": "\\\\host\\ADMIN$",
                           "action": "SMB::FILE_OPEN", "name": "sample.bin", "size": 96}],
            "ssl": [{"ts": 5000, "uid": "TLS1", "id.orig_h": "10.0.0.11",
                     "id.resp_h": "203.0.113.9", "server_name": "example.test",
                     "sni_matches_cert": "F", "version": "TLSv12"}],
        }
        iocs = validate_ioc_document({
            "schema_version": "1.0", "provider": "Test Intel",
            "source_reference": "https://intel.example/indicators", "retrieved_at_utc": "2026-11-22T12:00:00Z",
            "indicators": [{"type": "domain", "value": "example.test"}],
        })
        findings = detect_findings(logs, iocs)
        self.assertEqual(findings, detect_findings(logs, iocs))
        by_rule = {}
        for finding in findings:
            by_rule.setdefault(finding["rule_id"], []).append(finding)
        self.assertEqual(set(by_rule), {"NET-007", "NET-008", "NET-009", "NET-010", "NET-011", "NET-012"})
        for rule in ("NET-007", "NET-008", "NET-009", "NET-010", "NET-011", "NET-012"):
            self.assertEqual(len(by_rule[rule]), 1)
        for finding in findings:
            schema = json.loads((ROOT / "schemas/project_findings.schema.json").read_text())
            Draft202012Validator(schema).validate(finding)
            self.assertEqual(finding["alert_origin"], "project_generated")
            self.assertEqual(finding["source_tool"], "ProjectDetector")
            self.assertTrue(finding["evidence_refs"])
        self.assertEqual(by_rule["NET-012"][0]["related_events"][0]["uid"], "FOLLOW")
        self.assertIn("a" * 64, by_rule["NET-012"][0]["evidence"])
        self.assertIn("sample.bin", by_rule["NET-009"][0]["evidence"])

    def test_ioc_hash_requires_exact_hexadecimal_length(self):
        document = {"schema_version": "1.0", "provider": "source",
                    "source_reference": "https://example.test/iocs", "retrieved_at_utc": "2026-11-22T00:00:00Z",
                    "indicators": [{"type": "sha256", "value": "not-a-hash"}]}
        with self.assertRaisesRegex(ValueError, "sha256"):
            validate_ioc_document(document)

    def test_ioc_document_schema_and_parser_preserve_attribution(self):
        document = {"schema_version": "1.0", "provider": "Test Intel",
                    "source_reference": "https://intel.example/indicators",
                    "retrieved_at_utc": "2026-11-22T12:00:00Z",
                    "indicators": [{"type": "ip", "value": "203.0.113.9"}]}
        schema = json.loads((ROOT / "schemas/project_iocs.schema.json").read_text())
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(document)
        parsed = validate_ioc_document(document)
        self.assertEqual(parsed[0]["provider"], "Test Intel")
        self.assertEqual(parsed[0]["source_reference"], document["source_reference"])

    def test_url_ioc_match_uses_host_path_and_tls_context_exactly(self):
        document = {"schema_version": "1.0", "provider": "Test Intel",
                    "source_reference": "https://intel.example/indicators",
                    "retrieved_at_utc": "2026-11-22T12:00:00Z",
                    "indicators": [{"type": "url", "value": "https://example.test/CasePath"}]}
        iocs = validate_ioc_document(document)
        logs = {"http": [{"ts": 1000, "uid": "HTTP1", "host": "EXAMPLE.test", "uri": "/CasePath",
                          "id.orig_h": "10.0.0.1", "id.resp_h": "203.0.113.1"}],
                "ssl": [{"uid": "HTTP1", "server_name": "example.test"}]}
        matches = [finding for finding in detect_findings(logs, iocs) if finding["rule_id"] == "NET-011"]
        self.assertEqual(len(matches), 1)
        self.assertIn("HTTP1", matches[0]["evidence_refs"][0])

    def test_output_directory_refuses_to_overwrite_existing_contents(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "out"
            output.mkdir()
            marker = output / "keep.json"
            marker.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-empty"):
                prepare_output_dir(output)
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_log_line_references_remain_aligned_when_malformed_rows_are_skipped(self):
        import tempfile

        with tempfile.TemporaryDirectory() as temp:
            log_dir = Path(temp)
            (log_dir / "conn.log").write_text(
                "#separator \\x09\n#fields\tts\tuid\n"
                "1000\tU1\nmalformed\trow\textra\n1001\tU2\n",
                encoding="utf-8",
            )
            rows = _rows(log_dir, "conn")
        self.assertEqual([row["_evidence_ref"] for row in rows],
                         ["zeek/conn.log#line=3", "zeek/conn.log#line=5"])

    def test_custom_findings_merge_without_losing_original_engine_alerts(self):
        zeek = [{"rule_id": "NET-005", "uid": "", "evidence": "observed"}]
        suricata = [{"rule_id": "SURICATA-123", "uid": "", "evidence": "signature"}]
        custom = [{"rule_id": "NET-009", "source_tool": "ProjectDetector", "alert_origin": "project_generated",
                   "evidence": "{}", "evidence_refs": ["zeek/smb_mapping.log#line=8"]}]
        merged = merge_alerts(zeek, suricata, custom)
        self.assertEqual(len(merged), 3)
        self.assertEqual({item["rule_id"] for item in merged}, {"NET-005", "SURICATA-123", "NET-009"})
        by_rule = {item["rule_id"]: item for item in merged}
        self.assertEqual(by_rule["NET-005"]["source_tool"], "Zeek")
        self.assertEqual(by_rule["NET-005"]["alert_origin"], "project_generated")
        self.assertEqual(by_rule["SURICATA-123"]["source_tool"], "Suricata")
        self.assertEqual(by_rule["SURICATA-123"]["alert_origin"], "engine_alert")
        self.assertEqual(by_rule["NET-009"]["source_tool"], "ProjectDetector")


if __name__ == "__main__":
    unittest.main()
