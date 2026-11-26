import argparse
import hashlib
import json
import struct
from pathlib import Path
from unittest.mock import patch

import jsonschema
import pytest

from scripts import build_pcap_intelligence_dataset as dataset


def write_pcap(path: Path, *, payload=b"synthetic-frame", link_type=1, truncated=False):
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type)
    packet_header = struct.pack("<IIII", 1_700_000_000, 123_456, len(payload), len(payload))
    path.write_bytes(global_header + packet_header + (payload[:-1] if truncated else payload))


def valid_args(tmp_path, pcap, output, config, rules):
    return argparse.Namespace(
        pcap=pcap, out=output, suricata_config=config, suricata_rules=rules,
        zeek_bin="zeek", suricata_bin="suricata", source_kind="unknown",
        source_reference=None, publisher="Example publisher", publisher_label="scenario label", acquired_at_utc=None,
        license_status="unknown", license_reference=None, source_verification="unknown",
        enrich_malwarebazaar=False,
    )


def schema():
    return json.loads(dataset.SCHEMA_PATH.read_text(encoding="utf-8"))


def write_alert_outputs(root, *, zeek_count, suricata_count):
    root.mkdir(parents=True, exist_ok=True)
    (root / "zeek_adapter").mkdir()
    (root / "suricata_adapter").mkdir()
    (root / "unified").mkdir()
    (root / "suricata").mkdir(exist_ok=True)
    zeek_alerts = []
    for index in range(zeek_count):
        zeek_alerts.append({"timestamp_utc": f"2024-01-01T00:00:{index:02d}+00:00", "rule_id": f"NET-{index:03d}",
                            "severity": "low", "confidence": "low", "title": f"Zeek finding {index}",
                            "src_ip": "192.0.2.10", "dst_ip": "", "dst_port": "", "uid": "",
                            "evidence": f"synthetic Zeek evidence {index}"})
    suricata_alerts = []
    eve_events = []
    for index in range(suricata_count):
        signature_id = 1000 + index
        flow_id = 9000 + index
        timestamp = f"2024-01-02T00:00:{index % 60:02d}.000000+00:00"
        evidence = {"signature_id": signature_id, "flow_id": flow_id}
        alert = {"timestamp_utc": timestamp, "rule_id": f"SURICATA-{signature_id}", "severity": "low",
                 "confidence": "high", "title": f"Synthetic signature {signature_id}",
                 "src_ip": "192.0.2.20", "dst_ip": "198.51.100.20", "dst_port": 443, "uid": "",
                 "correlation": "", "related_rule_id": "", "related_fuid": "", "related_uid": "",
                 "evidence": json.dumps(evidence, sort_keys=True)}
        suricata_alerts.append(alert)
        eve_events.append({"timestamp": timestamp, "flow_id": flow_id, "src_ip": alert["src_ip"],
                           "dest_ip": alert["dst_ip"], "dest_port": alert["dst_port"],
                           "alert": {"signature_id": signature_id}})
    (root / "suricata" / "eve.json").write_text("".join(json.dumps(event) + "\n" for event in eve_events), encoding="utf-8")
    (root / "zeek_adapter" / "alerts.json").write_text(json.dumps({"tool": "offline-zeek-detection-engine", "alerts": zeek_alerts}), encoding="utf-8")
    (root / "suricata_adapter" / "alerts.json").write_text(json.dumps({"tool": "suricata-eve-adapter", "alerts": suricata_alerts}), encoding="utf-8")
    unified = [{**alert, "source_tool": "Zeek"} for alert in zeek_alerts]
    unified.extend({**alert, "source_tool": "Suricata"} for alert in suricata_alerts)
    unified.sort(key=lambda item: (item["timestamp_utc"], item["source_tool"], item["rule_id"]))
    (root / "unified" / "alerts.json").write_text(json.dumps({"tool": "unified-network-detection", "alerts": unified}), encoding="utf-8")
    return unified


def test_pcap_metadata_hash_timestamp_and_read_only(tmp_path):
    source = tmp_path / "synthetic.pcap"
    write_pcap(source)
    original = source.read_bytes()
    result = dataset.inspect_pcap(source)
    assert result["pcap_sha256"] == hashlib.sha256(original).hexdigest()
    assert result["size_bytes"] == len(original)
    assert result["packet_count"] == 1
    assert result["link_type"] == 1
    assert result["first_packet_utc"] == result["last_packet_utc"]
    assert source.read_bytes() == original


@pytest.mark.parametrize("kind", ["missing", "pcapng", "truncated", "unsupported_link"])
def test_invalid_or_unsupported_input_fails_safely(tmp_path, kind):
    path = tmp_path / "bad.pcap"
    if kind == "missing":
        with pytest.raises(dataset.InputError):
            dataset.inspect_pcap(path)
    else:
        if kind == "pcapng":
            path.write_bytes(b"\x0a\x0d\x0d\x0a" + bytes(40))
        else:
            write_pcap(path, link_type=101 if kind == "unsupported_link" else 1,
                       truncated=kind == "truncated")
        with pytest.raises(dataset.InputError):
            dataset.inspect_pcap(path)


def test_rejects_malformed_packet_record_header(tmp_path):
    path = tmp_path / "malformed.pcap"
    path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"short")
    with pytest.raises(dataset.InputError, match="Malformed PCAP"):
        dataset.inspect_pcap(path)


def test_suricata_file_store_must_be_explicitly_disabled(tmp_path):
    disabled = tmp_path / "disabled.yaml"
    disabled.write_text("outputs:\n  - file-store:\n      enabled: no\n", encoding="utf-8")
    dataset.assert_filestore_disabled(disabled)
    enabled = tmp_path / "enabled.yaml"
    enabled.write_text("outputs:\n  - file-store:\n      enabled: yes\n", encoding="utf-8")
    with pytest.raises(dataset.InputError, match="enabled to no"):
        dataset.assert_filestore_disabled(enabled)
    included = tmp_path / "included.yaml"
    included.write_text("include: other.yaml\noutputs:\n  - file-store:\n      enabled: no\n", encoding="utf-8")
    with pytest.raises(dataset.InputError, match="includes are unsupported"):
        dataset.assert_filestore_disabled(included)


def test_observed_file_hashes_are_validated_and_unknown_fields_ignored(tmp_path):
    zeek = tmp_path / "zeek"
    zeek.mkdir()
    (zeek / "files.log").write_text(
        "#fields\tts\tsha256\tmd5\tfilename\n"
        f"1700000000\t{'a' * 64}\t{'b' * 32}\tobserved.bin\n"
        "1700000001\tmalformed\tbad\tignored.bin\n", encoding="utf-8")
    write_alert_outputs(tmp_path, zeek_count=0, suricata_count=0)
    observations, _indicators, file_hashes = dataset.collect_observations(tmp_path)
    assert [entry["algorithm"] for entry in file_hashes] == ["md5", "sha256"]
    assert all(entry["source"] == "Zeek files.log" for entry in file_hashes)
    assert all(entry["evidence_ref"].startswith("pipeline/zeek/files.log#line=") for entry in file_hashes)
    assert all("filename" not in entry for entry in file_hashes)
    assert len(observations) == 2
    assert all(observation["evidence_ref"].startswith("pipeline/zeek/files.log#line=") for observation in observations)


def test_all_129_adapter_alerts_are_represented_once_with_source_references(tmp_path):
    unified = write_alert_outputs(tmp_path, zeek_count=2, suricata_count=127)
    observations = dataset.collect_alert_observations(tmp_path)
    assert len(unified) == 129
    assert len(observations) == 129
    assert {source: sum(item["source"] == source for item in observations) for source in ("Zeek", "Suricata")} == {
        "Zeek": 2, "Suricata": 127,
    }
    assert len({item["evidence_ref"] for item in observations}) == 129
    assert all(item["classification"] == "tool_alert" for item in observations)
    assert all(item["data"]["source_tool"] == item["source"] for item in observations)
    normalized = [{**item["data"]} for item in observations]
    key = lambda alert: json.dumps(alert, sort_keys=True, separators=(",", ":"))
    assert sorted(map(key, normalized)) == sorted(map(key, unified))
    assert all(item["evidence_ref"].startswith("pipeline/zeek_adapter/alerts.json#")
               for item in observations if item["source"] == "Zeek")
    assert all(item["evidence_ref"].startswith("pipeline/suricata/eve.json#line=")
               for item in observations if item["source"] == "Suricata")


def test_schema_accepts_explicit_empty_record_and_rejects_bad_hash():
    record = {
        "schema_version": "1.0.0", "record_id": "a" * 64,
        "provenance": {"source_kind": "unknown", "source_reference": None, "publisher": None,
                       "publisher_label": None, "acquired_at_utc": None, "license_status": "unknown",
                       "license_reference": None, "source_verification": "unknown"},
        "capture": {"pcap_sha256": "a" * 64, "size_bytes": 24, "format": "pcap", "link_type": 1,
                    "snaplen": 65535, "packet_count": 0, "first_packet_utc": None, "last_packet_utc": None},
        "analysis_tools": [], "observations": [], "indicators": [], "file_hash_observations": [],
        "malwarebazaar_enrichments": [], "assessment": {"confidence": "not_assessed", "limitations": [], "analyst_hypotheses": []},
    }
    validator = jsonschema.Draft202012Validator(schema(), format_checker=jsonschema.FormatChecker())
    validator.validate(record)
    bad = json.loads(json.dumps(record))
    bad["capture"]["pcap_sha256"] = "not-a-hash"
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(bad)
    missing_reference = json.loads(json.dumps(record))
    missing_reference["observations"] = [{"classification": "observed_fact", "source": "Zeek", "kind": "conn",
                                          "observed_at_utc": None, "data": {}}]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(missing_reference)


def test_build_records_provenance_and_keeps_outputs_outside_repo(tmp_path):
    pcap = tmp_path / "synthetic.pcap"
    write_pcap(pcap)
    config, rules = tmp_path / "suricata.yaml", tmp_path / "rules.rules"
    config.write_text("outputs:\n  - file-store:\n      enabled: no\n", encoding="utf-8")
    rules.write_text("# synthetic test rules\n", encoding="utf-8")
    output = tmp_path / "generated"
    args = valid_args(tmp_path, pcap, output, config, rules)

    def fake_pipeline(command, check):
        assert check is True
        root = output / "pipeline"
        (root / "zeek").mkdir(parents=True)
        (root / "suricata").mkdir()
        (root / "zeek" / "conn.log").write_text(
            "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            "1700000000\t192.0.2.5\t54321\t198.51.100.8\t443\ttcp\n", encoding="utf-8")
        (root / "suricata" / "eve.json").write_text("", encoding="utf-8")
        write_alert_outputs(root, zeek_count=0, suricata_count=0)
        (root / "run_manifest.json").write_text(json.dumps({"tools": {"zeek": "Zeek test", "suricata": "Suricata test", "python": "3.x"}, "configuration": {"suricata_yaml": {"sha256": "b" * 64}, "suricata_rules": {"sha256": "c" * 64}}}), encoding="utf-8")

    with patch.object(dataset.subprocess, "run", side_effect=fake_pipeline):
        record_path = dataset.build(args)
    record = json.loads(record_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema(), format_checker=jsonschema.FormatChecker()).validate(record)
    assert record["provenance"]["source_verification"] == "unknown"
    assert record["observations"][0]["classification"] == "observed_fact"
    assert record["observations"][-1]["classification"] == "publisher_label"
    assert len(record["indicators"]) == 2
    assert record["capture"]["pcap_sha256"] == hashlib.sha256(pcap.read_bytes()).hexdigest()
    assert dataset.ROOT not in record_path.parents


def test_build_refuses_repository_output_before_running_pipeline(tmp_path):
    pcap = tmp_path / "synthetic.pcap"
    write_pcap(pcap)
    config, rules = tmp_path / "suricata.yaml", tmp_path / "rules.rules"
    config.write_text("outputs:\n  - file-store:\n      enabled: no\n", encoding="utf-8")
    rules.write_text("", encoding="utf-8")
    args = valid_args(tmp_path, pcap, dataset.ROOT / "phase2-test-output", config, rules)
    with patch.object(dataset.subprocess, "run") as run:
        with pytest.raises(dataset.InputError, match="outside the repository"):
            dataset.build(args)
        run.assert_not_called()


def test_build_refuses_nonempty_output_without_changing_it(tmp_path):
    pcap = tmp_path / "synthetic.pcap"
    write_pcap(pcap)
    config, rules = tmp_path / "suricata.yaml", tmp_path / "rules.rules"
    config.write_text("outputs:\n  - file-store:\n      enabled: no\n", encoding="utf-8")
    rules.write_text("", encoding="utf-8")
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "keep.txt"
    marker.write_text("preserve", encoding="utf-8")
    with pytest.raises(dataset.InputError, match="non-empty"):
        dataset.build(valid_args(tmp_path, pcap, output, config, rules))
    assert marker.read_text(encoding="utf-8") == "preserve"
