#!/usr/bin/env python3
"""Build a provenance-preserving intelligence record from a classic Ethernet PCAP.

The source capture is read-only. Zeek/Suricata processing is delegated to the
existing offline unified pipeline and project adapters; packet payloads are
never extracted here. Generated files default to a directory under the user's
home directory, outside the repository.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "pcap_intelligence.schema.json"
HASHES = {"md5": (32, re.compile(r"^[a-fA-F0-9]{32}$")),
          "sha1": (40, re.compile(r"^[a-fA-F0-9]{40}$")),
          "sha256": (64, re.compile(r"^[a-fA-F0-9]{64}$"))}
MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
         b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}


class InputError(ValueError):
    """Input/configuration cannot be processed safely."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_pcap(path: Path) -> dict[str, Any]:
    """Stream-validate classic PCAP record boundaries and collect metadata only."""
    if not path.is_file():
        raise InputError("PCAP input must be an existing regular file")
    try:
        with path.open("rb") as stream:
            header = stream.read(24)
            if len(header) != 24 or header[:4] not in MAGIC:
                raise InputError("Unsupported or malformed input; classic PCAP v2.x is required")
            endian, fraction_base = MAGIC[header[:4]]
            major, minor = struct.unpack(endian + "HH", header[4:8])
            snaplen, link_type = struct.unpack(endian + "II", header[16:24])
            if major != 2 or minor not in (2, 3, 4):
                raise InputError("Unsupported classic PCAP version")
            if snaplen < 1:
                raise InputError("Malformed PCAP snap length")
            if link_type != 1:
                raise InputError("Only Ethernet-link-type PCAP files are supported")
            count = 0
            first = last = None
            while True:
                record = stream.read(16)
                if not record:
                    break
                if len(record) != 16:
                    raise InputError("Malformed PCAP: truncated packet record header")
                sec, fraction, included, original = struct.unpack(endian + "IIII", record)
                if fraction >= fraction_base or included > snaplen or included > original:
                    raise InputError("Malformed PCAP: invalid packet record metadata")
                payload = stream.read(included)
                if len(payload) != included:
                    raise InputError("Malformed PCAP: truncated packet record")
                timestamp = datetime.fromtimestamp(sec + fraction / fraction_base, timezone.utc).isoformat()
                first = first or timestamp
                last = timestamp
                count += 1
    except (OSError, OverflowError, struct.error) as exc:
        raise InputError("Unable to read valid classic PCAP metadata") from exc
    if count == 0:
        raise InputError("PCAP contains no packet records")
    return {"pcap_sha256": sha256_file(path), "size_bytes": path.stat().st_size,
            "format": "pcap", "link_type": link_type, "snaplen": snaplen,
            "packet_count": count, "first_packet_utc": first, "last_packet_utc": last}


def assert_filestore_disabled(config: Path) -> None:
    """Fail closed unless every explicit Suricata file-store stanza disables storage."""
    try:
        lines = config.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise InputError("Suricata configuration cannot be read") from exc
    stanzas: list[list[str]] = []
    current: list[str] | None = None
    start_indent = -1
    for line in lines:
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        if re.match(r"include\s*:", stripped):
            raise InputError("Suricata config includes are unsupported by the safe file-store preflight")
        indent = len(line) - len(stripped)
        if re.match(r"-\s+file-store\s*:", stripped):
            current, start_indent = [], indent
            stanzas.append(current)
        elif current is not None and indent <= start_indent:
            current = None
        if current is not None:
            current.append(stripped)
    if not stanzas:
        raise InputError("Suricata config must explicitly disable file-store extraction")
    for stanza in stanzas:
        settings = [re.match(r"enabled\s*:\s*(\S+)", line) for line in stanza]
        values = [match.group(1).lower() for match in settings if match]
        if not values or any(value not in {"no", "false", "off"} for value in values):
            raise InputError("Suricata config must set file-store enabled to no")


def _load_zeek_adapter():
    spec = importlib.util.spec_from_file_location("phase2_zeek_adapter", ROOT / "scripts" / "detect_network_anomalies.py")
    if spec is None or spec.loader is None:
        raise InputError("Cannot load existing Zeek adapter")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.read_zeek_tsv


def _zeek_record_lines(path: Path) -> list[int]:
    """Return physical line numbers for valid data rows read by the existing adapter."""
    if not path.is_file() or path.stat().st_size == 0:
        return []
    fields: list[str] = []
    line_numbers: list[int] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#") or not fields:
                continue
            elif len(line.split("\t")) == len(fields):
                line_numbers.append(line_number)
    return line_numbers


def _utc(value: Any) -> str | None:
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, timezone.utc).isoformat()
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None
    return None


def _load_alert_payload(path: Path, expected_tool: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InputError(f"Cannot read {expected_tool} adapter alert output") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
        raise InputError(f"Malformed {expected_tool} adapter alert output")
    alerts = payload["alerts"]
    if any(not isinstance(alert, dict) for alert in alerts):
        raise InputError(f"Malformed {expected_tool} alert record")
    return alerts


def _suricata_alert_key(record: dict[str, Any], *, eve: bool) -> tuple[Any, ...] | None:
    if eve:
        alert = record.get("alert")
        evidence = alert if isinstance(alert, dict) else {}
        timestamp = record.get("timestamp")
        flow_id = record.get("flow_id")
        source_ip, destination_ip = record.get("src_ip"), record.get("dest_ip")
        destination_port = record.get("dest_port")
    else:
        try:
            evidence = json.loads(record.get("evidence", ""))
        except (TypeError, json.JSONDecodeError):
            return None
        if not isinstance(evidence, dict):
            return None
        timestamp = record.get("timestamp_utc")
        flow_id = evidence.get("flow_id")
        source_ip, destination_ip = record.get("src_ip"), record.get("dst_ip")
        destination_port = record.get("dst_port")
    signature_id = evidence.get("signature_id")
    if signature_id is None or flow_id is None:
        return None
    return (signature_id, flow_id, _utc(timestamp), source_ip, destination_ip, destination_port)


def collect_alert_observations(output: Path) -> list[dict[str, Any]]:
    """Normalize each adapter alert once and verify the adapters equal unified output."""
    pipeline = output
    zeek_path = pipeline / "zeek_adapter" / "alerts.json"
    suricata_path = pipeline / "suricata_adapter" / "alerts.json"
    unified_path = pipeline / "unified" / "alerts.json"
    zeek_alerts = _load_alert_payload(zeek_path, "Zeek")
    suricata_alerts = _load_alert_payload(suricata_path, "Suricata")
    unified_alerts = _load_alert_payload(unified_path, "unified")

    expected: list[dict[str, Any]] = []
    for source, alerts in (("Zeek", zeek_alerts), ("Suricata", suricata_alerts)):
        expected.extend({**alert, "source_tool": source} for alert in alerts)

    def multiset(alerts: list[dict[str, Any]]) -> Counter[str]:
        return Counter(json.dumps(alert, sort_keys=True, separators=(",", ":")) for alert in alerts)

    if multiset(expected) != multiset(unified_alerts):
        raise InputError("Zeek and Suricata adapter alerts do not match the unified alert output")

    eve_path = pipeline / "suricata" / "eve.json"
    eve_refs: dict[tuple[Any, ...], deque[str]] = defaultdict(deque)
    if eve_path.is_file():
        try:
            with eve_path.open(encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, start=1):
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(event, dict) and isinstance(event.get("alert"), dict):
                        key = _suricata_alert_key(event, eve=True)
                        if key is not None:
                            eve_refs[key].append(f"pipeline/suricata/eve.json#line={line_number}")
        except (OSError, UnicodeError) as exc:
            raise InputError("Cannot read Suricata EVE output for evidence references") from exc

    observations: list[dict[str, Any]] = []
    for source, alerts, relative_path in (
        ("Zeek", zeek_alerts, "pipeline/zeek_adapter/alerts.json"),
        ("Suricata", suricata_alerts, "pipeline/suricata_adapter/alerts.json"),
    ):
        for index, alert in enumerate(alerts):
            source_record = {**alert, "source_tool": source}
            reference = f"{relative_path}#/alerts/{index}"
            if source == "Suricata":
                key = _suricata_alert_key(alert, eve=False)
                if key is not None and eve_refs.get(key):
                    reference = eve_refs[key].popleft()
            observations.append({
                "classification": "tool_alert", "source": source, "kind": "alert",
                "observed_at_utc": _utc(alert.get("timestamp_utc")),
                "evidence_ref": reference, "data": source_record,
            })
    return observations


def collect_observations(output: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    read_zeek_tsv = _load_zeek_adapter()
    observations: list[dict[str, Any]] = []
    indicators: list[dict[str, Any]] = []
    file_hashes: list[dict[str, Any]] = []
    for log_name in ("conn", "dns", "http", "ssl", "notice", "files"):
        log_path = output / "zeek" / f"{log_name}.log"
        rows = read_zeek_tsv(log_path)
        line_numbers = _zeek_record_lines(log_path)
        if len(rows) != len(line_numbers):
            raise InputError(f"Cannot align Zeek {log_name}.log rows with source line numbers")
        for row, line_number in zip(rows, line_numbers):
            timestamp = _utc(row.get("ts"))
            ref = f"pipeline/zeek/{log_name}.log#line={line_number}"
            observations.append({"classification": "observed_fact", "source": "Zeek", "kind": log_name,
                                "observed_at_utc": timestamp, "evidence_ref": ref, "data": row})
            if log_name == "conn":
                proto = row.get("proto") if isinstance(row.get("proto"), str) else None
                for side in ("src", "dst"):
                    zeek_side = "orig" if side == "src" else "resp"
                    ip, port = row.get(f"id.{zeek_side}_h"), row.get(f"id.{zeek_side}_p")
                    if isinstance(ip, str):
                        indicators.append({"type": "ip", "value": ip, "direction": "source" if side == "src" else "destination",
                                          "protocol": proto, "port": port if type(port) is int else None,
                                          "first_seen_utc": timestamp, "last_seen_utc": timestamp, "evidence_refs": [ref]})
            if log_name == "dns" and isinstance(row.get("query"), str):
                indicators.append({"type": "domain", "value": row["query"], "direction": "unknown", "protocol": "dns",
                                   "port": None, "first_seen_utc": timestamp, "last_seen_utc": timestamp, "evidence_refs": [ref]})
            if log_name == "http" and isinstance(row.get("host"), str):
                uri = row.get("uri") if isinstance(row.get("uri"), str) else ""
                value = f"http://{row['host']}{uri}" if uri.startswith("/") else row["host"]
                indicators.append({"type": "url" if value.startswith("http://") else "domain", "value": value,
                                   "direction": "destination", "protocol": "http", "port": None,
                                   "first_seen_utc": timestamp, "last_seen_utc": timestamp, "evidence_refs": [ref]})
            if log_name == "files":
                for algorithm in HASHES:
                    value = row.get(algorithm)
                    if isinstance(value, str) and HASHES[algorithm][1].fullmatch(value):
                        file_hashes.append({"algorithm": algorithm, "value": value.lower(), "source": "Zeek files.log", "evidence_ref": ref})
    observations.extend(collect_alert_observations(output))
    return observations, indicators, file_hashes


def _tool_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    tools = manifest.get("tools", {})
    config = manifest.get("configuration", {})
    return [
        {"name": "Zeek", "version": tools.get("zeek"), "role": "network protocol analysis", "configuration_sha256": None},
        {"name": "Suricata", "version": tools.get("suricata"), "role": "network signature analysis", "configuration_sha256": config.get("suricata_yaml", {}).get("sha256")},
        {"name": "Suricata ruleset", "version": None, "role": "signature input", "configuration_sha256": config.get("suricata_rules", {}).get("sha256")},
        {"name": "Python", "version": tools.get("python"), "role": "pipeline runtime", "configuration_sha256": None},
        {"name": "project offline pipeline", "version": None, "role": "existing alert adapters and merger", "configuration_sha256": None},
    ]


def build(args: argparse.Namespace) -> Path:
    try:
        import jsonschema
    except ImportError as exc:
        raise InputError("Install requirements-api.txt (includes JSON Schema validation support)") from exc
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    pcap = args.pcap.expanduser().resolve(strict=True)
    metadata = inspect_pcap(pcap)
    config = args.suricata_config.expanduser().resolve(strict=True)
    assert_filestore_disabled(config)
    repo = ROOT.resolve()
    if args.out:
        out = args.out.expanduser().resolve()
    else:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out = Path.home() / "pcap-intelligence" / f"{metadata['pcap_sha256'][:16]}-{stamp}"
    if out == repo or repo in out.parents:
        raise InputError("Output directory must be outside the repository")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise InputError("Refusing to use a non-empty output directory")
    out.mkdir(parents=True, exist_ok=True)
    before_hash = metadata["pcap_sha256"]
    pipeline = [sys.executable, str(ROOT / "scripts/run_offline_unified_pipeline.py"), "--pcap", str(pcap),
                "--out", str(out / "pipeline"), "--zeek-bin", args.zeek_bin,
                "--suricata-bin", args.suricata_bin, "--suricata-config", str(config),
                "--suricata-rules", str(args.suricata_rules.expanduser().resolve(strict=True))]
    subprocess.run(pipeline, check=True)
    if sha256_file(pcap) != before_hash:
        raise InputError("Source PCAP changed during analysis; refusing to create a completed record")
    pipeline_out = out / "pipeline"
    manifest = json.loads((pipeline_out / "run_manifest.json").read_text(encoding="utf-8"))
    observations, indicators, hashes = collect_observations(pipeline_out)
    if args.publisher_label:
        observations.append({"classification": "publisher_label", "source": args.publisher or "unspecified publisher",
                             "kind": "scenario_label", "observed_at_utc": None,
                             "evidence_ref": "#/provenance/publisher_label",
                             "data": {"label": args.publisher_label, "interpretation": "publisher-provided label; not independently verified"}})
    enrichments: list[dict[str, Any]] = []
    if args.enrich_malwarebazaar:
        from api.malwarebazaar import lookup_hash
        observed = {item["value"] for item in hashes if item["algorithm"] == "sha256"}
        for value in sorted(observed):
            result = lookup_hash(value)
            enrichments.append({"provider": "MalwareBazaar", "queried_hash": value,
                                "queried_algorithm": "sha256", "match_status": result["match_status"],
                                "lookup_time_utc": result["lookup_time"],
                                "source_reference": "https://bazaar.abuse.ch/api/", "metadata": result.get("metadata", {})})
    record = {
        "schema_version": "1.0.0", "record_id": before_hash,
        "provenance": {"source_kind": args.source_kind, "source_reference": args.source_reference,
                       "publisher": args.publisher, "publisher_label": args.publisher_label,
                       "acquired_at_utc": args.acquired_at_utc, "license_status": args.license_status,
                       "license_reference": args.license_reference, "source_verification": args.source_verification},
        "capture": metadata, "analysis_tools": _tool_entries(manifest), "observations": observations,
        "indicators": indicators, "file_hash_observations": hashes,
        "malwarebazaar_enrichments": enrichments,
        "assessment": {"confidence": "not_assessed", "limitations": ["Tool outputs and publisher labels are leads; they do not independently establish compromise.", "Only protocol metadata and tool observations are included; payloads are not extracted."], "analyst_hypotheses": []},
    }
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(record)
    record_path = out / "pcap_intelligence.json"
    record_path.write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return record_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--out", type=Path, help="New or empty output directory outside the repository")
    parser.add_argument("--zeek-bin", default="zeek")
    parser.add_argument("--suricata-bin", default="suricata")
    parser.add_argument("--suricata-config", type=Path, default=Path("/etc/suricata/suricata.yaml"))
    parser.add_argument("--suricata-rules", type=Path, default=Path("/var/lib/suricata/rules/suricata.rules"))
    parser.add_argument("--source-kind", choices=("local", "publisher", "researcher_generated", "unknown"), default="unknown")
    parser.add_argument("--source-reference")
    parser.add_argument("--publisher")
    parser.add_argument("--publisher-label")
    parser.add_argument("--acquired-at-utc")
    parser.add_argument("--license-status", choices=("verified", "unclear", "not_applicable", "unknown"), default="unknown")
    parser.add_argument("--license-reference")
    parser.add_argument("--source-verification", choices=("cryptographically_verified", "documented_only", "unverified", "unknown"), default="unknown")
    parser.add_argument("--enrich-malwarebazaar", action="store_true", help="Explicitly query MalwareBazaar for observed valid SHA-256 values")
    args = parser.parse_args()
    try:
        print(f"Intelligence record: {build(args)}")
        return 0
    except (InputError, OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
