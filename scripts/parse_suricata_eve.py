#!/usr/bin/env python3
"""Convert Suricata EVE alert events into the project's candidate-alert schema."""

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def first_value(value, default="unknown"):
    if isinstance(value, list):
        return first_value(value[0], default) if value else default
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        text = str(value)
        return text if text else default
    return default


def optional_text(container, field, issue_counter, default=""):
    value = container.get(field)
    if value is None or value == "":
        return default
    if not isinstance(value, str):
        issue_counter["invalid_optional_fields"] += 1
        return default
    return value


def optional_scalar(container, field, issue_counter):
    value = container.get(field)
    if value is None or isinstance(value, (str, int)) and not isinstance(value, bool):
        return value
    issue_counter["invalid_optional_fields"] += 1
    return None


def optional_object(container, field, issue_counter):
    value = container.get(field)
    if value is None:
        return {}
    if not isinstance(value, dict):
        issue_counter["invalid_optional_fields"] += 1
        return {}
    return value


def convert_event(event, issue_counter=None):
    if not isinstance(event, dict):
        raise ValueError("EVE record must be a JSON object")

    if issue_counter is None:
        issue_counter = {"invalid_optional_fields": 0}

    alert = event.get("alert")
    if not isinstance(alert, dict):
        raise ValueError("EVE alert field must be a JSON object")

    sid = alert.get("signature_id")
    # EVE alert.signature_id is an integer. Check it before optional evidence
    # so a rejected alert increments only the invalid-shape counter.
    if not isinstance(sid, int) or isinstance(sid, bool):
        return None

    metadata = optional_object(alert, "metadata", issue_counter)
    http = optional_object(event, "http", issue_counter)
    flow = optional_object(event, "flow", issue_counter)
    signature = optional_text(alert, "signature", issue_counter, f"Suricata SID {sid}")

    raw_severity = alert.get("severity")
    if raw_severity is not None and (not isinstance(raw_severity, int) or isinstance(raw_severity, bool)):
        issue_counter["invalid_optional_fields"] += 1
        raw_severity = None
    signature_severity = first_value(
        metadata.get("signature_severity"), ""
    ).lower()

    # Suricata numeric priority is authoritative for operational severity.
    # Signature metadata is preserved separately as descriptive classification.
    severity = {
        1: "high",
        2: "medium",
        3: "low",
    }.get(raw_severity, "unknown")

    timestamp = optional_text(event, "timestamp", issue_counter)
    try:
        timestamp = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        ).astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        pass

    evidence = {
        "source_tool": "Suricata",
        "signature": signature,
        "signature_id": sid,
        "suricata_priority": raw_severity,
        "gid": alert.get("gid"),
        "revision": alert.get("rev"),
        "category": optional_text(alert, "category", issue_counter),
        "signature_severity": signature_severity,
        "action": alert.get("action", ""),
        "flow_id": event.get("flow_id"),
        "protocol": optional_text(event, "proto", issue_counter),
        "hostname": optional_text(http, "hostname", issue_counter),
        "http_url": optional_text(http, "url", issue_counter),
        "http_method": optional_text(http, "http_method", issue_counter),
        "http_status": optional_scalar(http, "status", issue_counter),
        "flow_bytes_toserver": optional_scalar(flow, "bytes_toserver", issue_counter),
        "flow_bytes_toclient": optional_scalar(flow, "bytes_toclient", issue_counter),
    }

    confidence = first_value(metadata.get("confidence"))

    return {
        "timestamp_utc": timestamp,
        "rule_id": f"SURICATA-{sid}",
        "severity": severity,
        "confidence": confidence.lower(),
        "title": signature,
        "src_ip": optional_text(event, "src_ip", issue_counter),
        "dst_ip": optional_text(event, "dest_ip", issue_counter),
        "dst_port": optional_scalar(event, "dest_port", issue_counter),
        "uid": "",
        "correlation": "",
        "related_rule_id": "",
        "related_fuid": "",
        "related_uid": "",
        "evidence": json.dumps(evidence, ensure_ascii=False),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Convert Suricata EVE alerts to candidate alerts."
    )
    parser.add_argument("--eve", required=True, help="Input Suricata eve.json")
    parser.add_argument("--out", default="suricata-detection-output")
    args = parser.parse_args()

    eve_path = Path(args.eve)
    if not eve_path.is_file():
        parser.error(f"EVE file not found: {eve_path}")

    alerts = []
    event_counts = {}
    malformed = 0
    invalid_shape = 0
    issue_counter = {"invalid_optional_fields": 0}

    with eve_path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue

            if not isinstance(event, dict):
                invalid_shape += 1
                continue

            kind = event.get("event_type", "unknown")
            event_counts[kind] = event_counts.get(kind, 0) + 1

            if kind == "alert":
                try:
                    converted = convert_event(event, issue_counter)
                except ValueError:
                    invalid_shape += 1
                    continue
                if converted is None:
                    invalid_shape += 1
                    continue
                alerts.append(converted)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    invalid_optional_fields = issue_counter["invalid_optional_fields"]
    payload = {
        "tool": "suricata-eve-adapter",
        "source_file": str(eve_path),
        "event_counts": event_counts,
        "malformed_lines": malformed,
        "invalid_shape_records": invalid_shape,
        "invalid_optional_fields": invalid_optional_fields,
        "alert_count": len(alerts),
        "alerts": alerts,
        "disclaimer": "Alerts are investigation leads, not proof of compromise.",
    }

    json_path = out_dir / "alerts.json"
    csv_path = out_dir / "alerts.csv"

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)

    columns = [
        "timestamp_utc", "rule_id", "severity", "confidence", "title",
        "src_ip", "dst_ip", "dst_port", "uid", "correlation",
        "related_rule_id", "related_fuid", "related_uid", "evidence",
    ]

    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        writer.writerows(alerts)

    print(f"EVE event counts: {event_counts}")
    print(f"Malformed lines: {malformed}")
    print(f"Invalid-shape records: {invalid_shape}")
    print(f"Invalid optional fields: {invalid_optional_fields}")
    print(f"Suricata alerts converted: {len(alerts)}")
    print(f"JSON: {json_path.resolve()}")
    print(f"CSV:  {csv_path.resolve()}")
    print("Informational signatures are kept separate from threat severity.")


if __name__ == "__main__":
    main()
