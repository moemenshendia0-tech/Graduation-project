#!/usr/bin/env python3
"""Convert Suricata EVE alert events into the project's candidate-alert schema."""

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def first_value(value, default="unknown"):
    if isinstance(value, list):
        return str(value[0]) if value else default
    return str(value) if value not in (None, "") else default


def convert_event(event):
    alert = event.get("alert") or {}
    metadata = alert.get("metadata") or {}

    sid = alert.get("signature_id")
    if sid is None:
        return None

    raw_severity = alert.get("severity")
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

    timestamp = event.get("timestamp", "")
    try:
        timestamp = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        ).astimezone(timezone.utc).isoformat()
    except (ValueError, TypeError):
        pass

    http = event.get("http") or {}
    flow = event.get("flow") or {}

    evidence = {
        "source_tool": "Suricata",
        "signature": alert.get("signature", ""),
        "signature_id": sid,
        "suricata_priority": raw_severity,
        "gid": alert.get("gid"),
        "revision": alert.get("rev"),
        "category": alert.get("category", ""),
        "signature_severity": signature_severity,
        "action": alert.get("action", ""),
        "flow_id": event.get("flow_id"),
        "protocol": event.get("proto", ""),
        "hostname": http.get("hostname", ""),
        "http_url": http.get("url", ""),
        "http_method": http.get("http_method", ""),
        "http_status": http.get("status"),
        "flow_bytes_toserver": flow.get("bytes_toserver"),
        "flow_bytes_toclient": flow.get("bytes_toclient"),
    }

    confidence = first_value(metadata.get("confidence"))

    return {
        "timestamp_utc": timestamp,
        "rule_id": f"SURICATA-{sid}",
        "severity": severity,
        "confidence": confidence.lower(),
        "title": alert.get("signature", f"Suricata SID {sid}"),
        "src_ip": event.get("src_ip", ""),
        "dst_ip": event.get("dest_ip", ""),
        "dst_port": event.get("dest_port"),
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

    with eve_path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue

            kind = event.get("event_type", "unknown")
            event_counts[kind] = event_counts.get(kind, 0) + 1

            if kind == "alert":
                converted = convert_event(event)
                if converted:
                    alerts.append(converted)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = {
        "tool": "suricata-eve-adapter",
        "source_file": str(eve_path),
        "event_counts": event_counts,
        "malformed_lines": malformed,
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
    print(f"Suricata alerts converted: {len(alerts)}")
    print(f"JSON: {json_path.resolve()}")
    print(f"CSV:  {csv_path.resolve()}")
    print("Informational signatures are kept separate from threat severity.")


if __name__ == "__main__":
    main()
