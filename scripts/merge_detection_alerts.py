
#!/usr/bin/env python3
"""Merge Zeek and Suricata candidate alerts into one output."""

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


COLUMNS = [
    "timestamp_utc",
    "first_seen_utc",
    "last_seen_utc",
    "source_tool",
    "rule_id",
    "severity",
    "confidence",
    "title",
    "src_ip",
    "dst_ip",
    "dst_port",
    "uid",
    "correlation",
    "related_rule_id",
    "related_fuid",
    "related_uid",
    "evidence",
]


def load_payload(path, expected_tool):
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
        raise ValueError(f"Invalid alert payload: {path}")

    alerts = payload["alerts"]

    for alert in alerts:
        if not isinstance(alert, dict):
            raise ValueError(f"Invalid alert entry in: {path}")

    return payload, alerts


def merge_alerts(zeek_alerts, suricata_alerts):
    merged = []

    for source, alerts in (
        ("Zeek", zeek_alerts),
        ("Suricata", suricata_alerts),
    ):
        for original in alerts:
            alert = dict(original)
            alert["source_tool"] = source
            merged.append(alert)

    merged.sort(
        key=lambda item: (
            item.get("timestamp_utc") or "",
            item.get("source_tool") or "",
            item.get("rule_id") or "",
        )
    )
    return merged


def main():
    parser = argparse.ArgumentParser(
        description="Merge Zeek and Suricata candidate alerts."
    )
    parser.add_argument("--zeek", required=True)
    parser.add_argument("--suricata", required=True)
    parser.add_argument("--out", default="unified-detection-output")
    args = parser.parse_args()

    zeek_path = Path(args.zeek).expanduser().resolve()
    suricata_path = Path(args.suricata).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()

    if not zeek_path.is_file():
        parser.error(f"Zeek JSON not found: {zeek_path}")
    if not suricata_path.is_file():
        parser.error(f"Suricata JSON not found: {suricata_path}")

    try:
        zeek_payload, zeek_alerts = load_payload(zeek_path, "Zeek")
        suricata_payload, suricata_alerts = load_payload(
            suricata_path, "Suricata"
        )
    except (json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))

    alerts = merge_alerts(zeek_alerts, suricata_alerts)
    counts = Counter(alert["source_tool"] for alert in alerts)

    payload = {
        "tool": "unified-network-detection",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_metadata": {
            "zeek": {
                "input_file": str(zeek_path),
                "tool": zeek_payload.get("tool"),
                "input_counts": zeek_payload.get("input_counts"),
                "alert_count": len(zeek_alerts),
            },
            "suricata": {
                "input_file": str(suricata_path),
                "tool": suricata_payload.get("tool"),
                "event_counts": suricata_payload.get("event_counts"),
                "malformed_lines": suricata_payload.get("malformed_lines"),
                "alert_count": len(suricata_alerts),
            },
        },
        "source_alert_counts": dict(counts),
        "alert_count": len(alerts),
        "alerts": alerts,
        "deduplication": "Not performed; similar alerts require evidence-based correlation.",
        "disclaimer": (
            "Alerts are investigation leads, not proof of compromise, "
            "C2, or exfiltration."
        ),
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "alerts.json"
    csv_path = out_dir / "alerts.csv"

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)

    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=COLUMNS, extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(alerts)

    print(f"Zeek alerts: {len(zeek_alerts)}")
    print(f"Suricata alerts: {len(suricata_alerts)}")
    print(f"Unified alerts: {len(alerts)}")
    print(f"Source counts: {dict(counts)}")
    print(f"JSON: {json_path}")
    print(f"CSV: {csv_path}")
    print("No automatic deduplication or speculative correlation performed.")


if __name__ == "__main__":
    main()

