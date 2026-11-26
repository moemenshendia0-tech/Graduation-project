
#!/usr/bin/env python3
"""Merge Zeek and Suricata candidate alerts into one output."""

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


EXPECTED_TOOLS = {
    "Zeek": "offline-zeek-detection-engine",
    "Suricata": "suricata-eve-adapter",
}
ALLOWED_SEVERITIES = {"high", "medium", "low", "unknown"}
ALLOWED_CONFIDENCES = {"high", "medium", "low", "unknown"}
REQUIRED_ALERT_FIELDS = {
    "timestamp_utc": str,
    "rule_id": str,
    "severity": str,
    "confidence": str,
    "title": str,
    "src_ip": str,
    "dst_ip": str,
    "dst_port": (str, int, type(None)),
    "uid": str,
    "evidence": str,
}


COLUMNS = [
    "timestamp_utc",
    "first_seen_utc",
    "last_seen_utc",
    "source_tool",
    "alert_origin",
    "detection_engine",
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
    "evidence_refs",
    "related_events",
]


def load_payload(path, expected_tool):
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict):
        raise ValueError(f"Invalid alert payload in {path}: expected a JSON object")

    expected_identity = EXPECTED_TOOLS.get(expected_tool)
    if expected_identity is None:
        raise ValueError(f"Unknown expected source tool: {expected_tool}")
    actual_identity = payload.get("tool")
    if actual_identity != expected_identity:
        raise ValueError(
            f"Invalid source tool in {path}: expected tool {expected_identity!r} "
            f"for {expected_tool}, got {actual_identity!r}"
        )

    if not isinstance(payload.get("alerts"), list):
        raise ValueError(f"Invalid alert payload in {path}: 'alerts' must be a list")

    alerts = payload["alerts"]

    for index, alert in enumerate(alerts):
        location = f"{path}, alert {index}"
        if not isinstance(alert, dict):
            raise ValueError(f"Invalid alert entry in {location}: expected a JSON object")
        for field, expected_type in REQUIRED_ALERT_FIELDS.items():
            if field not in alert:
                raise ValueError(f"Invalid alert in {location}: missing required field {field!r}")
            if not isinstance(alert[field], expected_type):
                raise ValueError(f"Invalid alert in {location}: field {field!r} has an invalid type")
        if alert["severity"] not in ALLOWED_SEVERITIES:
            raise ValueError(
                f"Invalid alert in {location}: severity must be one of "
                f"{sorted(ALLOWED_SEVERITIES)}, got {alert['severity']!r}"
            )
        if alert["confidence"] not in ALLOWED_CONFIDENCES:
            raise ValueError(
                f"Invalid alert in {location}: confidence must be one of "
                f"{sorted(ALLOWED_CONFIDENCES)}, got {alert['confidence']!r}"
            )

    return payload, alerts


def load_project_findings(path):
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or payload.get("tool") != "project-network-findings":
        raise ValueError(f"Invalid project findings payload in {path}")
    findings = payload.get("alerts")
    if not isinstance(findings, list):
        raise ValueError(f"Invalid project findings payload in {path}: alerts must be a list")
    if payload.get("alert_count") != len(findings):
        raise ValueError(f"Invalid project findings payload in {path}: alert_count does not match alerts")
    required = ("rule_id", "severity", "confidence", "title", "source_tool", "evidence", "evidence_refs")
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or any(key not in finding for key in required):
            raise ValueError(f"Invalid project finding at index {index} in {path}")
        if finding["source_tool"] != "ProjectDetector" or not isinstance(finding["evidence_refs"], list) or not finding["evidence_refs"]:
            raise ValueError(f"Project finding {index} has invalid source or missing evidence references")
        if finding.get("alert_origin") != "project_generated" or finding.get("detection_engine") != "project-network-findings":
            raise ValueError(f"Project finding {index} has invalid origin metadata")
    return payload, findings


def merge_alerts(zeek_alerts, suricata_alerts, project_findings=None):
    merged = []

    for source, alerts, origin, engine in (
        ("Zeek", zeek_alerts, "project_generated", "offline-zeek-detection-engine"),
        ("Suricata", suricata_alerts, "engine_alert", "suricata-eve-adapter"),
        ("ProjectDetector", project_findings or [], "project_generated", "project-network-findings"),
    ):
        for original in alerts:
            alert = dict(original)
            alert["source_tool"] = source
            alert["alert_origin"] = alert.get("alert_origin", origin)
            alert["detection_engine"] = alert.get("detection_engine", engine)
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
    parser.add_argument("--project-findings", help="Optional evidence-linked project findings JSON")
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

    project_payload, project_findings = ({}, [])
    if args.project_findings:
        project_path = Path(args.project_findings).expanduser().resolve()
        if not project_path.is_file():
            parser.error(f"Project findings JSON not found: {project_path}")
        try:
            project_payload, project_findings = load_project_findings(project_path)
        except (json.JSONDecodeError, ValueError) as exc:
            parser.error(str(exc))

    alerts = merge_alerts(zeek_alerts, suricata_alerts, project_findings)
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
            "project_findings": {
                "tool": project_payload.get("tool"),
                "alert_count": len(project_findings),
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
        csv_rows = []
        for alert in alerts:
            row = dict(alert)
            for field in ("evidence_refs", "related_events"):
                if isinstance(row.get(field), (list, dict)):
                    row[field] = json.dumps(row[field], ensure_ascii=False, sort_keys=True)
            csv_rows.append(row)
        writer.writerows(csv_rows)

    print(f"Zeek alerts: {len(zeek_alerts)}")
    print(f"Suricata alerts: {len(suricata_alerts)}")
    print(f"Unified alerts: {len(alerts)}")
    print(f"Source counts: {dict(counts)}")
    print(f"JSON: {json_path}")
    print(f"CSV: {csv_path}")
    print("No automatic deduplication or speculative correlation performed.")


if __name__ == "__main__":
    main()
