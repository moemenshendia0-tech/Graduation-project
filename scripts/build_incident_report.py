#!/usr/bin/env python3
"""Build cautious incident candidates from aggregate Zeek detector alerts.

NET-002 and NET-003 are group-level alerts, not individual event records.
This report only flags overlapping aggregate activity ranges on the same
source/destination/port and explicitly labels the result low-confidence.
"""

import argparse
import json
from datetime import datetime, timezone
from collections import defaultdict
from pathlib import Path


def parse_timestamp(value):
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def alert_range(alert):
    """Use explicit group boundaries; never treat a single start timestamp as a range."""
    start = parse_timestamp(alert.get("first_seen_utc"))
    end = parse_timestamp(alert.get("last_seen_utc"))
    if start is None or end is None or end < start:
        return None
    return start, end


def range_gap_seconds(first, second):
    """Return 0 for overlap, otherwise the positive gap between two UTC ranges."""
    first_start, first_end = first
    second_start, second_end = second
    if first_start <= second_end and second_start <= first_end:
        return 0.0
    if first_end < second_start:
        return (second_start - first_end).total_seconds()
    return (first_start - second_end).total_seconds()


def endpoint_key(alert):
    return (
        alert.get("src_ip"),
        alert.get("dst_ip"),
        str(alert.get("dst_port") or ""),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Existing alerts.json")
    parser.add_argument("--out", required=True, help="Incident report JSON")
    parser.add_argument(
        "--window-seconds", type=float, default=10.0,
        help="Maximum gap allowed between aggregate activity windows (default: 10 seconds)",
    )
    args = parser.parse_args()
    if args.window_seconds < 0:
        parser.error("--window-seconds must be >= 0")

    source = Path(args.input).expanduser().resolve()
    data = json.loads(source.read_text(encoding="utf-8"))
    alerts = data.get("alerts", [])
    relevant = [
        alert for alert in alerts
        if alert.get("rule_id") in {"NET-002", "NET-003"}
        and alert.get("src_ip") and alert.get("dst_ip")
    ]

    by_endpoint = defaultdict(list)
    for alert in relevant:
        by_endpoint[endpoint_key(alert)].append(alert)

    incidents = []
    # Count missing-range aggregate alerts once, rather than once per pair.
    ranges_by_alert_id = {id(alert): alert_range(alert) for alert in relevant}
    ignored_missing_ranges = sum(
        1 for alert in relevant if ranges_by_alert_id[id(alert)] is None
    )
    for (src, dst, port), items in sorted(by_endpoint.items()):
        post_alerts = [
            alert for alert in items
            if alert.get("rule_id") == "NET-002" and ranges_by_alert_id[id(alert)] is not None
        ]
        periodic_alerts = [
            alert for alert in items
            if alert.get("rule_id") == "NET-003" and ranges_by_alert_id[id(alert)] is not None
        ]
        for post in post_alerts:
            post_range = ranges_by_alert_id[id(post)]
            for periodic in periodic_alerts:
                periodic_range = ranges_by_alert_id[id(periodic)]
                gap = range_gap_seconds(post_range, periodic_range)
                if gap > args.window_seconds:
                    continue
                incidents.append({
                    "incident_id": f"NET-CANDIDATE-{len(incidents) + 1:03d}",
                    "src_ip": src,
                    "dst_ip": dst,
                    "dst_port": port,
                    "candidate_type": "overlapping_aggregate_POST_and_periodic_activity",
                    "confidence": "low",
                    "status": "requires_event_level_validation",
                    "correlation_method": "aggregate_time_range_overlap",
                    "gap_between_ranges_seconds": round(gap, 3),
                    "correlation_window_seconds": args.window_seconds,
                    "post_activity_window_utc": {
                        "first_seen": post_range[0].isoformat(),
                        "last_seen": post_range[1].isoformat(),
                    },
                    "periodic_activity_window_utc": {
                        "first_seen": periodic_range[0].isoformat(),
                        "last_seen": periodic_range[1].isoformat(),
                    },
                    "post_evidence": post.get("evidence", ""),
                    "periodic_evidence": periodic.get("evidence", ""),
                    "limitations": [
                        "NET-002 and NET-003 summarize groups of events, not individual transactions.",
                        "Temporal overlap on the same endpoint and port does not prove event-level linkage or causality.",
                        "Periodicity does not prove command and control.",
                        "Request volume does not prove successful data exfiltration.",
                        "Validate individual UIDs, request/connection timestamps, payloads, and endpoint context.",
                    ],
                })

    report = {
        "source_report": str(source),
        "source_alert_count": len(alerts),
        "relevant_aggregate_alert_count": len(relevant),
        "incident_candidate_count": len(incidents),
        "aggregate_alerts_without_valid_time_range_skipped": ignored_missing_ranges,
        "incident_candidates": incidents,
        "disclaimer": (
            "Candidates represent only overlapping aggregate activity windows. "
            "They are low-confidence investigation leads, not proof of compromise, "
            "command-and-control, event-level linkage, or exfiltration. Alerts generated "
            "before the detector emitted first_seen_utc/last_seen_utc are skipped."
        ),
    }
    out = Path(args.out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Source alerts: {len(alerts)}")
    print(f"Relevant aggregate alerts: {len(relevant)}")
    print(f"Incident candidates: {len(incidents)}")
    print(f"Aggregate alerts without usable ranges skipped: {ignored_missing_ranges}")
    print(f"Report: {out}")


if __name__ == "__main__":
    main()
