#!/usr/bin/env python3
"""Identify shared POST patterns across Zeek HTTP logs without merging evidence."""

import argparse
import json
import statistics
from collections import defaultdict, Counter
from pathlib import Path

from detect_network_anomalies import read_zeek_tsv, number, utc_time


def analyze(rows):
    groups = defaultdict(list)

    for row in rows:
        if str(row.get("method") or "").upper() != "POST":
            continue

        key = (
            str(row.get("id.orig_h") or ""),
            str(row.get("id.resp_h") or ""),
            str(row.get("host") or ""),
            str(row.get("uri") or ""),
        )
        groups[key].append(row)

    results = []

    for (src, dst, host, uri), items in groups.items():
        items.sort(key=lambda r: number(r.get("ts")))
        sizes = [int(number(r.get("request_body_len"))) for r in items]
        times = [number(r.get("ts")) for r in items]
        intervals = [
            b - a for a, b in zip(times, times[1:]) if b > a
        ]

        results.append({
            "src_ip": src,
            "dst_ip": dst,
            "host": host,
            "uri": uri,
            "request_count": len(items),
            "total_request_body_bytes": sum(sizes),
            "request_body_sizes": sizes,
            "median_interval_seconds": (
                round(statistics.median(intervals), 3)
                if intervals else None
            ),
            "statuses": dict(Counter(
                str(r.get("status_code") or "missing")
                for r in items
            )),
            "uids": sorted({
                str(r.get("uid"))
                for r in items if r.get("uid")
            }),
            "first_seen_utc": utc_time(times[0]) if times else "",
            "last_seen_utc": utc_time(times[-1]) if times else "",
        })

    # A pattern match is only a lead: compare ordered body sizes and
    # require at least five POSTs in each group.
    patterns = defaultdict(list)

    for item in results:
        if item["request_count"] >= 5:
            patterns[tuple(item["request_body_sizes"])].append(item)

    clusters = []
    for sizes, members in patterns.items():
        if len(members) < 2:
            continue

        clusters.append({
            "matching_size_sequence": list(sizes),
            "group_count": len(members),
            "distinct_hosts": sorted({
                item["host"] for item in members if item["host"]
            }),
            "distinct_source_ips": sorted({
                item["src_ip"] for item in members if item["src_ip"]
            }),
            "total_observed_request_body_bytes": sum(
                item["total_request_body_bytes"] for item in members
            ),
            "groups": members,
            "interpretation": (
                "Shared request-size sequence; investigate common tooling "
                "or a generated/test pattern. This does not prove C2 or "
                "successful data exfiltration."
            ),
        })

    return {
        "post_group_count": len(results),
        "shared_pattern_cluster_count": len(clusters),
        "groups": sorted(
            results,
            key=lambda item: item["request_count"],
            reverse=True,
        ),
        "shared_patterns": sorted(
            clusters,
            key=lambda item: item["group_count"],
            reverse=True,
        ),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--logs", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    log_dir = Path(args.logs)
    rows = read_zeek_tsv(log_dir / "http.log")
    if not rows:
        parser.error(f"No HTTP rows found in {log_dir / 'http.log'}")

    report = analyze(rows)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"POST groups: {report['post_group_count']}")
    print(f"Shared pattern clusters: {report['shared_pattern_cluster_count']}")
    print(f"JSON report: {out}")

    for cluster in report["shared_patterns"]:
        print(
            f"- groups={cluster['group_count']}; "
            f"hosts={len(cluster['distinct_hosts'])}; "
            f"total_observed_bytes="
            f"{cluster['total_observed_request_body_bytes']}"
        )
        print(f"  sizes={cluster['matching_size_sequence']}")


if __name__ == "__main__":
    main()
