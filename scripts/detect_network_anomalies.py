#!/usr/bin/env python3
"""Offline detection engine for Zeek TSV logs.

Reads conn.log, http.log, dns.log and files.log and writes explainable
candidate alerts. Alerts are leads for investigation, not verdicts.
Source evidence is read-only; this script does not execute samples.
"""

import argparse
import csv
import json
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".msi", ".scr", ".ps1", ".bat", ".com")


def parse_value(value):
    if value in ("", "-", "(empty)"):
        return None
    if value == "T":
        return True
    if value == "F":
        return False
    try:
        return float(value) if any(c in value for c in ".eE") else int(value)
    except (ValueError, TypeError):
        return value


def read_zeek_tsv(path):
    """Read Zeek TSV using its #fields metadata, tolerating malformed rows."""
    path = Path(path)
    if not path.is_file() or path.stat().st_size == 0:
        return []

    fields = []
    rows = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not fields:
                continue
            values = line.split("\t")
            if len(values) != len(fields):
                continue
            rows.append({key: parse_value(value) for key, value in zip(fields, values)})
    return rows


def number(value, default=0.0):
    try:
        return float(value) if value is not None else default
    except (ValueError, TypeError):
        return default


def utc_time(value):
    try:
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError, OverflowError):
        return ""


def text_value(value, default=""):
    if value is None or value == "-":
        return default
    return str(value)


def parse_zeek_set(value):
    """Normalize Zeek set/vector fields such as resp_fuids to a list of IDs."""
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        raw_items = value
    else:
        string = str(value).strip()
        if string in ("", "-", "(empty)"):
            return []
        string = string.strip("[]{}")
        raw_items = string.split(",")

    result = []
    for item in raw_items:
        normalized = str(item).strip().strip("\"'")
        if normalized and normalized not in ("-", "(empty)") and normalized not in result:
            result.append(normalized)
    return result


def make_alert(
    rule_id,
    severity,
    confidence,
    title,
    evidence,
    row=None,
    src=None,
    dst=None,
    port=None,
    ts=None,
    uid=None,
    first_seen_ts=None,
    last_seen_ts=None,
):
    row = row or {}
    timestamp_value = ts if ts is not None else row.get("ts")
    alert = {
        "timestamp_utc": utc_time(timestamp_value),
        "rule_id": rule_id,
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "src_ip": src if src is not None else text_value(row.get("id.orig_h")),
        "dst_ip": dst if dst is not None else text_value(row.get("id.resp_h")),
        "dst_port": port if port is not None else text_value(row.get("id.resp_p")),
        "uid": uid if uid is not None else text_value(row.get("uid")),
        "evidence": evidence,
    }
    # Aggregate alerts represent time ranges, not a single connection/event.
    if first_seen_ts is not None:
        alert["first_seen_utc"] = utc_time(first_seen_ts)
    if last_seen_ts is not None:
        alert["last_seen_utc"] = utc_time(last_seen_ts)
    return alert


def detect(http_rows, conn_rows, dns_rows, file_rows):
    alerts = []
    # Keep event-to-alert associations out-of-band so source rows aren't emitted
    # into JSON and multiple HTTP requests sharing a connection UID don't clobber
    # one another during file correlation.
    http_row_for_alert = {}
    file_pair_for_alert = {}

    # NET-001: Possible executable download over HTTP.
    for row in http_rows:
        uri = str(row.get("uri") or "")
        mime = str(row.get("resp_mime_types") or "").lower()
        status = row.get("status_code")
        uri_path = uri.split("?", 1)[0].lower()
        executable = (
            uri_path.endswith(EXECUTABLE_EXTENSIONS)
            or any(marker in mime for marker in (
                "x-dosexec", "x-msdownload", "vnd.microsoft.portable-executable"
            ))
        )
        if executable and status in (None, 200, 206):
            alert = make_alert(
                "NET-001", "high", "medium",
                "Possible executable download over HTTP",
                (f"method={row.get('method')}; uri={uri}; "
                 f"status={status}; mime={mime or 'unknown'}; "
                 f"user_agent={row.get('user_agent') or 'unknown'}"),
                row=row,
            )
            alerts.append(alert)
            http_row_for_alert[id(alert)] = row

    # NET-002: Repeated POSTs with notable aggregate request volume.
    post_groups = defaultdict(list)
    for row in http_rows:
        if str(row.get("method") or "").upper() != "POST":
            continue
        key = (
            row.get("id.orig_h"), row.get("id.resp_h"),
            row.get("host"), row.get("uri"), row.get("id.resp_p"),
        )
        post_groups[key].append(row)

    for key, group in post_groups.items():
        total_bytes = sum(number(row.get("request_body_len")) for row in group)
        if len(group) < 5 or total_bytes < 100_000:
            continue
        src, dst, host, uri, port = key
        times = [number(row.get("ts")) for row in group if row.get("ts") is not None]
        if not times:
            continue
        first_ts, last_ts = min(times), max(times)
        unique_uids = {
            str(row.get("uid")) for row in group
            if row.get("uid") not in (None, "", "-")
        }
        alerts.append(make_alert(
            "NET-002", "medium", "medium",
            "Repeated HTTP POSTs with notable request volume",
            (f"count={len(group)}; unique_uids={len(unique_uids)}; "
             f"total_request_body_bytes={int(total_bytes)}; "
             f"host={host or 'unknown'}; uri={uri or 'unknown'}. "
             "Investigate payload and endpoint context before classifying as exfiltration."),
            row={}, src=src, dst=dst, port=port, ts=first_ts, uid="",
            first_seen_ts=first_ts, last_seen_ts=last_ts,
        ))

    # NET-003: Candidate periodic connections. This aggregates connections by
    # endpoint/protocol and therefore remains a low-confidence lead.
    connection_groups = defaultdict(list)
    for row in conn_rows:
        if row.get("ts") is None:
            continue
        protocol = str(row.get("proto") or "").lower()
        port = str(row.get("id.resp_p") or "")
        destination = str(row.get("id.resp_h") or "")
        if protocol == "udp" and port in {"137", "138"}:
            continue
        # Heuristic only; not a universal broadcast-address test.
        if protocol == "udp" and destination.endswith(".255"):
            continue
        if not row.get("id.orig_h") or not row.get("id.resp_h") or not port or not protocol:
            continue
        key = (row.get("id.orig_h"), row.get("id.resp_h"), row.get("id.resp_p"), row.get("proto"))
        connection_groups[key].append(row)

    for key, group in connection_groups.items():
        if len(group) < 6:
            continue
        times = sorted(number(row.get("ts")) for row in group if row.get("ts") is not None)
        intervals = [later - earlier for earlier, later in zip(times, times[1:]) if later > earlier]
        if len(intervals) < 5:
            continue
        median_interval = statistics.median(intervals)
        if median_interval <= 0 or median_interval > 3600:
            continue
        mad = statistics.median(abs(interval - median_interval) for interval in intervals)
        if mad / median_interval > 0.20:
            continue

        src, dst, port, protocol = key
        unique_uids = {
            str(row.get("uid")) for row in group
            if row.get("uid") not in (None, "", "-")
        }
        alerts.append(make_alert(
            "NET-003", "medium", "low", "Candidate periodic connection",
            (f"observations={len(times)}; unique_uids={len(unique_uids)}; "
             f"median_interval_seconds={median_interval:.2f}; "
             f"median_absolute_deviation_seconds={mad:.2f}; protocol={protocol}. "
             "Periodicity alone does not prove C2."),
            row={}, src=src, dst=dst, port=port, ts=times[0], uid="",
            first_seen_ts=times[0], last_seen_ts=times[-1],
        ))

    # NET-004: Large client-to-server transfer candidate.
    for row in conn_rows:
        orig_bytes = number(row.get("orig_bytes"))
        resp_bytes = number(row.get("resp_bytes"))
        if orig_bytes >= 1_000_000 and orig_bytes > max(resp_bytes * 3, 500_000):
            alerts.append(make_alert(
                "NET-004", "medium", "low",
                "Large client-to-server transfer candidate",
                (f"orig_bytes={int(orig_bytes)}; resp_bytes={int(resp_bytes)}; "
                 f"protocol={row.get('proto')}; service={row.get('service') or 'unknown'}; "
                 f"state={row.get('conn_state') or 'unknown'}. "
                 "Validate byte direction and expected application behavior."),
                row=row,
            ))

    # NET-005: Repeated DNS queries; volume-only heuristic, not DNS-tunneling proof.
    dns_groups = defaultdict(list)
    for row in dns_rows:
        query = row.get("query")
        if query:
            dns_groups[(row.get("id.orig_h"), query)].append(row)
    for (src, query), group in dns_groups.items():
        if len(group) < 20:
            continue
        times = [number(row.get("ts")) for row in group if row.get("ts") is not None]
        if not times:
            continue
        alerts.append(make_alert(
            "NET-005", "low", "low", "Repeated DNS query candidate",
            (f"query={query}; count={len(group)}. Review query length, subdomain diversity, "
             "response codes, and baseline before assessing tunneling."),
            src=src, ts=min(times),
        ))

    # NET-006: PE/executable observed in network traffic.
    for row in file_rows:
        analyzers = str(row.get("analyzers") or "").lower()
        mime = str(row.get("mime_type") or "").lower()
        filename = str(row.get("filename") or "")
        is_pe = (
            "pe" in analyzers or "x-dosexec" in mime
            or filename.lower().endswith((".exe", ".dll"))
        )
        if not is_pe:
            continue
        fuid = text_value(row.get("fuid"))
        uid = text_value(row.get("uid"))
        src = text_value(row.get("id.orig_h"))
        dst = text_value(row.get("id.resp_h"))
        alert = make_alert(
            "NET-006", "medium", "medium", "PE/executable file observed in network traffic",
            (f"fuid={fuid or 'unknown'}; uid={uid or 'unknown'}; "
             f"filename={filename or 'unknown'}; mime={mime or 'unknown'}; "
             f"analyzers={analyzers or 'unknown'}; seen_bytes={row.get('seen_bytes')}; "
             f"total_bytes={row.get('total_bytes')}. Network observation does not prove endpoint execution."),
            row=row, src=src, dst=dst, port=row.get("id.resp_p", ""),
            ts=row.get("ts"), uid=uid,
        )
        alert["fuid"] = fuid
        alerts.append(alert)
        file_pair_for_alert[id(alert)] = (uid, fuid)

    # Precise correlation: each download alert retains its own originating HTTP
    # row. Match response FUID + files.log UID + files.log FUID; do not use a
    # one-row-per-UID dictionary and do not suppress unrelated NET-006 alerts.
    file_rows_by_pair = defaultdict(list)
    for row in file_rows:
        uid = text_value(row.get("uid"))
        fuid = text_value(row.get("fuid"))
        if uid and fuid:
            file_rows_by_pair[(uid, fuid)].append(row)

    net006_by_pair = defaultdict(list)
    for alert in alerts:
        if alert["rule_id"] == "NET-006":
            pair = file_pair_for_alert.get(id(alert))
            if pair and all(pair):
                net006_by_pair[pair].append(alert)

    merged_file_alert_ids = set()
    for download in alerts:
        if download["rule_id"] != "NET-001":
            continue
        http_row = http_row_for_alert.get(id(download))
        if not http_row:
            continue
        uid = text_value(http_row.get("uid"))
        if not uid:
            continue

        response_fuids = parse_zeek_set(http_row.get("resp_fuids"))
        matched = []
        matched_pairs = set()
        for fuid in response_fuids:
            pair = (uid, fuid)
            # Require UID and FUID agreement in files.log. A matching FUID by
            # itself is insufficient to establish that it belongs to this HTTP event.
            matching_rows = file_rows_by_pair.get(pair, [])
            matching_alerts = net006_by_pair.get(pair, [])
            if not matching_rows or not matching_alerts:
                continue
            matched_pairs.add(pair)
            for file_row in matching_rows:
                matched.append({
                    "uid": uid,
                    "fuid": fuid,
                    "filename": file_row.get("filename") or "unknown",
                    "mime": file_row.get("mime_type") or "unknown",
                    "seen_bytes": file_row.get("seen_bytes"),
                    "total_bytes": file_row.get("total_bytes"),
                })
            for file_alert in matching_alerts:
                merged_file_alert_ids.add(id(file_alert))

        if not matched:
            continue
        # Remove duplicate evidence entries while preserving deterministic output.
        deduped = []
        seen_evidence = set()
        for item in matched:
            key = (item["uid"], item["fuid"], item["filename"], item["mime"], item["seen_bytes"], item["total_bytes"])
            if key not in seen_evidence:
                seen_evidence.add(key)
                deduped.append(item)
        download["correlation"] = "matched_http_uid_and_response_fuid_and_files_uid"
        download["related_rule_id"] = "NET-006"
        download["related_fuid"] = ",".join(sorted({item["fuid"] for item in deduped}))
        download["related_uid"] = uid
        download["related_file_evidence"] = deduped
        download["title"] = "HTTP executable download with correlated file observation"
        details = "; ".join(
            f"uid={item['uid']}, fuid={item['fuid']}, filename={item['filename']}, "
            f"mime={item['mime']}, seen_bytes={item['seen_bytes']}, total_bytes={item['total_bytes']}"
            for item in deduped
        )
        download["evidence"] += " | Correlated Zeek file observation: " + details + ". File observation does not prove endpoint execution."

    # Suppress only the NET-006 records actually merged into a NET-001.
    alerts = [alert for alert in alerts if id(alert) not in merged_file_alert_ids]

    # De-duplicate exact alerts. Keep related FUIDs in the key so distinct file
    # correlations cannot be collapsed into one record.
    unique = {}
    for item in alerts:
        key = (
            item["rule_id"], item["timestamp_utc"], item["src_ip"],
            item["dst_ip"], str(item["dst_port"]), item["uid"],
            item.get("related_fuid", ""), item["evidence"],
        )
        unique[key] = item

    return sorted(unique.values(), key=lambda item: (item["timestamp_utc"], item["rule_id"]))


def main():
    parser = argparse.ArgumentParser(description="Generate candidate alerts from Zeek TSV logs.")
    parser.add_argument("--logs", required=True, help="Directory containing Zeek log files")
    parser.add_argument("--out", default="detection-output", help="Output directory for CSV and JSON")
    args = parser.parse_args()

    log_dir = Path(args.logs).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()
    if not log_dir.is_dir():
        parser.error(f"Logs directory does not exist: {log_dir}")

    logs = {
        "http": read_zeek_tsv(log_dir / "http.log"),
        "conn": read_zeek_tsv(log_dir / "conn.log"),
        "dns": read_zeek_tsv(log_dir / "dns.log"),
        "files": read_zeek_tsv(log_dir / "files.log"),
    }
    if not any(logs.values()):
        parser.error("No Zeek rows found. Check the directory and log filenames.")

    results = detect(logs["http"], logs["conn"], logs["dns"], logs["files"])
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "alerts.json"
    csv_path = out_dir / "alerts.csv"
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump({
            "tool": "offline-zeek-detection-engine",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "input_counts": {name: len(rows) for name, rows in logs.items()},
            "alert_count": len(results),
            "alerts": results,
            "disclaimer": "Alerts are investigation leads, not proof of compromise, C2, or exfiltration.",
        }, handle, indent=2)

    columns = [
        "timestamp_utc", "first_seen_utc", "last_seen_utc", "rule_id", "severity",
        "confidence", "title", "src_ip", "dst_ip", "dst_port", "uid",
        "correlation", "related_rule_id", "related_fuid", "related_uid", "evidence",
    ]
    with csv_path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    print("Input rows:")
    for name, rows in logs.items():
        print(f"  {name}: {len(rows)}")
    print(f"Candidate alerts: {len(results)}")
    print(f"CSV report:  {csv_path}")
    print(f"JSON report: {json_path}")
    print("Alerts are investigation leads and require validation.")


if __name__ == "__main__":
    main()
