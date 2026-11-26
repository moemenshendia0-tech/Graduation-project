#!/usr/bin/env python3
"""Generate evidence-linked, explainable findings from existing Zeek logs.

This is a project rule layer, distinct from Suricata engine alerts. It is
offline-only: IOC input is supplied as a local JSON file and no network lookups
or packet payload extraction are performed.
"""

import argparse
import hashlib
import ipaddress
import json
import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from detect_network_anomalies import number, parse_zeek_set, read_zeek_tsv, text_value, utc_time

DEFAULTS = {
    "window_seconds": 60,
    "scan_unique_ports": 20,
    "dns_min_queries": 10,
    "dns_min_unique_labels": 5,
    "dns_long_label_chars": 32,
    "dns_min_label_entropy": 3.5,
    "correlation_window_seconds": 3600,
}
HASH_PATTERNS = {
    "md5": re.compile(r"^[0-9a-fA-F]{32}$"),
    "sha1": re.compile(r"^[0-9a-fA-F]{40}$"),
    "sha256": re.compile(r"^[0-9a-fA-F]{64}$"),
}


def _rows(log_dir: Path, name: str) -> list[dict]:
    path = log_dir / f"{name}.log"
    rows = read_zeek_tsv(path, include_line_numbers=True)
    for row in rows:
        row["_evidence_ref"] = f"zeek/{path.name}#line={row.pop('_line_number')}"
    return rows


def _ref(row: dict, log_name: str) -> str:
    if row.get("_evidence_ref"):
        return str(row["_evidence_ref"])
    uid = text_value(row.get("uid"))
    if uid:
        return f"zeek/{log_name}.log#uid={uid}"
    digest = hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()
    return f"zeek/{log_name}.log#record-sha256={digest}"


def _alert(rule_id: str, title: str, severity: str, confidence: str, evidence: dict,
           rows: list[tuple[str, dict]], related_events: list[dict] | None = None) -> dict:
    refs = sorted({ _ref(row, log) for log, row in rows })
    timestamps = [number(row.get("ts"), None) for _, row in rows if row.get("ts") is not None]
    timestamps = [ts for ts in timestamps if ts is not None]
    first = min(timestamps) if timestamps else None
    last = max(timestamps) if timestamps else None
    anchor = rows[0][1] if rows else {}
    return {
        "timestamp_utc": utc_time(first) if first is not None else "",
        "first_seen_utc": utc_time(first) if first is not None else "",
        "last_seen_utc": utc_time(last) if last is not None else "",
        "source_tool": "ProjectDetector", "alert_origin": "project_generated",
        "detection_engine": "project-network-findings", "rule_id": rule_id,
        "severity": severity, "confidence": confidence, "title": title,
        "src_ip": text_value(anchor.get("id.orig_h")), "dst_ip": text_value(anchor.get("id.resp_h")),
        "src_port": anchor.get("id.orig_p"), "dst_port": anchor.get("id.resp_p"),
        "protocol": text_value(anchor.get("proto")), "uid": text_value(anchor.get("uid")),
        "evidence": json.dumps(evidence, sort_keys=True, ensure_ascii=False),
        "evidence_refs": refs, "related_events": related_events or [],
    }


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = defaultdict(int)
    for char in value.lower():
        counts[char] += 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def validate_ioc_document(document: object) -> list[dict]:
    if not isinstance(document, dict) or document.get("schema_version") != "1.0":
        raise ValueError("IOC document must be an object with schema_version '1.0'")
    provider, reference, retrieved_at = (document.get(k) for k in ("provider", "source_reference", "retrieved_at_utc"))
    indicators = document.get("indicators")
    if not all(isinstance(v, str) and v.strip() for v in (provider, reference, retrieved_at)):
        raise ValueError("IOC document requires provider, source_reference, and retrieved_at_utc")
    parsed_reference = urlsplit(reference)
    if parsed_reference.scheme.casefold() != "https" or not parsed_reference.netloc:
        raise ValueError("IOC source_reference must be an absolute HTTPS URL")
    try:
        timestamp = datetime.fromisoformat(retrieved_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("IOC retrieved_at_utc must be an ISO-8601 timestamp") from exc
    if timestamp.tzinfo is None:
        raise ValueError("IOC retrieved_at_utc must include a timezone")
    if not isinstance(indicators, list):
        raise ValueError("IOC document indicators must be a list")
    normalized = []
    for item in indicators:
        if not isinstance(item, dict):
            raise ValueError("Each IOC indicator must be an object")
        kind, value = item.get("type"), item.get("value")
        if kind not in {"ip", "domain", "url", "md5", "sha1", "sha256"} or not isinstance(value, str) or not value.strip():
            raise ValueError("IOC type/value is invalid")
        if kind in HASH_PATTERNS and not HASH_PATTERNS[kind].fullmatch(value):
            raise ValueError(f"IOC {kind} must have a valid hexadecimal length")
        if kind == "url":
            parsed = urlsplit(value)
            if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
                raise ValueError("IOC URL must be absolute and use HTTP or HTTPS")
        if kind == "ip":
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError("IOC IP indicator is malformed") from exc
        if kind == "domain" and (" " in value or value.startswith(".") or value.endswith("..")):
            raise ValueError("IOC domain indicator is malformed")
        normalized.append({"type": kind, "value": value if kind == "url" else value.casefold(), "provider": provider,
                           "source_reference": reference, "retrieved_at_utc": retrieved_at})
    return normalized


def prepare_output_dir(path: Path) -> Path:
    path = Path(path).expanduser().resolve()
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError(f"Refusing to use non-empty output path: {path}")
    path.mkdir(parents=True, exist_ok=True)
    return path


def _observed_values(logs: dict[str, list[dict]]) -> dict[str, list[tuple[str, str, dict]]]:
    values: dict[str, list[tuple[str, str, dict]]] = defaultdict(list)
    tls_uids = {str(row.get("uid")) for row in logs.get("ssl", []) if row.get("uid")}
    for name in ("conn", "http", "dns", "ssl", "files"):
        for row in logs.get(name, []):
            if name == "conn":
                values["ip"].extend((str(row[field]), name, row) for field in ("id.orig_h", "id.resp_h") if row.get(field))
            elif name == "http":
                if row.get("host"):
                    values["domain"].append((str(row["host"]), name, row))
                uri = str(row.get("uri") or "")
                if uri:
                    if uri.startswith(("http://", "https://")):
                        observed_url = uri
                    elif row.get("host"):
                        scheme = "https" if str(row.get("uid")) in tls_uids else "http"
                        observed_url = f"{scheme}://{row['host']}{uri if uri.startswith('/') else '/' + uri}"
                    else:
                        observed_url = uri
                    values["url"].append((observed_url, name, row))
            elif name == "dns" and row.get("query"):
                values["domain"].append((str(row["query"]), name, row))
            elif name == "ssl" and row.get("server_name"):
                values["domain"].append((str(row["server_name"]), name, row))
            elif name == "files":
                for algorithm, pattern in HASH_PATTERNS.items():
                    digest = row.get(algorithm)
                    if isinstance(digest, str) and pattern.fullmatch(digest):
                        values[algorithm].append((digest.casefold(), name, row))
    return values


def detect_findings(logs: dict[str, list[dict]], iocs: list[dict] | None = None,
                    config: dict | None = None) -> list[dict]:
    """Detect investigation leads from already-generated Zeek logs."""
    cfg = {**DEFAULTS, **(config or {})}
    findings = []

    # NET-007: DNS complexity/rate thresholds are configurable triage values,
    # not universal signatures for DNS tunneling.
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in logs.get("dns", []):
        query = str(row.get("query") or "").rstrip(".").casefold()
        if query:
            labels = query.split(".")
            suffix = ".".join(labels[-2:]) if len(labels) >= 2 else query
            groups[(text_value(row.get("id.orig_h")), suffix)].append(row)
    for (source, suffix), rows in sorted(groups.items()):
        times = sorted(number(row.get("ts")) for row in rows if row.get("ts") is not None)
        if not times:
            continue
        maximum = left = 0
        for right, current in enumerate(times):
            while current - times[left] > cfg["window_seconds"]:
                left += 1
            maximum = max(maximum, right - left + 1)
        labels = [str(row.get("query") or "").rstrip(".").split(".")[0] for row in rows]
        unique_labels = len(set(labels))
        max_label = max(map(len, labels), default=0)
        max_entropy = max((shannon_entropy(label) for label in labels), default=0.0)
        if (maximum < cfg["dns_min_queries"]
                and unique_labels < cfg["dns_min_unique_labels"]
                and max_label < cfg["dns_long_label_chars"]
                and max_entropy < cfg["dns_min_label_entropy"]):
            continue
        findings.append(_alert("NET-007", "Unusual DNS query complexity or rate", "low", "low",
            {"source_ip": source, "domain_suffix": suffix, "query_count": len(rows),
             "max_queries_in_window": maximum, "window_seconds": cfg["window_seconds"],
             "unique_first_labels": unique_labels, "maximum_first_label_length": max_label,
             "maximum_first_label_entropy_bits_per_character": round(max_entropy, 3),
             "thresholds": {k: cfg[k] for k in ("dns_min_queries", "dns_min_unique_labels", "dns_long_label_chars", "dns_min_label_entropy")},
             "interpretation": "Triage signal only; long or diverse DNS labels can be benign."}, [("dns", row) for row in rows]))

    # NET-008: connection-level broad port sweep. Zeek conn logs alone do not
    # establish SYN-only scanning or failed attempts.
    by_source: dict[str, list[dict]] = defaultdict(list)
    for row in logs.get("conn", []):
        if row.get("ts") is not None and row.get("id.orig_h") and row.get("id.resp_p") is not None:
            by_source[str(row["id.orig_h"])].append(row)
    for source, rows in sorted(by_source.items()):
        rows = sorted(rows, key=lambda row: number(row.get("ts")))
        left = 0
        port_counts = Counter()
        for right, row in enumerate(rows):
            current = number(row.get("ts"))
            while current - number(rows[left].get("ts")) > cfg["window_seconds"]:
                expired_port = str(rows[left].get("id.resp_p"))
                port_counts[expired_port] -= 1
                if port_counts[expired_port] == 0:
                    del port_counts[expired_port]
                left += 1
            port_counts[str(row.get("id.resp_p"))] += 1
            if len(port_counts) >= cfg["scan_unique_ports"]:
                window = rows[left:right + 1]
                first_by_port = {}
                for item in window:
                    first_by_port.setdefault(str(item.get("id.resp_p")), item)
                    if len(first_by_port) == len(port_counts):
                        break
                ports = sorted(first_by_port)
                findings.append(_alert("NET-008", "Broad destination-port sweep candidate", "medium", "low",
                    {"source_ip": source, "unique_destination_ports": ports,
                     "window_seconds": cfg["window_seconds"], "threshold": cfg["scan_unique_ports"],
                     "interpretation": "Connection records show a port sweep pattern; packet-level scan type is not inferred."},
                    [("conn", first_by_port[port]) for port in ports]))
                break

    # NET-009: observed administrative shares and RPC enumeration operations.
    smb_groups: dict[tuple[str, str], list[tuple[str, dict]]] = defaultdict(list)
    for row in logs.get("smb_mapping", []):
        path = str(row.get("path") or "").casefold()
        if "ipc$" in path or "admin$" in path:
            smb_groups[(text_value(row.get("id.orig_h")), text_value(row.get("id.resp_h")))].append(("smb_mapping", row))
    for row in logs.get("dce_rpc", []):
        operation = str(row.get("operation") or "").casefold()
        if "shareenum" in operation or "openscmanager" in operation or "enum" in operation:
            smb_groups[(text_value(row.get("id.orig_h")), text_value(row.get("id.resp_h")))].append(("dce_rpc", row))
    for row in logs.get("smb_files", []):
        path = str(row.get("path") or "").casefold()
        if "ipc$" in path or "admin$" in path:
            smb_groups[(text_value(row.get("id.orig_h")), text_value(row.get("id.resp_h")))].append(("smb_files", row))
    for (source, destination), rows in sorted(smb_groups.items()):
        operations = sorted({str(row.get("operation")) for log, row in rows if log == "dce_rpc" and row.get("operation")})
        shares = sorted({str(row.get("path")) for log, row in rows if log == "smb_mapping" and row.get("path")})
        file_observations = [{"action": row.get("action"), "path": row.get("path"),
                              "name": row.get("name"), "size": row.get("size")}
                             for log, row in rows if log == "smb_files"]
        findings.append(_alert("NET-009", "SMB share or RPC management enumeration observed", "medium", "medium",
            {"source_ip": source, "destination_ip": destination, "rpc_operations": operations,
             "share_paths": shares, "file_observations": file_observations,
             "interpretation": "Protocol observation for review; file events do not establish a write unless the log explicitly records one. Does not prove lateral movement or execution."}, rows))

    # NET-010: only an explicit SNI/certificate mismatch is flagged.
    for row in logs.get("ssl", []):
        if row.get("sni_matches_cert") not in (False, "F", 0):
            continue
        findings.append(_alert("NET-010", "TLS SNI does not match observed certificate metadata", "low", "low",
            {"server_name": row.get("server_name"), "sni_matches_cert": row.get("sni_matches_cert"),
             "version": row.get("version"), "interpretation": "Metadata mismatch is a triage signal, not proof of interception or malicious TLS."}, [("ssl", row)]))

    # NET-011: explicitly supplied, dated intelligence only; no live lookup.
    observed = _observed_values(logs)
    for ioc in iocs or []:
        for value, log, row in observed.get(ioc["type"], []):
            if ioc["type"] == "url":
                observed_url = urlsplit(value)
                wanted_url = urlsplit(ioc["value"])
                matches = (observed_url.scheme.casefold() == wanted_url.scheme.casefold()
                           and observed_url.netloc.casefold() == wanted_url.netloc.casefold()
                           and observed_url.path == wanted_url.path
                           and observed_url.query == wanted_url.query)
            else:
                matches = value.casefold().rstrip(".") == ioc["value"].casefold().rstrip(".")
            if not matches:
                continue
            findings.append(_alert("NET-011", "Observed indicator matches supplied intelligence", "medium", "medium",
                {"indicator_type": ioc["type"], "indicator": ioc["value"], "provider": ioc["provider"],
                 "source_reference": ioc["source_reference"], "retrieved_at_utc": ioc["retrieved_at_utc"],
                 "interpretation": "An intelligence match is not proof of compromise or execution."}, [(log, row)]))

    # NET-012: UID/FUID-based download-to-file linkage plus later connections.
    files_by_pair = defaultdict(list)
    for row in logs.get("files", []):
        uid, fuid = text_value(row.get("uid")), text_value(row.get("fuid"))
        if uid and fuid:
            files_by_pair[(uid, fuid)].append(row)
    conns_by_source = defaultdict(list)
    for row in logs.get("conn", []):
        conns_by_source[str(row.get("id.orig_h") or "")].append(row)
    for http in logs.get("http", []):
        mime = str(http.get("resp_mime_types") or "").casefold()
        uri = str(http.get("uri") or "").split("?", 1)[0].casefold()
        if http.get("status_code") not in (200, 206) or not ("x-dosexec" in mime or uri.endswith((".exe", ".dll", ".msi", ".scr"))):
            continue
        uid, host = text_value(http.get("uid")), str(http.get("id.orig_h") or "")
        if not uid or not host or http.get("ts") is None:
            continue
        related_files = [f for fuid in parse_zeek_set(http.get("resp_fuids")) for f in files_by_pair.get((uid, fuid), [])]
        if not related_files:
            continue
        downloaded_at = number(http.get("ts"))
        later = [conn for conn in conns_by_source.get(host, []) if downloaded_at < number(conn.get("ts")) <= downloaded_at + cfg["correlation_window_seconds"]]
        if not later:
            continue
        file_hashes = []
        for f in related_files:
            for algorithm, pattern in HASH_PATTERNS.items():
                value = f.get(algorithm)
                if isinstance(value, str) and pattern.fullmatch(value):
                    file_hashes.append({"algorithm": algorithm, "value": value.casefold()})
        later = sorted(later, key=lambda r: (number(r.get("ts")), text_value(r.get("uid"))))
        related_events = [{"uid": text_value(row.get("uid")), "src_ip": row.get("id.orig_h"),
                           "dst_ip": row.get("id.resp_h"), "dst_port": row.get("id.resp_p"),
                           "timestamp_utc": utc_time(row.get("ts")), "evidence_ref": _ref(row, "conn")} for row in later]
        rows = [("http", http)] + [("files", f) for f in related_files] + [("conn", row) for row in later]
        findings.append(_alert("NET-012", "Executable transfer has temporally subsequent network activity", "medium", "low",
            {"download_uid": uid, "file_ids": sorted({text_value(f.get("fuid")) for f in related_files}),
             "observed_file_hashes": file_hashes, "follow_on_connection_count": len(later),
             "correlation_window_seconds": cfg["correlation_window_seconds"],
             "interpretation": "Temporal correlation only; process telemetry does not establish that the file caused later connections."}, rows, related_events))

    unique = {(item["rule_id"], tuple(item["evidence_refs"])): item for item in findings}
    return sorted(unique.values(), key=lambda item: (item["timestamp_utc"], item["rule_id"], item["evidence_refs"]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--logs", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--iocs", type=Path, help="Optional local attributed IOC JSON; no network lookup")
    parser.add_argument("--window-seconds", type=int, default=DEFAULTS["window_seconds"])
    parser.add_argument("--scan-unique-ports", type=int, default=DEFAULTS["scan_unique_ports"])
    parser.add_argument("--dns-min-queries", type=int, default=DEFAULTS["dns_min_queries"])
    parser.add_argument("--dns-min-unique-labels", type=int, default=DEFAULTS["dns_min_unique_labels"])
    parser.add_argument("--dns-long-label-chars", type=int, default=DEFAULTS["dns_long_label_chars"])
    parser.add_argument("--dns-min-label-entropy", type=float, default=DEFAULTS["dns_min_label_entropy"])
    parser.add_argument("--correlation-window-seconds", type=int, default=DEFAULTS["correlation_window_seconds"])
    args = parser.parse_args()
    if (args.window_seconds < 1 or args.scan_unique_ports < 2 or args.dns_min_queries < 1
            or args.dns_min_unique_labels < 1 or args.dns_long_label_chars < 1
            or args.dns_min_label_entropy < 0 or args.correlation_window_seconds < 1):
        parser.error("Detection thresholds must be positive (scan ports >= 2; entropy >= 0)")
    log_dir, out_dir = args.logs.expanduser().resolve(), args.out.expanduser().resolve()
    if not log_dir.is_dir():
        parser.error("Zeek log directory does not exist")
    names = ("conn", "http", "dns", "files", "ssl", "smb_mapping", "dce_rpc", "smb_files")
    logs = {name: _rows(log_dir, name) for name in names}
    iocs = []
    if args.iocs:
        try:
            document = json.loads(args.iocs.expanduser().resolve().read_text(encoding="utf-8"))
            iocs = validate_ioc_document(document)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            parser.error(f"Invalid local IOC file: {exc}")
    config = {key: getattr(args, key) for key in DEFAULTS}
    findings = detect_findings(logs, iocs, config)
    try:
        out_dir = prepare_output_dir(out_dir)
    except ValueError as exc:
        parser.error(str(exc))
    payload = {"tool": "project-network-findings", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
               "alert_origin": "project_generated", "alert_count": len(findings), "alerts": findings,
               "disclaimer": "Findings are evidence-linked investigation leads, not proof of compromise, C2, execution, or exfiltration."}
    (out_dir / "findings.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Project findings: {len(findings)}")
    print(f"JSON: {out_dir / 'findings.json'}")


if __name__ == "__main__":
    main()
