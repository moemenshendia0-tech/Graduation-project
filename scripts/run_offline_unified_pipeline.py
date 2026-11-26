#!/usr/bin/env python3
"""Run Zeek and Suricata offline on one PCAP and merge candidate alerts."""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = Path("/etc/suricata/suricata.yaml")
DEFAULT_RULES = Path("/var/lib/suricata/rules/suricata.rules")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact_metadata(path):
    path = Path(path)
    return {
        "path": str(path),
        "sha256": sha256(path),
        "size_bytes": path.stat().st_size,
    }


DEFAULT_COMMAND_TIMEOUT_SECONDS = 900


def run(command, cwd=None, timeout_seconds=DEFAULT_COMMAND_TIMEOUT_SECONDS):
    command = [str(part) for part in command]
    if timeout_seconds <= 0:
        raise ValueError("Command timeout must be a positive number of seconds")
    try:
        result = subprocess.run(command, cwd=cwd, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, check=False, timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        executable = Path(command[0]).name if command else "unknown command"
        raise RuntimeError(
            f"Command timed out after {timeout_seconds} seconds: {executable}"
        ) from exc
    if result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {command!r}\n{result.stdout[-8000:]}")
    return result.stdout.strip()


def create_output_dir(requested):
    if requested is None:
        return Path(tempfile.mkdtemp(prefix="offline-unified-pipeline-")).resolve()
    output = requested.expanduser().resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError(f"Refusing to use non-empty output path: {output}")
    output.mkdir(parents=True, exist_ok=True)
    return output


def run_pipeline(pcap, output_dir=None, zeek_bin="zeek", suricata_bin="suricata",
                 suricata_config=DEFAULT_CONFIG, suricata_rules=DEFAULT_RULES, iocs_file=None,
                 command_timeout_seconds=DEFAULT_COMMAND_TIMEOUT_SECONDS):
    if command_timeout_seconds <= 0:
        raise ValueError("Command timeout must be a positive number of seconds")
    pcap = Path(pcap).expanduser().resolve()
    config = Path(suricata_config).expanduser().resolve()
    rules = Path(suricata_rules).expanduser().resolve()
    iocs_path = Path(iocs_file).expanduser().resolve() if iocs_file else None
    if not pcap.is_file():
        raise ValueError(f"PCAP not found: {pcap}")
    if not config.is_file():
        raise ValueError(f"Suricata configuration not found: {config}")
    if not rules.is_file():
        raise ValueError(f"Suricata rules file not found: {rules}")
    if iocs_path is not None and not iocs_path.is_file():
        raise ValueError("Local IOC document not found")
    binaries = {name: shutil.which(binary) for name, binary in
                (("zeek", zeek_bin), ("suricata", suricata_bin))}
    missing = [name for name, path in binaries.items() if path is None]
    if missing:
        raise ValueError(f"Required executable(s) not found on PATH: {', '.join(missing)}")

    output = create_output_dir(output_dir)
    zeek_dir, suricata_dir = output / "zeek", output / "suricata"
    zeek_dir.mkdir()
    suricata_dir.mkdir()
    parameters = {
        "zeek": [binaries["zeek"], "-r", str(pcap)],
        "suricata": [binaries["suricata"], "-c", str(config), "-S", str(rules),
                     "-r", str(pcap), "-l", str(suricata_dir)],
    }
    manifest = {
        "tool": "offline-pcap-to-unified-alerts", "status": "running",
        "started_at_utc": utc_now(),
        "pcap": {"path": str(pcap), "sha256": sha256(pcap), "size_bytes": pcap.stat().st_size},
        "tools": {}, "configuration": {}, "execution_parameters": parameters,
    }
    manifest_path = output / "run_manifest.json"
    try:
        manifest["tools"] = {
            "zeek": run([binaries["zeek"], "--version"], timeout_seconds=command_timeout_seconds).splitlines()[0],
            "suricata": run([binaries["suricata"], "--build-info"], timeout_seconds=command_timeout_seconds).splitlines()[0],
            "python": sys.version.split()[0],
        }
        manifest["configuration"] = {
            "suricata_yaml": {"path": str(config), "sha256": sha256(config)},
            "suricata_rules": {"path": str(rules), "sha256": sha256(rules)},
        }
        if iocs_path is not None:
            manifest["configuration"]["local_iocs"] = {
                "path": str(iocs_path), "sha256": sha256(iocs_path),
            }
        run(parameters["zeek"], cwd=zeek_dir, timeout_seconds=command_timeout_seconds)
        eve = suricata_dir / "eve.json"
        run(parameters["suricata"], timeout_seconds=command_timeout_seconds)
        if not eve.is_file():
            raise RuntimeError(f"Suricata completed without creating EVE output: {eve}")
        zeek_out, suricata_out, unified_out = (output / name for name in
                                                ("zeek_adapter", "suricata_adapter", "unified"))
        project_out = output / "project_findings"
        run([sys.executable, ROOT / "scripts/detect_network_anomalies.py",
             "--logs", zeek_dir, "--out", zeek_out], timeout_seconds=command_timeout_seconds)
        run([sys.executable, ROOT / "scripts/parse_suricata_eve.py",
             "--eve", eve, "--out", suricata_out], timeout_seconds=command_timeout_seconds)
        project_command = [sys.executable, ROOT / "scripts/detect_project_findings.py",
                           "--logs", zeek_dir, "--out", project_out]
        if iocs_path is not None:
            project_command.extend(("--iocs", iocs_path))
        run(project_command, timeout_seconds=command_timeout_seconds)
        run([sys.executable, ROOT / "scripts/merge_detection_alerts.py",
             "--zeek", zeek_out / "alerts.json", "--suricata",
             suricata_out / "alerts.json", "--project-findings",
             project_out / "findings.json", "--out", unified_out],
            timeout_seconds=command_timeout_seconds)
        with (zeek_out / "alerts.json").open(encoding="utf-8") as stream:
            zeek_payload = json.load(stream)
        with (suricata_out / "alerts.json").open(encoding="utf-8") as stream:
            suricata_payload = json.load(stream)
        with (unified_out / "alerts.json").open(encoding="utf-8") as stream:
            unified_payload = json.load(stream)
        with (project_out / "findings.json").open(encoding="utf-8") as stream:
            project_payload = json.load(stream)
        expected_alert_total = (zeek_payload["alert_count"] + suricata_payload["alert_count"]
                                + project_payload["alert_count"])
        if unified_payload.get("alert_count") != expected_alert_total:
            raise RuntimeError("Unified alert merge count does not match its source alert counts")
        manifest["inputs"] = {
            "zeek": zeek_payload.get("input_counts", {}),
            "suricata": {key: suricata_payload.get(key) for key in
                         ("event_counts", "malformed_lines", "invalid_shape_records", "invalid_optional_fields")},
        }
        manifest["alert_counts"] = {
            "zeek": zeek_payload["alert_count"],
            "suricata": suricata_payload["alert_count"],
            "unified": unified_payload["alert_count"],
            "project_findings": project_payload["alert_count"],
        }
        manifest["artifacts"] = {
            "zeek_alerts_json": artifact_metadata(zeek_out / "alerts.json"),
            "zeek_alerts_csv": artifact_metadata(zeek_out / "alerts.csv"),
            "suricata_alerts_json": artifact_metadata(suricata_out / "alerts.json"),
            "suricata_alerts_csv": artifact_metadata(suricata_out / "alerts.csv"),
            "unified_json": artifact_metadata(unified_out / "alerts.json"),
            "unified_csv": artifact_metadata(unified_out / "alerts.csv"),
            "project_findings_json": artifact_metadata(project_out / "findings.json"),
        }
        manifest["status"] = "complete"
    except Exception as exc:
        manifest["status"] = "failed"
        manifest["error"] = str(exc)
        raise
    finally:
        manifest["finished_at_utc"] = utc_now()
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Run manifest: {manifest_path}")
    print(f"Unified JSON: {manifest['artifacts']['unified_json']['path']}")
    print(f"Unified CSV:  {manifest['artifacts']['unified_csv']['path']}")
    print(f"Alert counts: {manifest['alert_counts']}")
    return manifest


def positive_int(value):
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--out", type=Path, help="Output path; default is a unique system temp directory")
    parser.add_argument("--zeek-bin", default="zeek")
    parser.add_argument("--suricata-bin", default="suricata")
    parser.add_argument("--suricata-config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--suricata-rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--iocs", type=Path, help="Optional local attributed IOC JSON; no external lookups")
    parser.add_argument("--command-timeout-seconds", type=positive_int,
                        default=DEFAULT_COMMAND_TIMEOUT_SECONDS,
                        help="Maximum duration for each pipeline command (default: 900)")
    args = parser.parse_args()
    try:
        run_pipeline(args.pcap, args.out, args.zeek_bin, args.suricata_bin,
                     args.suricata_config, args.suricata_rules, args.iocs,
                     args.command_timeout_seconds)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
