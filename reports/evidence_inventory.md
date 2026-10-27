# Evidence and Duplicate-File Inventory

## Purpose

This document records known duplicate artifacts, the result of the latest comparison,
and how each pair is handled. No files are deleted or moved by this inventory.

## Duplicate-file pairs (comparison run 2026-10-27)

Method: `sha256sum` per pair; for `ioc_table.tsv`, `diff --strip-trailing-cr` as well.

| Copy A | Copy B | Result | Handling |
|---|---|---|---|
| `evidence/detection_summary.txt` | `reports/detection_summary.txt` | DIFFER | The `reports/` copy is current: it states the mean of the 51 in-range intervals (60.14 s) and the mean across all 57 intervals (55.51 s). The `evidence/` copy gives only the first value. Retain both; treat `reports/` as the reference. |
| `evidence/timeline_finding.txt` | `reports/timeline_finding.txt` | Identical hash | Retain pending final review. |
| `evidence/ioc_table.tsv` | `wireshark/ioc_table.tsv` | Differ only in line endings | The `wireshark/` copy uses CRLF; content is identical after `--strip-trailing-cr`. Retain both. |
| `evidence/netsupport_http_timeline.tsv` | `wireshark/netsupport_http_timeline.tsv` | Identical hash | Retain pending final review. |
| `evidence/suspicious_http.tsv` | `wireshark/suspicious_http.tsv` | Identical hash | Retain both copies; headers are tab-separated. |
| `evidence/netsupport_timing_finding.txt` | `zeek/netsupport_timing_finding.txt` | Identical hash | Retain pending final review. |
| `evidence/netsupport_suricata_alerts.tsv` | `suricata/netsupport_alerts.tsv` | Identical hash | Retain pending final review. |
| `evidence/stream77.txt` | `evidence/stream77_full.txt` | Identical hash (13,483 bytes each) | Retain until their roles are confirmed. Raw stream exports are ignored by Git. |

## Local-only duplicates (not tracked by Git)

| Location | Relation |
|---|---|
| `*.log` in the project root (18 files) | Duplicate of `zeek/baseline_zeek810_20261027/`. For `conn.log` and `http.log` the rows match (305 and 64 rows, same first timestamp 1732596578.458138) when Zeek headers and random UIDs are ignored. The other logs were not compared. |
| `*.backup_*`, `*.pre_finalize_backup`, `*.bak` | Backups made before report edits. Kept locally, not deleted. |

## Evidence limitations

- Raw `cmp` is not a valid test for two Zeek runs: each log header carries open/close
  times and UIDs are random. Compare content columns instead.
- Capture time: the capture starts at 2024-11-26 04:49:38 UTC (epoch 1732596578.458138).
  Local time on the analysis machine was UTC+2, so 06:49:38 in older notes is local time.
- TShark counts 74 HTTP requests while Zeek `http.log` has 64 rows. The tools count
  differently; quote the source with each number.
- An empty HTTP export alone does not prove that no application data was exchanged.
- NetSupport-like traffic is suspicious, but current findings alone do not confirm
  malicious use, command-and-control, or exfiltration.
- Distinguish direct observations from interpretations and hypotheses.
