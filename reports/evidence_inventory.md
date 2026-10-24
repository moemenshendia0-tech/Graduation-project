# Evidence and Duplicate-File Inventory

## Purpose

This document records known duplicate artifacts and their handling status.
No files are deleted or moved by this inventory.

## Duplicate-file pairs and latest equality check

| Copy A | Copy B | Handling |
|---|---|---|
| `evidence/detection_summary.txt` | `reports/detection_summary.txt` | DIFFER: report copy was updated; retain both pending final review. |
| `evidence/timeline_finding.txt` | `reports/timeline_finding.txt` | Retain pending final review. |
| `evidence/ioc_table.tsv` | `wireshark/ioc_table.tsv` | Retain pending final review. |
| `evidence/netsupport_http_timeline.tsv` | `wireshark/netsupport_http_timeline.tsv` | Retain pending final review. |
| `evidence/suspicious_http.tsv` | `wireshark/suspicious_http.tsv` | Retain both copies; headers are tab-separated. |
| `evidence/netsupport_timing_finding.txt` | `zeek/netsupport_timing_finding.txt` | Retain pending final review. |
| `evidence/netsupport_suricata_alerts.tsv` | `suricata/netsupport_alerts.tsv` | Retain pending final review. |
| `evidence/stream77.txt` | `evidence/stream77_full.txt` | Retain until their roles are confirmed. |

## Evidence limitations

- Latest SHA-256 comparison: seven listed pairs matched; the detection-summary pair differed after the report copy was updated. Recheck after future edits.
- An empty HTTP export alone does not prove that no application data was exchanged.
- NetSupport-like traffic is suspicious, but current findings alone do not confirm malicious use, command-and-control, or exfiltration.
- Distinguish direct observations from interpretations and hypotheses.
