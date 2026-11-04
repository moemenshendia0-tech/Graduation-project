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


## 3. Investigation Evidence Register

This register summarizes the principal reviewed captures and their supporting
artifacts. Hashes are included only where a recorded value is available.
A sample hash must not be confused with its source PCAP hash.

| Investigation / source | Hash and scope | Tools and recorded analysis | Observed result | Interpretation and limitations |
|---|---|---|---|---|
| NetSupport baseline — `pcaps/baseline.pcap` | PCAP SHA-256: `a38267943a7bf3b0e445d7e51cb0a68b3dee797d67081bc9a033f73d079c0f50` | TShark HTTP request filter; Zeek `http.log` and `conn.log`; Suricata NetSupport and HTTP POST alerts; RITA `show-beacons-sni` | Internal host `10.11.26.183` contacted `194.180.191.64:443`; 58 HTTP POSTs were recorded by Zeek; RITA `show-beacons` returned no row; `show-beacons-sni` returned score 0.968 for 58 connections (average 15,882 bytes; total 921,162 bytes; most frequent interval 60 seconds). MongoDB `beaconSNI` record confirms the result; its `fqdn` field is the IP literal `194.180.191.64`. | Suspicious repeated remote-administration-like traffic. RITA's `uconn` aggregation is separate from `beaconSNI` and reports a grouped count of 2; these counts are not interchangeable. The stored import MD5 values differ from the current Zeek files, so byte-for-byte identity of the imported baseline inputs is not established. Does not independently prove unauthorized access, execution, compromise, C2, or exfiltration. TShark's recorded HTTP count is 74; Zeek's is 64 rows. These are different tool counts. |
| FormBook-related traffic — `2026-08-09-traffic-analysis-exercise.pcap` | PCAP SHA-256: `0ea6b597732a9ce6af9a7e3adff4512c9a91b4bce27184c8fdeb746f05cce170` | Zeek HTTP records; review of HTTP POST destinations, URIs, and User-Agent | Source `172.16.8.49` sent POST requests to `146.59.71.167` (`/irpw/`), `38.182.168.246` (`/lqjm/`), and `45.130.41.161` (`/8nw8/`) as three examples (the full report lists 15 destination groups, 113 POSTs and GET check-ins); Firefox 39 / Windows NT 6.2 User-Agent | FormBook-related suspicious HTTP activity documented in the dedicated report. The observed requests alone do not establish the exact data submitted, successful infection, or endpoint execution. |
| Runner executable download — `2026-10-01-traffic-analysis-exercise.pcap` | PCAP SHA-256: `287d6dee90cfef71f98a97c42e30444608de2cf59d2f7392a0a6df8dbbc8274b` (from the batch summary). Extracted executable SHA-256: `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061` | HTTP response and object extraction documented in `reports/incident_runner_ilove.md` | `10.10.1.128` received HTTP 200 for `/wilow/runner_ilove.exe` from `107.175.82.242:9000`; response body 1,646,592 bytes. Later traffic to `195.63.128.106:443` was observed | Suspicious executable transfer. The packet evidence does not prove execution or that the later connection was caused by the executable. Endpoint/process correlation remains outstanding. |
| WebInvestigation — `WebInvestigation.pcap` | PCAP SHA-256: `cf31ec09cf2ece5d0a55c750a0fee19af3ab34d4b7125c4781a56025e2721647` | HTTP request/response review; SQLmap and Gobuster traffic review; Suricata default and adjusted HOME_NET runs | SQL injection and directory enumeration indicators, login response 302, and upload of `NVri2vhp.php`; a 79-byte extracted part contains PHP and command-execution-related strings. Suricata produced 0 alerts with the reviewed default HOME_NET and 210 with `HOME_NET=73.124.22.0/24` | Draft investigation. Successful PHP execution, server compromise, callback, and exfiltration are not established. The HOME_NET difference indicates a detection-configuration limitation. |
| Netmetria — `netmetria-focused-scenario.pcap` | PCAP SHA-256: `84e66539101bcf14d28ca97c26674096f4afc53e9370a5dd0ef77069cdf850e6` | Zeek SMB records and Suricata alerts; SMB operation sequence reviewed in the dedicated report | Host `10.42.10.21` performed IPC$ access and share enumeration against multiple hosts, followed by service-control-related requests and 96-byte writes to `q4-summary.bin` on multiple targets | Draft investigation. The sequence may resemble lateral-movement staging, but service creation/start, successful lateral movement, account identity, C2, and exfiltration are not established. |
| Benign lab simulation — generated capture under `simulations/lab_sim/` | Capture SHA-256 `12b9dc61ca65cd902c00758d72ea54cdc437844d8d90393204b4e6e65a554de3` (from `SHA256SUMS` in the run directory); run artifacts are retained in the timestamped run directory | Nmap, tcpdump, Zeek, Suricata; custom DNS/HTTP lab services | 2,635 packets over approximately 74.52 seconds; DNS and HTTP activity; 20 HTTP POST requests with 262,144-byte transfers and HTTP 200 responses | Controlled benign simulation. Observed DNS volume differed from the requested count; checksum alerts and port ownership require cautious interpretation. This is not evidence of malicious C2, DNS tunneling, or real-world exfiltration. |
| Controlled Beacon simulation — `simulations/lab_beacon/lab_beacon_20261102_211623/` | PCAP SHA-256: `fe2208fd964c61823aa2aeaf8559c610662f0d954a8315bcd3a593dd13f4d124` | Zeek connection and HTTP logs; RITA analysis not completed for this partial dataset | 87 HTTP GET requests/connections; 86 intervals with mean 60.000 seconds, standard deviation 0.011 seconds, minimum 59.942 and maximum 60.059 seconds | Scripted periodic lab behavior. The run completed only 87 of 750 planned requests. RITA analysis was not completed for this dataset. MongoDB was subsequently restored, but this partial dataset has not been re-imported or analyzed. Its approximately 86-minute duration is below the configured 6-hour duration and 11-hour histogram thresholds. Periodicity alone is not proof of real C2. |

## 4. Evidence Handling and Reproducibility

- Preserve original PCAPs and record their SHA-256 hashes before analysis.
- Record the exact source PCAP, tool version, command, filter, rule configuration,
  output artifact, and execution time for each new finding.
- Keep source-capture hashes separate from extracted-file hashes.
- Do not infer that an empty export proves the absence of application data.
- Do not treat an alert, HTTP status code, periodic interval, or suspicious URI
  as independent proof of compromise or data exfiltration.
- Preserve raw outputs and derived summaries separately. Document transformations
  and filters used to generate TSV, CSV, and text exports.
- The evidence files and reports remain subject to final content, provenance,
  and publication-safety review.
