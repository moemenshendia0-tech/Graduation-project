# Incident Report: WebInvestigation.pcap

Status: draft built from recorded tool output (see Limitations). All times are UTC. Suricata `fast.log` prints host-local time (UTC+2); it was converted by matching the first sqlmap request (12:07:34 UTC in Zeek, 14:07:34 in Suricata).

Related material: `reports/webinvestigation_sqli_report.md` (earlier report on the data retrieved through the SQL injection; the values are omitted there) and `docs/webinvestigation_sqli_runbook.md`.

## 1. Evidence and tools

| Item | Value |
|---|---|
| PCAP | `WebInvestigation.pcap` (kept outside Git; `*.pcap` is ignored) |
| SHA-256 | `cf31ec09cf2ece5d0a55c750a0fee19af3ab34d4b7125c4781a56025e2721647` |
| Capture | about 88k packets, 2,832 s, 11:39:21 to 12:26:33 UTC |
| Provenance | Not recorded in the project files (to be filled in) |
| Tools | TShark 4.6.4, Zeek 8.0.10, Suricata 8.0.3 |
| Ruleset | `/var/lib/suricata/rules/suricata.rules`, 53,248 alert rules, SHA-256 `30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b`. `suricata-update` reports no enabled sources, so the ruleset origin and version are not recorded. |

## 2. Hosts

| Host | Role in this capture | Basis |
|---|---|---|
| 73.124.22.98 | Web server, `bookworldstore.com`, TCP 80 | Observed |
| 111.224.250.131 | Attack source: 41,684 requests (41,527 gobuster/3.6, 121 sqlmap/1.8.3, 36 Firefox/115 on Linux) | Observed tooling, role Inferred |
| 170.40.150.126 | Ordinary-looking browsing: 25 requests (Chrome/121), 15 rejected TCP 443 attempts | Observed |
| 73.124.22.1 | One UDP 57621 broadcast (Spotify P2P signature), unrelated | Observed |

Zeek: 660 connections (626 from 111.224.250.131, 33 from 170.40.150.126, 1 UDP). No connection was originated by 73.124.22.98.

## 3. Timeline (UTC)

| Time | Event | Class |
|---|---|---|
| 11:39:59 to 12:26:25 | 170.40.150.126 browses the site | Observed |
| 12:07:34 to 12:09:57 | sqlmap: 121 requests (70 x 200, 51 x 500). Suricata `ET SCAN Sqlmap SQL Injection Scan` x6 | Correlated |
| 12:09:32, 12:09:40, 12:09:57 | Requests referencing `bookworld_db` (admin table, columns id, password, username). Responses contain the DB-evaluated separator; the request carried it only as hex | Correlated |
| 12:12:20 to 12:12:26 | gobuster: 41,527 requests (41,487 x 404, 30 x 403, 8 x 200, 2 x 301) | Observed |
| 12:12:58 | `GET /admin/` returns 302 to `login.php` | Observed |
| 12:13:04, 12:13:51, 12:13:55 | `POST /admin/login.php` returns 200 each | Observed |
| 12:17:35 | `POST /admin/login.php` returns 302 to `index.php`; `GET /admin/index.php` returns 200 | Observed |
| 12:24:18 | `POST /admin/index.php`, multipart upload of `NVri2vhp.php` (application/x-php, 79 bytes), response 200. Five Suricata alerts on source port 50076 | Correlated |
| 12:24:24 | `/admin/uploads/` listing (200) references the filename | Observed |
| 12:24:28 | `GET /admin/uploads/NVri2vhp.php` returns 500, empty body | Observed |
| 12:26:28 | `/admin/uploads/` listing references the filename again | Observed |

## 4. Findings

| Finding | Class |
|---|---|
| Directory brute force and SQL injection scanning against `bookworldstore.com` from one source | Observed (tools identified by User-Agent, which the sender controls) |
| SQL injection returned database content to the sender | Correlated |
| Values returned were credentials | Unconfirmed (values deliberately not decoded or reproduced) |
| The four login POSTs used credentials obtained through the SQLi | Unconfirmed |
| Authenticated session established at 12:17:35 | Inferred (302 to index.php, then 200; no session analysis) |
| A PHP file was uploaded and appears in the uploads listing | Observed |
| The 79-byte uploaded part contains the strings `<?php`, `exec`, `/dev/tcp` and `bash` (consistent with a PHP reverse-shell one-liner) | Observed (strings), Inferred (purpose) |
| The payload targets `111.224.250.131:443`, the scan source (consistent with a reverse-shell attempt) | Observed (target), Inferred (intent) |
| The PHP file is a web shell and was executed | Unconfirmed (500 with empty body; no server-side evidence) |
| Data exfiltration or successful compromise | Unconfirmed |

## 5. Detection results

| Run | Settings | Alerts |
|---|---|---|
| Original | default `HOME_NET` (`192.168.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`) | 0 |
| Rerun A | `-k none`, default `HOME_NET` | 0 |
| Rerun B | `-k none`, `HOME_NET=[73.124.22.0/24]` | 210 |

The only difference between A and B is `HOME_NET`, so the zero-alert result was a configuration gap, not a ruleset gap (Observed). The effect of checksum validation was not isolated. Rerun B is a documented deviation from the default configuration.

Selected signatures in rerun B: GPL WEB_SERVER 403 Forbidden x30; ET WEB_SPECIFIC_APPS Address Book SQL Injection x29 (+3 UNION variant); ET WEB_SERVER SQL Injection Select Sleep Time Delay x14; ET SCAN Sqlmap SQL Injection Scan x6; on the upload POST: PHP tags in HTTP POST x1, Suspicious PHP Code in HTTP POST x2, Possible SQL Injection (exec) in Request Body x1, Possible bash shell piped to dev tcp x1. The ruleset has no signature that names gobuster (0 matching lines); its traffic was detected only indirectly through path and response signatures (Inferred). The Address Book signature is application-specific, so a match is not evidence that the site is that application. `ET INFO Spotify P2P Client` is an unrelated UDP broadcast.

## 6. MITRE ATT&CK (candidate mapping; verify IDs against the current ATT&CK version)

| Technique | Basis |
|---|---|
| T1595.002 Active Scanning: Vulnerability Scanning | sqlmap activity (Observed) |
| T1595.003 Active Scanning: Wordlist Scanning | gobuster burst (Observed) |
| T1190 Exploit Public-Facing Application | SQLi that returned data (Correlated) |
| T1505.003 Server Software Component: Web Shell | Candidate only: PHP upload observed, function unconfirmed |

Not mapped for lack of evidence: execution (the upload GET returned 500), command and control (no callback observed), exfiltration, valid accounts.


## 7. Uploaded file: content check

Method: the multipart part for NVri2vhp.php was cut out of the exported HTTP request body of TCP stream 650 (scripts/analyze_webinvestigation_6.sh). The part was parsed in memory and never executed; the exported HTTP bodies stay in the local evidence directory (TShark named them index.php, mode 0644). Zeek files.log had no SHA-256 for it.

```text
source_file=index.php
request_body_bytes=441
file_content_bytes=79
file_content_sha256=24d6d938aa8d87fc32577d3513fad6fe2bf574ebc3d7967a429e52171d92a745
markers_present=<?php,exec,/dev/tcp,bash
dev_tcp_target_in_request_body=/dev/tcp/
```

Marker names are plain substring matches (for example exec also matches shell_exec). They show that a string is present, not what the code does.

Result: the extracted 79-byte part has SHA-256 `24d6d938aa8d87fc32577d3513fad6fe2bf574ebc3d7967a429e52171d92a745` (hash of the bytes between the multipart part headers and the closing boundary, as parsed by the script; line-ending handling could change it). It contains `<?php`, `exec`, `/dev/tcp` and `bash`. The request body contains a shell redirection to `/dev/tcp/111.224.250.131/443`, the same host that sent the scan and the upload (the first extraction attempt failed because the address is wrapped in quotes in the payload). The exported 441-byte body is the multipart request body of the upload POST.

Not established: that the code ran. The GET for the file returned 500 with an empty body, and the capture shows no connection originated by the web server.

## 8. Indicators (observed in this capture; no external reputation lookup was performed)

| Type | Value |
|---|---|
| IP | 111.224.250.131 (attack source), 73.124.22.98 (web server) |
| Host | bookworldstore.com |
| URIs | `/admin/login.php`, `/admin/index.php`, `/admin/uploads/NVri2vhp.php` |
| Filename | `NVri2vhp.php` |
| Payload target | `111.224.250.131:443` (inside the upload body; same host as the attack source) |
| SHA-256 (extracted part) | `24d6d938aa8d87fc32577d3513fad6fe2bf574ebc3d7967a429e52171d92a745` |
| User-Agents | `gobuster/3.6`, `sqlmap/1.8.3#stable (https://sqlmap.org)` |
| sqlmap markers | `qxvbq`, `qvpjq` (request-side, hex separator `0x7a76676a636b`) |

## 9. Limitations

- PCAP only: no web server, database or file-system evidence, so login success, file storage, execution and data theft cannot be confirmed.
- Capture vantage point is unknown; the absence of server-originated connections is limited to what this capture could see.
- Credential-like values returned by the SQLi exist in the PCAP. They were not decoded or published. Do not commit raw evidence.
- Some response lengths differ between tools (for example 413 vs 689 at 12:24:18); probably HTTP compression, not verified.
- IP addresses were not checked against threat intelligence; the data may be anonymized exercise data.
- Suricata reruns used a non-default `HOME_NET` and `-k none`.
- The callback target was read from the request body only. No connection to 111.224.250.131:443 and no connection originated by 73.124.22.98 appear in this capture, so a callback is not observed (capture vantage point unknown).

## 10. Reproduction

Scripts in `scripts/` (run in order): `analyze_webinvestigation.sh` to `analyze_webinvestigation_7.sh`. Outputs go to `evidence/webinvestigation/` (contains raw HTTP content; do not commit).
