# Incident Report: netmetria-focused-scenario.pcap

Status: draft built from recorded tool output. Times are UTC (Zeek epoch converted). `capinfos` and Suricata `fast.log` print host-local time, which for this capture date was UTC+3 (Inferred by comparing the first Zeek event, 14:06:50 UTC, with the capinfos start, 17:06:00 local). The data looks synthetic (198.18.0.0/15 is reserved for benchmarking, `.local` names); this is Inferred.

## 1. Evidence and tools

| Item | Value |
|---|---|
| PCAP | `netmetria-focused-scenario.pcap` (kept outside Git) |
| SHA-256 | `84e66539101bcf14d28ca97c26674096f4afc53e9370a5dd0ef77069cdf850e6` |
| Capture | 1,592 packets, 718.95 s, 2026-09-02 17:06:00 to 17:17:59 local |
| Tools | Zeek 8.0.10, TShark 4.6.4, Suricata 8.0.3 |
| Ruleset | `/var/lib/suricata/rules/suricata.rules`, sha256 `30d7a02cd85f7f7544231a91008a20dedbb15ff0e11ca388ac07aa8d564bf36b`, default `HOME_NET` (covers 10.0.0.0/8) |

## 2. Hosts

| Host | Role | Basis |
|---|---|---|
| 10.42.10.21 | Workstation: 145 connections, source of all SMB activity | Observed |
| 10.42.10.22 | Workstation: 115 connections, no SMB | Observed |
| 10.42.20.53 | DNS server (150 A queries, none over 31 characters) | Observed |
| 10.42.20.40 | Web server: all `*.arden.local` names resolve to it; also SMB target | Observed |
| 10.42.20.10, .15, .20, .30 | SMB targets (TCP 445) plus one TCP 80 connection each from .21 | Observed |
| 10.42.20.123 | NTP | Observed |
| 198.18.42.52 | External-looking server: connectivity-test HTTP and 28 TLS connections (SNI names are Microsoft / Windows Update hosts) | Observed |

## 3. Timeline (UTC)

| Time | Event | Class |
|---|---|---|
| 14:06:50 | .21 connects to IPC$ on 5 servers (.10, .15, .20, .30, .40) and calls `srvsvc NetrShareEnum` on each | Observed |
| 14:12:45 | .21 connects to IPC$ on the same 5 and calls `svcctl OpenSCManagerW` (opnum 15); responses returned. No CreateServiceW (12) or StartServiceW (19) | Observed |
| 14:15:12 | .21 tree-connects `ADMIN$` on the same 5, opens `q4-summary.bin` (Zeek size 0), and sends one 96-byte SMB2 Write per server, all STATUS_SUCCESS | Observed |
| whole capture | .21 and .22 poll `*.arden.local` on 10.42.20.40: 6 host/URI groups, 5 to 6 GETs each, mean interval about 135 s (sd 1.2 to 2.4 s), all 200, Chrome/124 User-Agent | Observed |
| whole capture | Both workstations request `www.msftconnecttest.com/connecttest.txt` 11 times each (mean 71.8 s, sd about 32 s, irregular) | Observed |

## 4. Findings

| Finding | Class |
|---|---|
| One workstation enumerated shares, opened the Service Control Manager and accessed ADMIN$ on five servers in about 8 minutes | Observed |
| The sequence resembles lateral-movement staging | Inferred |
| One 96-byte write per server went to `q4-summary.bin` on ADMIN$ | Inferred (write target handle not mapped to a file) |
| A service was created or started | Unconfirmed (no opnum 12 or 19 seen) |
| Authentication method, account and success | Unconfirmed (Zeek kerberos.log has 15 rows with every field empty) |
| The `*.arden.local` polling is application background traffic | Inferred (fixed interval, internal, GET 200, one browser User-Agent; no payload analysis) |
| C2, beaconing or exfiltration | Unconfirmed (about 1.0 to 1.3 KB per SMB connection; per-group HTTP counts of 5 to 6 are too small for a periodicity claim) |

## 5. Detection results

Suricata (default `HOME_NET`, same ruleset): 22 alerts, all `ET INFO Microsoft Connection Test`. No alert covers the share-enumeration, SCM or ADMIN$ sequence (Observed). Whether a rule for that sequence exists in the ruleset was not checked.

RITA was not run for this capture. Most traffic is internal-to-internal, which RITA filters at import. 10.42.10.21 has 30 connections to 198.18.42.52 (19 on TCP 443, 11 on TCP 80); whether RITA would score that pair was not tested.

## 6. MITRE ATT&CK (candidate mapping; verify IDs against the current ATT&CK version)

| Technique | Basis |
|---|---|
| T1135 Network Share Discovery | `srvsvc NetrShareEnum` on 5 hosts (Observed) |
| T1021.002 Remote Services: SMB/Windows Admin Shares | IPC$ and ADMIN$ access on 5 hosts (Correlated) |
| T1570 Lateral Tool Transfer | Candidate only: file opened and 96 bytes written; content unknown |

Not mapped for lack of evidence: T1569.002 / T1543.003 (no service creation or start seen), valid accounts (authentication data empty), command and control, exfiltration.

## 7. Indicators (observed in this capture; no reputation lookup)

| Type | Value |
|---|---|
| Hosts | 10.42.10.21 (SMB source), 10.42.20.10 / .15 / .20 / .30 / .40 (SMB targets) |
| File | `q4-summary.bin` on `ADMIN$` |
| Pipes / operations | `srvsvc` `NetrShareEnum`, `svcctl` `OpenSCManagerW` |
| Names | `*.arden.local` (portal, updates, config, support, files, directory), all resolving to 10.42.20.40 |

## 8. Limitations

- PCAP only, apparently synthetic; no endpoint or server telemetry.
- Kerberos fields are empty in Zeek, so account and authentication result are unknown.
- The target of the five 96-byte writes was not mapped to a file handle; file content was not extracted.
- The UNC path `\\files.arden.local\...` is identical across five different server IPs although DNS maps that name only to 10.42.20.40; unexplained (possible generation artifact).
- One TCP 80 connection from 10.42.10.21 to each of .10, .15, .20 and .30 has no HTTP transaction in Zeek; not yet examined.
- SMB opnum names (12, 15, 19) are from memory of MS-SCMR and should be verified.
- Suricata ran with the default `HOME_NET`; all hosts here are inside it.

## 9. Reproduction

`scripts/analyze_netmetria.sh` and `scripts/analyze_netmetria_2.sh`. Outputs go to `evidence/netmetria/` (untracked via `.git/info/exclude`).
