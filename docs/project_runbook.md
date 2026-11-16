# Network Traffic Analysis Project Runbook

**Last reviewed:** 4 November 2026

## 1. Purpose and Safety Rules

This runbook documents the reviewed project environment, analysis workflows, evidence handling, and recovery procedures.

- Run commands from the repository root unless stated otherwise.
- Preserve original PCAPs and record their SHA-256 hashes.
- Never execute suspicious or extracted malware samples on the host.
- Do not delete backups, duplicate evidence, or untracked files during routine analysis.
- Inspect scripts before running them, especially scripts that append to reports or overwrite existing outputs.
- Record the input capture, hash, tool version, command/filter, output, interpretation, and limitations.
- Distinguish Observed, Correlated, Inferred, and Unconfirmed findings.
- A periodic connection or IDS alert is not proof of compromise, C2, or data exfiltration.

## 2. Repository and Environment

Repository: `~/projects/soc-migration/network-traffic-project`

Reviewed tool versions:
- TShark 4.6.4
- Zeek 8.0.10
- Suricata 8.0.3
- suricata-update 1.3.7
- RITA 4.8.2 at `$HOME/tools/rita-v4.8.2/rita`

RITA requires a reachable MongoDB backend for dataset import and analysis. In the reviewed environment the MongoDB backend runs as the Docker container `rita-mongo` (127.0.0.1:27017), not as a service inside the WSL distribution. Docker Desktop must be running and the container started before RITA can import or analyze; it was verified reachable on 2026-11-04 (see `reports/project_status.md`). NetworkMiner was not available in the reviewed WSL PATH.


## 3. PCAP Handling and Integrity

Source PCAP folder in WSL:
`/mnt/d/DEPI - graduation/PCAPs files/`

Example integrity checks:
```bash
sha256sum "/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap"
capinfos "/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap"
```

Verify the source path and hash against the relevant incident report before analysis. Keep raw PCAPs and extracted executables outside public Git history.

## 4. Benign Lab Simulation

Relevant files:
- `scripts/run_lab_sim.sh`
- `scripts/analyze_lab_sim.sh`
- `scripts/lab_sim_client.py`
- `scripts/lab_sim_server.py`
- `reports/incident_lab_simulation.md`

The completed simulation generated local Nmap TCP scan traffic, DNS queries, and HTTP POST requests. The captured traffic was analyzed with Zeek and Suricata.

The runner requires elevated privileges and a non-root invoking user. It uses loopback aliases `10.99.99.1/32` and `203.0.113.5/32`, creates a timestamped output directory under `simulations/lab_sim/`, starts a local server, captures traffic, and records a PCAP hash.

Inspect the runner before execution. It does not automatically remove loopback aliases that it adds. Do not remove aliases without checking whether another lab process uses them.

The analysis script expects an existing run directory:
```bash
./scripts/analyze_lab_sim.sh simulations/lab_sim/<run_directory>
```

This simulation validates limited traffic generation and telemetry collection only. It does not validate real malware, C2, DNS tunneling, or external data exfiltration. Checksum-related Suricata alerts were observed, but their cause was not established.


## 5. Periodic Beacon Lab

Relevant files:
- `scripts/run_lab_beacon.sh`
- `scripts/analyze_lab_beacon.sh`
- `server_keepalive.py`
- `reports/scenario_02_beaconing.md`

The reviewed Beacon run was partial: 87 of 750 planned requests. The capture contains 87 HTTP GET requests to `/`, with a mean inter-connection interval of approximately 60 seconds.

The observed periodicity is consistent with the intentionally scripted lab behavior. It is not evidence of real malware or C2 activity.

The partial capture SHA-256 is `fe2208fd964c61823aa2aeaf8559c610662f0d954a8315bcd3a593dd13f4d124`.

The runner requires sudo, a non-root invoking user, and the expected loopback aliases. Its default plan is 750 requests at 60-second intervals. Review the script and available disk space before starting a long run.

RITA analysis was not completed for this partial dataset during the original run because MongoDB was unavailable. MongoDB was subsequently restored, but this dataset has not been re-imported or analyzed. Its approximately 86-minute duration is below the configured 6-hour duration and 11-hour histogram thresholds. Do not describe the partial Beacon dataset as RITA-validated.

## 6. RITA and MongoDB

RITA 4.8.2 is present at `$HOME/tools/rita-v4.8.2/rita`, but importing and analyzing datasets requires a reachable MongoDB backend.

Before running RITA, verify the executable, MongoDB availability, and the configured connection settings. Do not assume that a successful RITA version check means dataset analysis is operational.

Example checks:
```bash
"$HOME/tools/rita-v4.8.2/rita" version
docker ps --filter name=rita-mongo --format '{{.Names}} | {{.Status}} | {{.Ports}}' || true
ss -lnt | grep 27017 || true
```

The NetSupport baseline produced a RITA SNI beacon result with score 0.968 for source `10.11.26.183` and FQDN field `194.180.191.64` (an IP literal, so it does not show a TLS SNI hostname) across 58 connections. This is an analytical indicator, not standalone proof of malicious command-and-control.


## 7. Standard PCAP Analysis Workflow

Start by identifying the capture metadata and preserving its hash:
```bash
sha256sum <capture.pcap>
capinfos <capture.pcap>
tshark -r <capture.pcap> -q -z io,phs
```

Generate protocol logs in a dedicated output directory. Do not mix outputs from different PCAPs:
```bash
mkdir -p <output_directory>/zeek <output_directory>/suricata
cd <output_directory>/zeek
zeek -r <absolute_path_to_capture.pcap>
```

Run Suricata with an explicit configuration and output directory. Confirm HOME_NET is appropriate for the capture before interpreting alert coverage:
```bash
suricata -r <absolute_path_to_capture.pcap> -c /etc/suricata/suricata.yaml -l <absolute_path_to_output_directory>
```

Useful TShark starting points:
```bash
tshark -r <capture.pcap> -Y http.request -T fields -e frame.time -e ip.src -e ip.dst -e http.request.method -e http.host -e http.request.uri
tshark -r <capture.pcap> -Y dns -T fields -e frame.time -e ip.src -e dns.qry.name
tshark -r <capture.pcap> -Y tls.handshake.extensions_server_name -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
```

Use these as starting points, not complete detection logic. Adapt filters to the protocols and evidence present in each capture.

## 8. Reviewed Investigation Notes

### NetSupport-like baseline

Observed: internal host `10.11.26.183` sent 58 HTTP POST requests to `194.180.191.64:443`, using URI `/fakeurl.htm` and user agent `NetSupport Manager/1.3`. Most requests were separated by approximately 50–70 seconds. Suricata generated 58 NetSupport Remote Admin Checkin alerts and 58 HTTP POST alerts.

Interpretation: the repeated pattern and client identifier are suspicious and warrant endpoint and network-owner investigation. They do not independently prove unauthorized remote access, malware execution, compromise, or data exfiltration.

### FormBook-related capture

Observed HTTP destinations included `146.59.71.167` (`grinswakebthu.info`, URI `/irpw/`), `38.182.168.246` (`taibeinan.cc`, URI `/lqjm/`), and `45.130.41.161` (`legenda-sochi.com`, URI `/8nw8/`). For these three URIs Zeek `http.log` records 35 POST requests (14, 14 and 7 respectively) and 5 GET requests that carry long query strings; the matching Suricata signature is `ET MALWARE FormBook CnC Checkin (GET) M5`. These three are examples: the full report lists 15 destination/host groups with the same four-character URI pattern (113 POST requests in total) and 18 signature alerts.

Interpretation: preserve the network indicators and correlate them with endpoint telemetry and the original capture. Network requests alone do not establish successful execution or the full scope of compromise.

### Runner iLove capture

Observed: host `10.10.1.128` downloaded `/wilow/runner_ilove.exe` from `107.175.82.242:9000` with HTTP status 200. The response body was 1,646,592 bytes and its recorded SHA-256 was `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061`.

A later connection to `195.63.128.106:443` was observed. The available network evidence does not establish that the downloaded file executed or that the later connection was caused by it.


### WebInvestigation capture

Observed: source `111.224.250.131` performed SQL injection testing and directory enumeration against `73.124.22.98` (`bookworldstore.com`). A login response returned HTTP 302. A PHP-named file, `NVri2vhp.php`, was uploaded; the captured 79-byte content included PHP execution-related strings such as `exec` and `/dev/tcp`.

The subsequent GET for the uploaded file returned HTTP 500. No server-originated callback was established in the reviewed capture.

Interpretation: the activity is consistent with attempted web-server exploitation and a potentially dangerous upload. Successful execution, persistent access, compromise, callback, and exfiltration remain unconfirmed.

Suricata produced no alerts with the default HOME_NET setting in the reviewed run, while a run using `HOME_NET=73.124.22.0/24` produced 210 alerts. This demonstrates that network scope configuration affects observed alert coverage; it does not by itself establish detection completeness.

### Netmetria capture

Observed: host `10.42.10.21` initiated SMB activity toward multiple internal servers. The reviewed sequence included IPC$ tree connections, share enumeration activity, service-control-manager access, ADMIN$ tree connections, and writes of 96 bytes to `q4-summary.bin` on multiple targets. Zeek recorded the relevant SMB activity.

Interpretation: the sequence may be consistent with administrative discovery or lateral-movement staging. The available evidence does not establish service creation or start, successful remote execution, the identity of the account, or the purpose of the 96-byte writes. Do not assign SMB operation names unless verified against an authoritative protocol reference.

The capture also contained HTTP and TLS traffic to `198.18.42.52`. Its purpose was not established. Do not label it command-and-control or exfiltration without additional evidence.

## 9. WebInvestigation and Netmetria Analysis Scripts

These scripts are consecutive analysis stages, not duplicates. Do not delete a script because a higher-numbered one exists. Run every command from the repository root. Outputs go to `evidence/webinvestigation/` and `evidence/netmetria/`, which are excluded from Git and contain raw protocol content (do not publish them). See also `docs/webinvestigation_sqli_runbook.md`.

### 9.1 WebInvestigation (`WebInvestigation.pcap`, SHA-256 `cf31ec09cf2ece5d0a55c750a0fee19af3ab34d4b7125c4781a56025e2721647`)

| Step | Script | Reads | Produces | Notes |
|---|---|---|---|---|
| 1 | `analyze_webinvestigation.sh` | PCAP | `http_requests.tsv`, `summary.txt` | Identity, per-source counts, methods, User-Agents, status codes, injection-like URI count |
| 2 | `analyze_webinvestigation_2.sh` | PCAP, `http_requests.tsv` (step 1), Suricata ruleset | `summary2.txt`, `suricata_rerun_A/`, `suricata_rerun_B/` | Per-tool time windows; Suricata rerun A (`-k none`) and rerun B (`-k none` plus `HOME_NET=[73.124.22.0/24]`). The sections that use the TShark field `http.response_for.uri` return nothing on TShark 4.6.4, and its POST "no-response" lines are unreliable. Step 3 supersedes them. |
| 3 | `analyze_webinvestigation_3.sh` | PCAP, `suricata_rerun_B/` (step 2) | `zeek/`, `summary3.txt` | Zeek logs, POST status codes, status by tool, sqlmap marker counts, Suricata signature list, ruleset hash, `HOME_NET` line |
| 4 | `analyze_webinvestigation_4.sh` | PCAP, `zeek/`, `suricata_rerun_B/` | `summary4.txt`, `objects_stream_<N>/` | Connection originators, `/admin/uploads` requests, multipart metadata, alert-to-request mapping. It exports the HTTP objects of the upload stream: raw content, keep it local, never open or execute it. |
| 5 | `analyze_webinvestigation_5.sh` | PCAP, `zeek/` | `summary5.txt`, `zeek_hash/` | 302 requests, responses mentioning the uploaded filename, SQL injection response structure (lengths only), port 443 connections |
| 6 | `analyze_webinvestigation_6.sh` | `objects_stream_650/` (step 4) | appends a section to `reports/incident_webinvestigation.md` | Hash and string markers of the uploaded part. It appends with `>>`: run it once only. A rerun duplicates the section, and its appended heading number (10) differs from the current report numbering (7). |
| 7 | `analyze_webinvestigation_7.sh` | `objects_stream_650/`, `zeek/`, PCAP | `summary7.txt` | Reads the text after `/dev/tcp/` and checks that address in the PCAP and `conn.log` |

Notes:

- Steps 3, 4 and 5 contain a lab-run health check hard-coded to `simulations/lab_beacon/lab_beacon_20261102_211623`. It is unrelated to WebInvestigation and only prints an error if that directory is absent.
- Steps 6 and 7 hard-code the export directory `objects_stream_650`. Step 4 chooses the stream number dynamically, so for another capture adjust them.
- Do not run step 6 before reviewing the current report.

### 9.2 Netmetria (`netmetria-focused-scenario.pcap`, SHA-256 `84e66539101bcf14d28ca97c26674096f4afc53e9370a5dd0ef77069cdf850e6`)

| Step | Script | Reads | Produces | Notes |
|---|---|---|---|---|
| 1 | `analyze_netmetria.sh` | PCAP, Suricata ruleset | `evidence/netmetria/zeek/`, `evidence/netmetria/suricata/`, `summary.txt` | Zeek, SMB, DCE/RPC, HTTP, DNS and TLS summaries, plus Suricata with the default `HOME_NET`. It builds its output path from `$(pwd)`, so run it from the repository root. |
| 2 | `analyze_netmetria_2.sh` | PCAP, `zeek/` (step 1) | `summary2.txt` | `svcctl` opnums, SMB2 commands and status, port 445 connection sizes, Kerberos field counts (no account names), HTTP and DNS checks |

The SMB operation names attached to opnums 12, 15 and 19 come from memory of the MS-SCMR specification and must be verified against the protocol reference before publication.

## 10. Script Requirements, Local Paths and Validation Status

Requirements:

- Zeek 8.0.10 (including `zeek-cut`), TShark 4.6.4 (including `capinfos`), Suricata 8.0.3, Python 3, `awk`, `sed`, `sha256sum`.
- Suricata ruleset at `/var/lib/suricata/rules/suricata.rules` and configuration at `/etc/suricata/suricata.yaml`. In the reviewed environment `suricata-update` reported no enabled sources, so the ruleset origin and version are not recorded; the incident reports record its SHA-256 instead.

Local paths hard-coded in the scripts:

| Path | Where | Adjusting it |
|---|---|---|
| `/mnt/d/DEPI - graduation/PCAPs files/<name>.pcap` | `PCAP=` near the top of every WebInvestigation and Netmetria script | Edit the `PCAP=` line to your copy and verify its SHA-256 against the report first |
| `/var/lib/suricata/rules/suricata.rules`, `/etc/suricata/suricata.yaml` | Suricata steps (WebInvestigation 2 and 3, Netmetria 1, `analyze_lab_sim.sh`) | Edit the paths if your installation differs |
| `$HOME/tools/rita-v4.8.2/rita` and `$HOME/projects/soc-migration/.rita-wsl/config.yaml` | `analyze_lab_beacon.sh` | Needs a reachable MongoDB; the Zeek stage works without it, the RITA stage does not |
| loopback aliases `10.99.99.1/32`, `203.0.113.5/32` | lab runners | Not persistent: they disappear when WSL restarts |

List the hard-coded lines with `grep -n '^PCAP=' scripts/*.sh`. Edit a copy of a script, or back it up first.

Validation status:

- `bash -n` passed for all 11 analysis scripts. That checks syntax only.
- The scripts were run in the author's environment during the investigations. No run from a fresh clone or a clean environment has been performed.
- Later steps do not check that the outputs of earlier steps exist (for example step 2 reads `http_requests.tsv` without checking it).
- Raw outputs contain protocol content from the captures, including database content returned by SQL injection in WebInvestigation. Keep them out of Git.

## 11. Troubleshooting and Recovery

- **Suricata permission errors:** use a dedicated writable output directory or the required elevated privileges. Do not change ownership or permissions recursively across system directories.
- **Suricata socket or cache warnings:** check for an existing Suricata process and configured socket before starting another instance. Do not terminate unrelated processes.
- **No Suricata alerts:** verify the capture, ruleset, interface or offline mode, HOME_NET, and output directory. No alerts does not mean no suspicious activity.
- **RITA import or analysis failure:** verify MongoDB availability and RITA configuration. A working RITA executable alone does not mean the backend is ready.
- **Docker unavailable in WSL:** verify Docker Desktop is running and WSL integration is enabled for the relevant distribution before relying on containers.
- **Missing tool:** record that the tool was unavailable in the reviewed environment. Do not report an analysis as completed if it was not run.

## 12. Final Evidence and Reporting Checklist

Before closing an investigation, verify:
- [ ] Original PCAP path and SHA-256 are recorded.
- [ ] Capture time range, packet count, and relevant metadata are recorded.
- [ ] Tool versions, commands, filters, ruleset, and configuration are documented.
- [ ] Output files are preserved and linked to the correct capture.
- [ ] Important timestamps, source and destination addresses, ports, protocols, and artifacts are recorded.
- [ ] Observations are separated from interpretations and hypotheses.
- [ ] Limitations, missing telemetry, and unconfirmed findings are explicit.
- [ ] Findings are corroborated across tools where possible.
- [ ] No claim of execution, compromise, C2, persistence, or exfiltration is made without supporting evidence.
- [ ] Report changes are reviewed before publication.

Do not delete raw captures, backups, intermediate evidence, or untracked files as part of routine cleanup. Any cleanup must be separately reviewed and explicitly approved.

---

This runbook reflects the reviewed project state as of 4 November 2026. Revalidate paths, versions, configurations, and service availability before repeating commands.
