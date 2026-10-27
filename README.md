# Network Traffic Analysis & C2/Exfiltration Detection

## Project Overview

This project focuses on analyzing network traffic and detecting suspicious activities such as network scanning, Command and Control (C2) communication, beaconing, DNS tunneling, and potential data exfiltration.

The project combines multiple network security tools into a practical traffic analysis and detection pipeline.

## Project Objectives

* Analyze network traffic and PCAP files.
* Identify suspicious network activity.
* Extract Indicators of Compromise (IOCs).
* Detect suspicious C2 communication.
* Identify beaconing behavior.
* Analyze suspicious DNS activity and DNS tunneling.
* Detect potential data exfiltration.
* Correlate results from multiple security tools.
* Map identified behaviors to MITRE ATT&CK.
* Produce investigation reports based on network evidence.

## Tools

* Wireshark
* TShark
* Zeek
* Suricata
* Emerging Threats Open Ruleset
* RITA
* VirtualBox
* Kali Linux
* Windows 10
* Ubuntu

## Project Workflow

```text
Network Traffic / PCAP
          ↓
   Wireshark / TShark
          ↓
         Zeek
          ↓
      Suricata
          ↓
         RITA
          ↓
 C2 / Beaconing Detection
          ↓
      Investigation
          ↓
    IOC Extraction
          ↓
 MITRE ATT&CK Mapping
          ↓
     Final Report
```

## Team Structure

| Member   | Role                             |
| -------- | -------------------------------- |
| Member 1 | Team Leader / Integration        |
| Member 2 | Network Traffic Analyst          |
| Member 3 | Network Detection Analyst        |
| Member 4 | C2 & Beaconing Analyst           |
| Member 5 | Attack Simulation & Lab Engineer |

## Main Scenarios

### 1. Network Scanning

Analyze scanning activity generated inside the isolated lab environment.

### 2. C2 Communication

Analyze controlled Command and Control communication and identify suspicious network patterns.

### 3. Beaconing

Detect periodic communication between a host and a potential C2 destination.

### 4. DNS Tunneling

Analyze suspicious DNS activity and identify potential DNS tunneling behavior.

### 5. Data Exfiltration

Analyze controlled outbound data transfers and identify suspicious exfiltration patterns.

## Investigation Process

Each scenario will follow the same general process:

```text
Traffic / PCAP
      ↓
Wireshark Analysis
      ↓
Zeek Logs
      ↓
Suricata Alerts
      ↓
RITA Analysis
      ↓
Correlation
      ↓
IOC Extraction
      ↓
MITRE ATT&CK Mapping
      ↓
Investigation Report
```

## Repository Structure

```text
Network-Traffic-Analysis-C2-Exfil/
│
├── README.md
├── scripts/
├── tests/
│
├── docs/
├── pcaps/
├── wireshark/
├── zeek/
├── suricata/
├── rita/
├── simulations/
├── reports/
└── evidence/
```

## Project Scope

All attack simulations and testing activities will be performed inside an isolated laboratory environment for educational and defensive security analysis purposes.

## Project Status

**Phase 1 — Repository and Project Setup**

Current tasks:

* [x] Create GitHub repository
* [x] Assign team responsibilities
* [x] Define project workflow
* [ ] Prepare project environment
* [x] Analyze first PCAP
* [x] Configure and run Zeek; preserve the reviewed logs
* [x] Configure and run Suricata; preserve the reviewed EVE/alert output
* [x] Configure and run RITA 4.8.2; import fresh Zeek logs into `soc_baseline_zeek810_20261027`
* [ ] Start controlled attack simulations
* [x] Validate detector output on the two reviewed captures (broader multi-tool and endpoint correlation remains pending)
* [ ] Review and finalize investigation reports and evidence before publication

---

## Completed Investigation: Suspicious NetSupport-like Traffic

A PCAP dated 26 November 2024 was investigated using Wireshark/TShark, Zeek, and Suricata artifacts. RITA 4.8.2 is available at `$HOME/tools/rita-v4.8.2/rita`, and a fresh Zeek dataset was imported. Further RITA interpretation and endpoint correlation remain pending; the import alone does not establish compromise.

### Key Findings

- Internal host: `10.11.26.183`
- External destination: `194.180.191.64:443`
- HTTP URI: `/fakeurl.htm`
- Observed User-Agent: `NetSupport Manager/1.3`
- Zeek identified 58 HTTP POST requests over approximately 52.73 minutes.
- 51 of 57 request intervals fell between 50 and 70 seconds.
- Suricata generated NetSupport remote-administration and HTTP POST alerts.
- Additional TLS connections were observed for `modandcrackedapk.com`
  and `classicgrand.com`.

### Assessment

The repeated NetSupport-like traffic is suspicious and warrants further
investigation. The PCAP alone does not confirm malware infection,
unauthorized remote access, a confirmed C2 channel, or data exfiltration.

### Investigation Artifacts

- `reports/incident_report.md` — full investigation report
- `reports/detection_summary.txt` — detection summary
- `reports/timeline_finding.txt` — timeline correlation and assessment
- `evidence/ioc_table.tsv` — indicators of compromise under investigation
- `evidence/netsupport_http_timeline.tsv` — HTTP request timeline
- `evidence/netsupport_suricata_alerts.tsv` — relevant Suricata alerts
- `evidence/netsupport_timing_finding.txt` — periodicity analysis

> Raw packet captures and generated raw logs are excluded from version control.

## Evidence Inventory

- `reports/evidence_inventory.md` — duplicate-artifact inventory and handling notes.

## Additional Investigation: runner_ilove.exe

A separate investigation examined an HTTP transfer of a Windows executable
observed in the `2026-10-01-traffic-analysis-exercise.pcap` capture.

- Source host: `10.10.1.128`
- Download server: `107.175.82.242:9000`
- Requested path: `/wilow/runner_ilove.exe`
- HTTP status: `200 OK`
- Captured response body: `1,646,592` bytes
- SHA-256: `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061`
- Threat-intelligence correlation: a matching ThreatFox hash record is documented
  in the dedicated report.
- A later connection to `195.63.128.106:443` requires further investigation;
  the capture alone does not establish that the downloaded file initiated it.

The evidence supports treating the sample as potentially malicious for
defensive handling. Execution, host compromise, causal command-and-control
activity, and data exfiltration have not been established by the available
packet evidence.

Detailed documentation:
- `reports/incident_runner_ilove.md` — investigation report
- `reports/runner_ilove_iocs.csv` — investigation indicators
- `reports/runner_ilove_evidence_checklist.md` — evidence review checklist

The extracted executable and local batch-analysis output are excluded from
Git. Do not execute the sample on a normal workstation.


## Local Detector Utilities

The Python scripts operate on existing Zeek TSV logs and write derived output under the ignored local `analysis/` directory. Keep original PCAPs, extracted executables, and raw stream exports out of public Git history.

Run syntax and regression checks:

```bash
python3 -m py_compile scripts/detect_network_anomalies.py scripts/analyze_post_patterns.py scripts/build_incident_report.py
python3 -m unittest discover -s tests -v
```

Example: process the available August capture's existing Zeek logs:

```bash
python3 scripts/detect_network_anomalies.py \
  --logs analysis/batch/2026-08-09-traffic-analysis-exercise/zeek \
  --out analysis/detection-results/2026-08-09
python3 scripts/build_incident_report.py \
  --input analysis/detection-results/2026-08-09/alerts.json \
  --out analysis/detection-results/2026-08-09/incident_candidates.json
python3 scripts/analyze_post_patterns.py \
  --logs analysis/batch/2026-08-09-traffic-analysis-exercise/zeek \
  --out analysis/detection-results/2026-08-09/post_patterns.json
```

These outputs are investigation leads, not proof of compromise, command-and-control, or successful exfiltration. The incident builder only correlates overlapping aggregate time ranges; validate individual events before drawing causal conclusions.
