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
│
├── docs/
├── pcaps/
├── wireshark/
├── zeek/
├── suricata/
├── rita/
├── simulations/
└── reports/
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
* [ ] Analyze first PCAP
* [ ] Configure Zeek
* [ ] Configure Suricata
* [ ] Configure RITA
* [ ] Start controlled attack simulations
* [ ] Correlate detection results
* [ ] Complete final investigation reports

---

## Completed Investigation: Suspicious NetSupport-like Traffic

A PCAP dated 26 November 2024 was analyzed using Wireshark/TShark,
Zeek, Suricata, and RITA.

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
- `wireshark/ioc_table.tsv` — indicators of compromise under investigation
- `wireshark/netsupport_http_timeline.tsv` — HTTP request timeline
- `suricata/netsupport_alerts.tsv` — relevant Suricata alerts
- `zeek/netsupport_timing_finding.txt` — periodicity analysis

> Raw packet captures and generated raw logs are excluded from version control.

