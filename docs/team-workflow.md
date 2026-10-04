# Team Workflow

## 1. Overview

This document defines the collaboration workflow between all five team members and describes how individual technical tasks are connected to form one complete network security investigation.

Each member owns a specific area of the project, while all outputs are integrated into a unified workflow.

```text
Traffic Generation / PCAP
            ↓
         Capture
            ↓
         Analysis
            ↓
         Detection
            ↓
        Correlation
            ↓
       Investigation
            ↓
       IOC Extraction
            ↓
      MITRE ATT&CK
            ↓
       Final Report
2. Team Structure
Member	Role	Primary Responsibility	Main Tools
M1	Team Leader / Integration	Coordination, integration, documentation	GitHub, VirtualBox
M2	Network Traffic Analyst	PCAP and packet analysis	Wireshark, TShark
M3	Network Detection Analyst	Network monitoring and IDS analysis	Zeek, Suricata
M4	C2 & Beaconing Analyst	C2, beaconing, RITA and MITRE analysis	RITA, MITRE ATT&CK
M5	Attack Simulation & Lab Engineer	Lab setup and controlled traffic generation	VirtualBox, Kali, Nmap
3. End-to-End Workflow

The project follows a connected pipeline in which the output of one stage becomes the input for the next stage.

Stage 1 — Traffic Generation

Owner: M5

M5 prepares the isolated laboratory environment and generates controlled network traffic through project scenarios.

Lab Environment
      ↓
Controlled Scenario
      ↓
Network Traffic
      ↓
PCAP

The generated traffic may include:

Network Scanning
C2 Activity
DNS Tunneling
Controlled Data Transfer / Exfiltration

The resulting PCAP files are provided to the analysis team.

Stage 2 — Network Traffic Analysis

Owner: M2

M2 analyzes the captured traffic using Wireshark and TShark.

PCAP
 ↓
Wireshark / TShark
 ↓
Traffic Analysis
 ↓
Findings
 ↓
IOCs

The analysis focuses on:

Source and destination hosts
Protocols
Ports
DNS activity
HTTP activity
TCP behavior
Suspicious communications
Network indicators

Relevant findings are shared with the other members for correlation.

Stage 3 — Network Detection

Owner: M3

M3 processes the traffic using Zeek and Suricata to generate network logs and detection alerts.

PCAP
 ↓
Zeek
 ↓
Network Logs
 ↓
Suricata
 ↓
Detection Alerts

The analysis includes:

Connection activity
DNS logs
HTTP logs
Suspicious destinations
IDS alerts
True Positive / False Positive analysis
Detection limitations

These results provide additional evidence for the investigation.

Stage 4 — C2 & Beaconing Analysis

Owner: M4

M4 investigates suspicious communication patterns, C2 activity, and beaconing behavior using Zeek logs and RITA.

Zeek Logs
    ↓
   RITA
    ↓
Beaconing Analysis
    ↓
C2 Investigation
    ↓
MITRE ATT&CK Mapping

The analysis focuses on:

Periodic communication
Repeated connections
Suspicious destinations
C2 behavior
DNS-based suspicious activity
Beaconing patterns
MITRE ATT&CK techniques
Stage 5 — Correlation & Investigation

Owner: M1

M1 integrates the findings produced by all members into one investigation.

              ┌── M2: Wireshark / TShark
              │
              ├── M3: Zeek / Suricata
              │
PCAP / Data ──┼── M4: RITA / C2 / MITRE
              │
              └── M5: Lab / Scenario Evidence
                         ↓
                   M1 Integration
                         ↓
                    Investigation
                         ↓
                    Final Report

M1 verifies that the findings are consistent and that the evidence from different tools supports the final conclusions.

4. Member Handover

Clear handover between team members is required to keep the project workflow connected.

From	To	Handover
M5	M2	PCAP files and scenario information
M5	M3	PCAP files and scenario information
M5	M4	Relevant traffic and scenario information
M2	M3	Traffic findings and suspicious indicators
M2	M4	Network findings and extracted IOCs
M2	M1	PCAP analysis and investigation findings
M3	M4	Zeek logs and detection results
M3	M1	Logs, alerts and detection findings
M4	M1	C2, beaconing, RITA and MITRE findings
M1	Team	Integration feedback and final documentation structure
5. Scenario Workflow

Each major scenario follows the same general collaboration process.

Example — C2 Beaconing Scenario
1. Generate

M5

Creates the controlled C2 activity inside the isolated laboratory.

Controlled C2 Activity
          ↓
        PCAP
2. Analyze

M2

Analyzes the PCAP using Wireshark and TShark.

PCAP
 ↓
Wireshark / TShark
 ↓
Suspicious Communication
 ↓
IOCs
3. Detect

M3

Processes the PCAP using Zeek and Suricata.

PCAP
 ↓
Zeek
 ↓
Logs
 ↓
Suricata
 ↓
Alerts
4. Investigate

M4

Uses Zeek logs and RITA to investigate beaconing and C2 behavior.

Zeek Logs
    ↓
   RITA
    ↓
Beaconing Detection
    ↓
C2 Analysis
    ↓
MITRE ATT&CK
5. Integrate

M1

Combines the available evidence into one investigation.

Wireshark Findings
        +
Zeek Findings
        +
Suricata Alerts
        +
RITA Results
        +
MITRE Mapping
        ↓
Investigation Report
6. Evidence Correlation

Findings should be correlated across multiple tools whenever possible.

A suspicious indicator identified by one tool should be investigated using the available evidence from other stages.

Example:

Wireshark
    ↓
Suspicious IP / Domain
    ↓
Zeek
    ↓
Connection / DNS / HTTP Evidence
    ↓
Suricata
    ↓
Detection Alert
    ↓
RITA
    ↓
Beaconing Evidence
    ↓
Investigation

This approach helps the team build conclusions based on multiple sources of evidence rather than relying on a single tool.

7. Scenario Documentation

Every completed scenario should contain a consistent set of information:

Objective
Environment
Scenario Description
Steps
Input / PCAP
Analysis
Findings
IOCs
Screenshots
Expected Result
Actual Result
Conclusion

This ensures that each scenario can be reviewed, reproduced, and connected to the rest of the project.

8. GitHub Collaboration

All project outputs must be stored in their appropriate directories.

project/
├── docs/
├── pcaps/
├── wireshark/
├── zeek/
├── suricata/
├── rita/
├── simulations/
├── reports/
└── README.md

Each team member is responsible for keeping their assigned directory organized and maintaining clear documentation.

Before committing work, members should verify:

The file is stored in the correct directory.
The file name is clear and consistent.
The analysis is complete.
Required screenshots are included.
Relevant IOCs are documented.
Scenario information is complete.
Unnecessary files are not committed.
9. Integration Checkpoints

The project will be validated through the following checkpoints.

Checkpoint 1 — Environment
GitHub
+
Virtual Machines
+
Isolated Network
+
Required Tools
Checkpoint 2 — Core Analysis Pipeline
PCAP
 ↓
Wireshark
 ↓
Zeek
 ↓
Suricata

The team must verify that the basic analysis pipeline works before moving to advanced scenarios.

Checkpoint 3 — First Complete Investigation

The entire team completes one end-to-end scenario and verifies that the outputs from different tools can be correlated.

Checkpoint 4 — Advanced Scenarios

The team proceeds with:

Network Scanning
C2
DNS Tunneling
Controlled Exfiltration
Checkpoint 5 — Final Correlation

All relevant findings, IOCs, alerts, and analysis results are combined into complete investigation reports.

10. Team Communication Rules

To maintain consistency throughout the project:

Important findings must be documented.
Technical outputs must be shared with the members who depend on them.
Scenario names and file names must remain consistent.
Important IOCs must be recorded in the relevant documentation.
Changes affecting another member's work should be communicated before implementation.
Evidence should be preserved and referenced during investigation.
Members should avoid duplicating work that is already assigned to another member.
11. Definition of Done

The team workflow is considered successfully implemented when the project can demonstrate the complete investigation pipeline:

Generate / Obtain Traffic
          ↓
        Capture
          ↓
        Analyze
          ↓
         Detect
          ↓
       Correlate
          ↓
      Investigate
          ↓
      Extract IOCs
          ↓
      Map to MITRE
          ↓
       Final Report

Each member must be able to explain how their assigned responsibility contributes to the overall workflow.

12. Team Principle

Each member owns a specific part of the project, but no part of the project works in isolation.

The final project should demonstrate a single, connected network security investigation rather than five independent technical tasks.
