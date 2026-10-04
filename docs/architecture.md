# Project Architecture

## Network Traffic Analysis & C2/Exfiltration Detection

The project follows a multi-stage network traffic analysis and detection pipeline.

```text
                    Network Traffic
                          │
                          ▼
               ┌─────────────────────┐
               │ Wireshark / TShark  │
               │ Packet Analysis     │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │        Zeek         │
               │   Network Logging   │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │      Suricata       │
               │   IDS Detection     │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │        RITA         │
               │ Beacon Detection    │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │    Investigation    │
               │ Correlation + IOCs  │
               └──────────┬──────────┘
                          │
                          ▼
               ┌─────────────────────┐
               │ MITRE ATT&CK +      │
               │ Final Report        │
               └─────────────────────┘
```

## Laboratory Environment

The project will use an isolated virtual laboratory:

```text
                 Isolated Lab Network
                         │
          ┌──────────────┼──────────────┐
          │              │              │
          ▼              ▼              ▼
      Kali Linux     Windows 10      Ubuntu
          │              │              │
          └──────────────┼──────────────┘
                         │
                         ▼
                  Network Traffic
                         │
                         ▼
             Analysis & Detection Pipeline
```

## Analysis Flow

1. Obtain a PCAP or generate controlled network traffic.
2. Analyze packets using Wireshark/TShark.
3. Process the traffic with Zeek.
4. Analyze Zeek logs.
5. Process traffic with Suricata.
6. Analyze IDS alerts.
7. Use RITA for beaconing analysis.
8. Correlate findings from all tools.
9. Extract IOCs.
10. Map relevant behavior to MITRE ATT&CK.
11. Produce the final investigation report.
