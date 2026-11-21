# Project Architecture

## Network Traffic Analysis & C2/Exfiltration Detection

The unified alert path runs Zeek and Suricata independently against the same offline PCAP. RITA can analyze Zeek logs separately. The alert merge preserves source identity and candidate records; it does not deduplicate or correlate events across sensors.

```text
                         PCAP
              ┌──────────┼──────────┐
              ▼          ▼          ▼
       Wireshark/      Zeek      Suricata
        TShark          │           │
                        ▼           ▼
                 Zeek adapter   EVE adapter
                        └─────┬─────┘
                              ▼
                    Candidate-alert merge
                              ▼
                       FastAPI → Flutter

              RITA ← Zeek logs (separate analysis)
              Analyst review → IOCs → report
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
8. Compare findings from all tools and correlate only when shared evidence supports the link.
9. Extract IOCs.
10. Map relevant behavior to MITRE ATT&CK.
11. Produce the final investigation report.
