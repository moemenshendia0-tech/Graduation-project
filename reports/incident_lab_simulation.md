# Benign Lab Network Simulation

## 1. Overview

A controlled, benign network simulation was executed on the local loopback interface to generate traffic for defensive monitoring and detection validation.

- Run directory: `simulations/lab_sim/lab_sim_20261103_232117/`
- Capture: `capture.pcap`
- Capture size: approximately 5.3 MB
- Packets: 2,635
- Duration: 74.52 seconds
- Tools: Nmap, Zeek, Suricata, tcpdump
- Suricata version: 8.0.3
- Zeek version: 8.0.10
- Nmap version: 7.98

## 2. Lab Configuration

The execution script assigns the following addresses to the loopback interface:

- Simulated client/source: `10.99.99.1`
- Simulated destination: `203.0.113.5`

The custom Python server provides DNS over UDP/53 and HTTP over TCP/8080. The client runs a TCP SYN scan, DNS-style queries, and HTTP POST transfers.

The execution phases recorded in `phases.log` were:

- Scan start: 23:21:21
- DNS start: 23:21:21
- HTTP transfer start: 23:21:38
- End: 23:22:38

## 3. Nmap Results

The configured command scans TCP ports 1–1000:

`nmap -sS -S 10.99.99.1 -e lo -Pn -n -p 1-1000 203.0.113.5`

Nmap reported:

| Port | State | Service |
|---|---|---|
| 25/tcp | Open | SMTP |
| 465/tcp | Open | SMTPS |
| 587/tcp | Open | Submission |

The other 997 scanned TCP ports were reported closed.

The three SMTP listeners are not services implemented by the custom Python simulation server. Their process ownership at the exact capture time was not established; they must not be attributed to the custom server.

The previous `distinct TCP dst ports probed: 1001` value was incorrect. It counted unique destination ports in Zeek connection records, including traffic unrelated to the Nmap scan. The configured scan range and original Nmap output are the appropriate evidence for the scan scope and results.

## 4. DNS Activity

Zeek recorded:

- DNS queries: 70
- Unique query names: 63
- Mean query-name length: 94.5 characters
- Maximum query-name length: 108 characters
- Query names longer than 50 characters: 60

The client invocation requested 60 DNS-style queries. The difference between that requested count and the 70 records observed by Zeek has not been reconciled.

Long query names are useful detection signals to investigate, but these observations alone do not establish DNS tunneling or malicious activity. No dnscat2 or iodine scenario was run.

## 5. HTTP POST Transfer

Zeek recorded:

- HTTP POST requests: 20
- Total request-body bytes: 5,242,880
- Per-transfer size reported by the client: 262,144 bytes
- Client responses: HTTP 200

This was a controlled transfer to the local lab HTTP server. The script labels this phase `exfil`, but that label describes the simulation phase only. It is not evidence of real data exfiltration, external communication, or compromise.

## 6. Suricata Results

Suricata generated 655 alerts using the default `HOME_NET` configuration:

| Signature | Count |
|---|---:|
| `SURICATA TCPv4 invalid checksum` | 495 |
| `SURICATA UDPv4 invalid checksum` | 140 |
| `ET INFO Python BaseHTTP ServerBanner` | 20 |
| **Total** | **655** |

The 20 Python BaseHTTP ServerBanner alerts are informational identification of the test HTTP server, not proof of malicious behavior.

The 635 checksum alerts are recorded as observed alerts. Their underlying cause was not conclusively established, so they should not be interpreted as attack detections.

## 7. Evidence and Limitations

- Original PCAP and tool outputs are retained in the run directory.
- Zeek generated connection, DNS, and HTTP logs.
- Suricata generated EVE and fast alert logs.
- The Nmap output is retained in `nmap.out`.
- The simulation was performed on loopback using documentation/test addresses.
- No real C2 framework, malware, DNS tunneling tool, or external exfiltration destination was used.
- SMTP listener ownership at capture time remains unconfirmed.
- The difference between the requested DNS query count and Zeek's observed count remains unexplained.
- Checksum alert causes were not independently verified.

## 8. Conclusion

The simulation successfully generated observable TCP scanning, DNS-style query activity, and repeated HTTP POST transfers. Zeek recorded the expected traffic categories, while Suricata produced informational HTTP server identification alerts and checksum-related alerts.

The results demonstrate traffic generation and basic telemetry collection. They do not demonstrate successful malicious activity, command and control, DNS tunneling, or real data exfiltration.

## 9. Reproduction References

- `scripts/run_lab_sim.sh`
- `scripts/lab_sim_server.py`
- `scripts/lab_sim_client.py`
- `scripts/analyze_lab_sim.sh`

Raw PCAPs and generated evidence should remain outside Git publication unless explicitly reviewed and approved.
