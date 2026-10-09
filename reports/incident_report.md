# Network Traffic Analysis & Suspicious C2 Investigation

## 1. Executive Summary

A packet capture dated 26 November 2024 was analyzed using
Wireshark/TShark, Zeek, Suricata, and RITA.

The primary finding was repeated HTTP POST traffic from internal
host `10.11.26.183` to external IP `194.180.191.64` on TCP port
443. The requests used the URI `/fakeurl.htm` and the User-Agent
`NetSupport Manager/1.3`.

Zeek identified 58 HTTP POST requests over approximately 52.73
minutes. Of 57 request intervals, 51 were between 50 and 70
seconds, with an average interval of approximately 60.14 seconds.
Suricata also generated 58 NetSupport Remote Admin Checkin alerts
and 58 alerts for HTTP POST traffic on port 443.

Additional TLS connections were observed to:
- `modandcrackedapk.com` — `193.42.38.139`
- `classicgrand.com` — `213.246.109.5`

These findings warrant further investigation. The capture alone
does not confirm malware infection, unauthorized remote access,
or data exfiltration.

## 2. Scope and Methodology

The investigation used an existing PCAP file and passive network
traffic analysis.

Tools:
- Wireshark / TShark: packet and protocol inspection
- Zeek: connection, DNS, HTTP, TLS, and file-related logs
- Suricata: signature-based network alerts
- RITA: connection analysis and beacon-oriented review

The original capture was analyzed without modifying its contents.
Derived logs, timelines, and findings were saved separately.

## 3. Primary Finding: NetSupport-like Traffic

Source host: `10.11.26.183`
Destination IP: `194.180.191.64`
Destination port: TCP/443
HTTP URI: `http://194.180.191.64/fakeurl.htm`
User-Agent: `NetSupport Manager/1.3`
TCP streams: 77 and 140

### Evidence

- 58 HTTP POST requests were identified by Zeek.
- The requests used two source TCP ports.
- The observed request sequence spanned approximately 52.73 minutes.
- 51 of 57 intervals were between 50 and 70 seconds.
- The average interval was approximately 60.14 seconds.
- Suricata generated 58 `ET REMOTE_ACCESS NetSupport Remote Admin Checkin`
  alerts and 58 `ET INFO HTTP traffic on port 443 (POST)` alerts.
- Stream inspection showed `CMD=POLL` and repeated `CMD=ENCD`
  payloads. The available ASCII view did not establish the meaning
  of the encoded payload contents.

### Assessment

The regular timing and NetSupport identification are consistent
with beacon-like remote-administration communication. This is
suspicious, particularly if the software was not authorized.

However, legitimate remote-administration software can produce
similar traffic. The available packet evidence does not establish
whether the software was authorized or maliciously used.

The fact that client-to-server traffic exceeded server-to-client
traffic in the inspected streams is not, by itself, proof of
data exfiltration.

## 4. Additional TLS Destinations

### modandcrackedapk.com

- Resolved IP: `193.42.38.139`
- Destination port: TCP/443
- TLS SNI matching the domain was observed.
- Multiple TLS connections were recorded.
- The PCAP does not reveal the full encrypted application content.

Assessment: Requires investigation. The domain and connections
should be validated against trusted threat-intelligence sources
and correlated with endpoint telemetry.

### classicgrand.com

- Resolved IP: `213.246.109.5`
- Destination port: TCP/443
- TLS SNI matching the domain was observed.

Assessment: Requires investigation. The observed traffic alone
does not establish malicious activity.

### Temporal Relationship

The TLS connections occurred shortly before the first HTTP POST
observed in the NetSupport timeline. Temporal proximity does not
prove that these connections share a cause or are part of the same
attack chain.

## 5. IOC Summary

| Type | Indicator | Context | Assessment |
|---|---|---|---|
| IPv4 | `194.180.191.64` | NetSupport-like HTTP POST destination | High-priority suspicious |
| Domain | `modandcrackedapk.com` | TLS SNI observed | Requires investigation |
| IPv4 | `193.42.38.139` | TLS destination associated with the domain | Requires investigation |
| Domain | `classicgrand.com` | TLS SNI observed | Requires investigation |
| IPv4 | `213.246.109.5` | TLS destination associated with the domain | Requires investigation |

These are investigation indicators, not confirmed malicious IOCs.
Reputation and ownership can change over time.

## 6. MITRE ATT&CK Mapping

Potential mapping, subject to validation:

- **T1219 — Remote Access Software:** relevant if the NetSupport
  installation or use is confirmed to be unauthorized.

Command-and-control behavior is a hypothesis based on the repeated
communication pattern, not a confirmed ATT&CK technique from the
available evidence alone.

## 7. Limitations

- The analysis is based on a single PCAP dated 26 November 2024.
- Endpoint process, persistence, and execution telemetry was not
  available in the examined network evidence.
- TLS application content was not decrypted.
- Suricata alerts are detections, not proof of compromise.
- Zeek and Suricata analyzed the same capture; their agreement
  strengthens protocol-level corroboration but is not independent
  evidence from a separate source.
- No direct evidence of stolen data or confirmed exfiltration was
  established by these findings.

## 8. Recommendations

1. Verify whether NetSupport Manager was approved and expected on
   host `10.11.26.183`.
2. Review endpoint process execution, parent processes, installed
   software, scheduled tasks, services, and persistence artifacts.
3. Correlate the capture timestamps with EDR, Windows event,
   DNS, proxy, firewall, and authentication logs.
4. Investigate the two TLS domains using current, reputable
   threat-intelligence sources.
5. If unauthorized activity is confirmed, follow the organization's
   incident-response process, including containment and evidence
   preservation.
6. Preserve the original PCAP and record hashes for evidence integrity.

## 9. Conclusion

The strongest finding is repeated, approximately one-minute
NetSupport-like HTTP POST communication from `10.11.26.183` to
`194.180.191.64:443`.

This pattern merits prioritized investigation. Based on the
available PCAP alone, malicious execution, a confirmed C2 channel,
and data exfiltration remain unproven.
