# Detection Engineering Matrix

## Network Traffic Analysis & C2 / Exfiltration Detection

**Status:** Updated working document — observed behavior, detection evidence, and validation are tracked separately.

**Scope:** PCAP-based network traffic analysis and detection using Zeek, Suricata, and TShark, with RITA used where applicable.

## 1. Purpose

This matrix defines the project's network detection use cases, required telemetry, candidate detection logic, available evidence, validation status, and known limitations.

Three different states must remain separate:

- **Behavior Evidence:** The activity or traffic pattern is present in the reviewed capture.
- **Detection Evidence:** A security tool or detection rule actually generated a relevant alert or finding.
- **Validation Status:** The detection was tested sufficiently to establish whether it identifies the intended behavior and how it behaves against benign traffic.

A behavior observed in a PCAP is not automatically a successful detection. An alert alone does not prove malware execution, command-and-control (C2), host compromise, lateral movement success, or data exfiltration.

## 2. Detection Coverage Matrix

| ID | Detection use case | MITRE ATT&CK mapping | Required telemetry | Candidate detection logic | Behavior evidence | Detection evidence | Validation status |
|---|---|---|---|---|---|---|---|
| DET-01 | Suspicious executable download | [T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) — observed file transfer; adversarial interpretation supported by threat intelligence | Zeek `http.log`, `files.log`; Suricata alerts; file hash | Successful HTTP download of an executable combined with destination, URI, file, or reputation context | Observed in `2026-10-01-traffic-analysis-exercise.pcap`; `runner_ilove.exe` downloaded successfully | Threat-intelligence hash match is documented; general reusable rule validation is not established | Partial — investigation evidence exists; general rule and benign comparison pending |
| DET-02 | Periodic outbound beaconing | Not assigned — periodicity alone does not establish adversarial C2 | Zeek `conn.log`; DNS/TLS metadata; RITA where applicable | Repeated connections to the same destination with consistent intervals over a meaningful observation window | Periodic NetSupport-like traffic observed in `baseline.pcap`; partial controlled Beacon run retained | Suricata generated relevant NetSupport remote-access and HTTP POST alerts in the baseline investigation | Partial — existing timing analysis and partial Beacon run; baseline RITA SNI analysis recorded; controlled Beacon RITA validation not completed |
| DET-03 | Potential HTTP-based C2 | [T1071.001 – Web Protocols](https://attack.mitre.org/techniques/T1071/001/) — potential mapping for FormBook-signature-associated HTTP activity only; C2 not independently confirmed | Zeek `http.log`, `conn.log`; Suricata alerts | Repeated POST requests, unusual URI patterns, destination context, recurring request sizes, and supporting indicators | Repeated POST activity observed in the 2026-08-09 capture; additional HTTP activity observed in WebInvestigation | Suricata alerts exist for selected HTTP activity; these do not establish C2 attribution | Partial — traffic and alert evidence exist; C2 remains unconfirmed |
| DET-04 | Potential HTTP data exfiltration | Not assigned — controlled HTTP POST transfer does not establish adversarial exfiltration | HTTP request/body lengths; Zeek connection byte counts; destination context | Unusual outbound request volume, repeated uploads, and suspicious destination or payload context | Controlled lab simulation transferred 20 HTTP POST bodies totaling 5,242,880 bytes; this is benign test traffic, not confirmed exfiltration | Zeek recorded the HTTP POST activity; Suricata output includes alerts that require contextual interpretation | Partial — transfer generation and logging demonstrated; malicious exfiltration detection not validated |
| DET-05 | DNS tunneling or unusual DNS activity | Not assigned — unusual DNS characteristics alone do not establish tunneling | Zeek `dns.log`; query names, lengths, types, rates, and response patterns | Long or high-entropy labels, excessive unique subdomains, abnormal query rates, and unusual record types | Lab simulation generated 70 DNS queries, 63 unique names, mean query length 94.5 characters, maximum 108; 60 queries exceeded 50 characters | Zeek DNS telemetry is available; no confirmed DNS-tunneling alert is established | Partial — DNS traffic generation and analysis available; tunneling detection and benign comparison pending |
| DET-06 | Suspicious TLS destination | Not assigned — TLS metadata alone does not establish a specific ATT&CK technique | Zeek `ssl.log` or `conn.log`; DNS; threat intelligence | Suspicious destination/SNI, certificate context, unusual connection behavior, and attributable intelligence | TLS observations exist in the baseline and Netmetria investigations | Relevant TLS metadata is recorded; no single TLS observation proves malicious activity | Partial — metadata available; contextual and intelligence validation required |
| DET-07 | Threat-intelligence IOC match | Not assigned — an IOC match is not itself a behavior technique | DNS, HTTP, TLS, connection logs, file hashes | Match observed indicators against dated and attributable intelligence sources | `runner_ilove.exe` sample hash is recorded in the dedicated investigation | A ThreatFox hash match is reported in `reports/incident_runner_ilove.md` | Partial — reported hash correlation; source freshness and environmental relevance require review |
| DET-08 | Large or anomalous outbound transfer | Not assigned — transfer volume alone does not establish exfiltration | Zeek `conn.log`; HTTP/file metadata; protocol logs | Unusual byte counts, long sessions, rare destinations, and deviation from known benign behavior | Controlled HTTP transfer of 5,242,880 request-body bytes observed in lab simulation | Zeek records 20 POST requests; this is a controlled test, not a malicious transfer | Partial — volume telemetry demonstrated; anomaly thresholds and false-positive behavior pending |
| DET-09 | Suspicious protocol/port mismatch | Not assigned — protocol/port mismatch alone does not establish a specific technique | Zeek `conn.log`, HTTP/TLS metadata; Suricata alerts | Application protocol inconsistent with expected service behavior, such as plaintext HTTP on port 443 | HTTP on port 443 observed in the NetSupport-like baseline | Suricata alerts are documented for the related NetSupport-like activity | Partial — observed protocol/port mismatch; legitimacy and malicious attribution remain unconfirmed |
| DET-10 | Correlation of download and follow-on activity | Not assigned — temporal correlation does not establish execution or causal C2 activity | Zeek `http.log`, `files.log`, `conn.log`, DNS/TLS; endpoint telemetry where available | Correlate host, timestamps, file/hash, process evidence, destinations, and subsequent connections | Runner iLove download and later connection to `195.63.128.106:443` are recorded; WebInvestigation also contains upload and follow-up HTTP requests | Network evidence supports temporal correlation only; no causal endpoint evidence is available | Partial — network timeline exists; execution and causal attribution are unconfirmed |

## 3. Candidate Detection Logic

The following logic describes investigation heuristics, not production-ready universal thresholds. Thresholds must be calibrated against available suspicious and benign traffic.

### DET-01 — Suspicious Executable Download

Raise an investigation finding when:

- HTTP returns a successful response for a file identified as an executable by file analysis or reliable metadata.
- The destination, URI, client behavior, or threat-intelligence context is unusual.
- Response size and extracted file metadata are consistent across relevant logs.

Required enrichment:

- Source and destination IP/port.
- Timestamp and timezone.
- HTTP method, host, URI, status, and user agent.
- Zeek connection UID and file identifier, where available.
- SHA-256 of the extracted file.
- Suricata signature and signature ID, if present.

**Limitations:** A successful download does not establish execution or endpoint compromise.

### DET-02 — Periodic Beaconing

For each candidate destination:

1. Group connections by source host and destination IP/port.
2. Sort connection timestamps and calculate consecutive intervals.
3. Record interval count, median interval, interval spread, total duration, and byte counts.
4. Compare the result with expected software and infrastructure behavior.
5. Investigate recurring patterns alongside DNS, TLS, and endpoint telemetry.

Do not classify traffic as C2 based only on regular intervals. Legitimate management software, update agents, monitoring systems, and remote support tools can also generate periodic connections.

**Project note:** The partial Beacon simulation is retained as preliminary evidence. The decision to avoid a long rerun is intentional. RITA limitations and the scope of the partial analysis must be documented rather than represented as completed validation.

### DET-03 — Suspicious HTTP POST Activity

Prioritize investigation when multiple signals coincide:

- Repeated POST requests to an unusual host or URI.
- Large or repetitive request bodies.
- Unusual user-agent or HTTP header patterns.
- Recurring timing or uncommon destination infrastructure.
- Supporting IDS alerts or threat-intelligence matches.

Record request-body lengths and response-body lengths separately.

Do not label request traffic as exfiltration until direction, payload context, and destination purpose have been assessed.

### DET-04 — Potential HTTP Data Exfiltration

Review:

- Request-body bytes separately from response-body bytes.
- Number and frequency of outbound uploads.
- Destination ownership, reputation, and expected business purpose.
- Whether the transfer is unusually large relative to the host's baseline.
- Whether the traffic contains sensitive or otherwise relevant content, where authorized inspection is available.

The controlled lab's 20 POST requests and 5,242,880 transferred request-body bytes demonstrate a repeatable HTTP transfer scenario. They do not demonstrate malicious exfiltration.

### DET-05 — Potential DNS Tunneling

Review:

- Query length and label length distributions.
- Number of unique subdomains under each registered domain.
- Query rate per client and time window.
- Unusual record types and response patterns.
- Domain reputation and whether the observed pattern fits known applications.

High entropy, long labels, or high query volume are supporting signals only. DNS tunneling requires corroboration and comparison with normal activity.

The lab DNS simulation demonstrates DNS query generation and logging, not confirmed tunneling.

### DET-06 — Suspicious TLS Destination

Review:

- Source and destination IP/port.
- TLS SNI and DNS resolution, where available.
- Certificate metadata, where available.
- Connection frequency, duration, and byte counts.
- Destination reputation and known business context.

Encryption or an unusual SNI alone is not proof of malicious activity. Missing HTTP visibility may be expected when application data is encrypted.

### DET-07 — Threat-Intelligence IOC Match

For every match, record:

- Exact indicator and indicator type.
- Intelligence provider and source reference.
- Lookup date and, where available, confidence or context.
- Whether the indicator was directly observed in the PCAP or only reported by an external source.
- Whether the match applies to a file hash, domain, IP address, or URL.

A threat-intelligence match is supporting evidence. It does not independently establish execution, compromise, or malicious activity in the investigated environment.

### DET-08 — Large or Anomalous Outbound Transfer

Review:

- Connection byte counts and direction.
- Transfer duration and destination.
- Protocol and application context.
- Number of transfers and recurrence.
- Deviation from known benign activity.

Do not use a single universal byte threshold without a defensible baseline.

The controlled HTTP transfer is useful for checking telemetry and analysis workflows. Its volume must not be reported as a real exfiltration incident.

### DET-09 — Suspicious Protocol/Port Mismatch

Investigate cases where:

- Observed application protocol differs from the expected service on the destination port.
- HTTP metadata appears on a port commonly associated with TLS.
- The destination, user agent, URI, and connection pattern are unusual.
- Other indicators support investigation.

A port mismatch is a triage signal, not a verdict. Document the actual application protocol rather than inferring it from the port number.

### DET-10 — Download and Follow-on Activity Correlation

When a suspicious executable download is observed:

- Build a timeline around the download.
- Identify subsequent connections from the same host.
- Compare destination, protocol, TLS metadata, duration, and byte counts.
- Check DNS and HTTP evidence for links between the destination and the downloaded file.
- Seek endpoint process and file-creation telemetry if available.

Temporal proximity is not proof of causation. Keep observed connections separate from threat-intelligence-only indicators.

## 4. Additional Investigation Coverage

### Netmetria-focused scenario

Evidence report: `reports/incident_netmetria.md`

Supporting evidence: `evidence/netmetria/`

Observed behavior:

- Host `10.42.10.21` enumerated shares on five internal servers.
- The same host made five `OpenSCManagerW` requests, with corresponding responses.
- The host accessed `ADMIN$` on the five servers.
- A 96-byte SMB2 write associated with `q4-summary.bin` was observed for each server.

Detection and limitations:

- Suricata generated 22 alerts, all `ET INFO Microsoft Connection Test`.
- No Suricata alert for the observed SMB/RPC sequence was identified in the reviewed output.
- No `CreateServiceW` or `StartServiceW` operation was observed in the reviewed RPC evidence.
- Authentication details and the purpose/content of the written file remain unconfirmed.
- RITA was not used to validate this scenario.

Assessment: The sequence is consistent with activity worth investigating for possible lateral-movement staging. It does not prove successful service creation, execution, or compromise.

### WebInvestigation scenario

Evidence report: `reports/incident_webinvestigation.md`

Supporting evidence: `evidence/webinvestigation/`

Observed behavior:

- SQL injection scanning activity and directory enumeration were observed from `111.224.250.131`.
- Requests referencing `bookworld_db` were observed.
- A PHP upload named `NVri2vhp.php` was observed; the extracted file part was 79 bytes.
- The extracted content contained PHP, `exec`, `/dev/tcp`, and `bash` strings.
- The request body referenced `111.224.250.131:443` as a potential callback target.

Detection and limitations:

- Suricata with the original default `HOME_NET` produced zero alerts in the reviewed run.
- A rerun with `-k none` and the same default `HOME_NET` also produced zero alerts.
- A rerun with `-k none` and `HOME_NET` set to `73.124.22.0/24` produced 210 alerts.
- The comparison demonstrates that `HOME_NET` configuration affected alert visibility in this capture. It does not establish that every rule was effective or ineffective.
- No connection originating from the web server to `111.224.250.131:443` was observed in the PCAP.
- PHP execution, successful callback, and server compromise remain unconfirmed.

Assessment: The upload content is consistent with a reverse-shell-style payload, but packet evidence alone does not establish execution or successful compromise.

### Controlled lab simulation

Evidence directory: `simulations/lab_sim/lab_sim_20261103_232117/`

Observed test activity:

- Nmap SYN scan command targeted TCP ports 1–1000.
- Nmap reported 25/tcp, 465/tcp, and 587/tcp open; 997 ports closed.
- Zeek recorded 70 DNS queries, including 63 unique query names.
- Zeek recorded 20 HTTP POST requests with a total of 5,242,880 request-body bytes.
- The simulation PCAP contains 2,635 packets and is approximately 74.5 seconds long.

Detection and limitations:

- Suricata default-HOME_NET output included 20 Python BaseHTTP ServerBanner alerts and checksum-related alerts.
- The alternate HOME_NET run retained the checksum-related alerts but did not show the same Python server-banner alert.
- The simulation used loopback traffic. Checksum alerts may be affected by loopback capture or checksum offload behavior; this explanation has not been conclusively verified.
- The host also had Courier SMTP listeners on ports 25, 465, and 587 when checked. These ports must not be attributed to the custom simulation server, which implemented DNS and HTTP services.
- The Nmap command defines the intended scan range. Zeek's distinct TCP destination-port count must not be presented as the number of Nmap ports scanned.

Assessment: The simulation demonstrates traffic generation and multi-tool telemetry collection. It is not evidence of a real attack or successful malicious exfiltration.

### Partial Beacon simulation

Evidence directory: `simulations/lab_beacon/lab_beacon_20261102_211623/`

Available artifacts:

- `capture.pcap`
- `analysis_summary.txt`
- `client.log`
- `server.log`
- `tcpdump.err`

Assessment: The artifacts support retaining the partial controlled Beacon run for preliminary analysis. The project intentionally does not require an additional 11–12 hour rerun. RITA scoring and full threshold validation must not be claimed as completed.

## 5. Validation Plan

Each detection should be evaluated against the following:

1. **Positive evidence:** At least one capture contains the behavior the detection is intended to identify.
2. **Benign comparison:** Test against known legitimate traffic and record false positives.
3. **Reproducibility:** Document tool versions, input capture hash, filters, commands, and output location.
4. **Evidence integrity:** Preserve original PCAPs and extracted samples; calculate SHA-256 hashes.
5. **Coverage:** Identify missing telemetry and cases where encryption or packet loss limits visibility.
6. **Configuration:** Record relevant settings such as `HOME_NET`, checksum validation, and enabled rules.
7. **Limitations:** Record what the detection cannot establish.
8. **Repeatability:** Re-run the same analysis on the same input and compare outputs.

A successful rule execution is not equivalent to a validated detection. Validation requires checking that the rule identifies the intended behavior and does not indiscriminately flag benign traffic.

## 6. Metrics to Track

For each detection use case, record:

- Number of candidate events.
- Number of manually reviewed events.
- Relevant alerts and supporting event rows.
- Confirmed findings for the specific claim being made.
- False positives and their causes.
- Required telemetry availability.
- Missed detections identified during review.
- Runtime and reproducibility.
- Tool versions and relevant configuration.
- Known limitations.

Do not report precision, recall, or false-positive rate unless suitable labeled ground truth is available.

## 7. Outstanding Work

The following reflects the agreed reduced project scope. Completed documentation tasks are marked accordingly; remaining investigation and final QA tasks are kept open.

- [x] Document the partial Beacon analysis and its RITA/MongoDB limitations.
- [ ] Complete final review of the Netmetria investigation and its cautious lateral-movement assessment.
- [x] Complete the simple Nmap, DNS-query, and HTTP POST simulation documentation.
- [x] Review MITRE ATT&CK mappings in the FormBook and Runner iLove reports.
- [x] Align the Detection Coverage Matrix with verified investigation and simulation evidence.
- [x] Document the Suricata `HOME_NET` configuration issue and its effect on alert visibility.
- [x] Prepare the project Runbook covering execution and WSL restart.
- [x] Update README, Project Status, and Evidence Inventory to match verified work.
- [ ] Perform final report, IOC, and publication-safety QA.
- [ ] Verify that PCAPs, extracted executables, sensitive content, and large generated artifacts are not staged for Git publication.

Explicitly excluded from the remaining scope:

- Long Beacon simulation rerun.
- Full VirtualBox Kali lab.
- NetworkMiner installation inside WSL.
- Sliver or real C2 deployment.
- dnscat2/iodine DNS tunneling setup.
- Re-analysis of already completed PCAPs.
- Deletion of backups or stray files without explicit approval.

## 8. Reporting Standard

Every finding must distinguish:

- **Observed:** Directly present in packet captures or logs.
- **Correlated:** Supported by multiple evidence sources, without necessarily proving causation.
- **Threat-intelligence match:** Reported by an external source, with source and lookup date documented.
- **Hypothesis:** Plausible explanation requiring further validation.
- **Detection observed:** A relevant tool alert or analytic result was actually generated.
- **Validated detection:** The detection was tested against appropriate positive and benign evidence, with configuration and limitations documented.
- **Confirmed conclusion:** Supported by sufficient evidence for the specific claim.

Never promote a hypothesis to a confirmed conclusion solely because an IDS alert fired, a domain looks suspicious, a connection occurred after a download, a file contains suspicious strings, or a transfer has a large byte count.
