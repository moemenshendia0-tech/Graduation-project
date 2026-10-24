# Detection Engineering Matrix
## Network Traffic Analysis & C2 / Exfiltration Detection

**Status:** Working document — implementation and validation are tracked separately.  
**Scope:** PCAP-based network detection using Zeek, Suricata, and TShark.

## 1. Purpose

This matrix defines the detection use cases, required telemetry, detection logic, expected false positives, validation procedures, and current evidence status for the project.

A detection hypothesis must not be reported as a confirmed incident until supporting evidence has been reviewed. An alert alone does not prove malware execution, command-and-control (C2), host compromise, or data exfiltration.

## 2. Detection Coverage Matrix

| ID | Detection use case | Required telemetry | Detection logic | Current status |
|---|---|---|---|---|
| DET-01 | Suspicious executable download | Zeek `http.log`, `files.log`; Suricata alerts | HTTP response containing an executable, especially with an unusual destination, URI, or client | Observed in `2026-10-01-traffic-analysis-exercise.pcap`; general rule validation pending |
| DET-02 | Periodic outbound beaconing | Zeek `conn.log`; DNS and TLS logs where available | Repeated connections to the same destination with consistent intervals over a meaningful observation window | Observed periodic NetSupport-like traffic in `baseline.pcap`; formal threshold testing pending |
| DET-03 | Potential HTTP-based C2 | Zeek `http.log`, `conn.log`; Suricata alerts | Repeated POST requests, unusual URI patterns, suspicious destination context, and recurring request sizes | Suspicious POST activity observed in the 2026-08-09 capture; C2 attribution remains unconfirmed |
| DET-04 | Potential data exfiltration over HTTP | HTTP request metadata and body lengths; connection byte counts | Large or repeated outbound request bodies, unusual upload volume, and destination/context anomalies | Candidate activity observed; exfiltration is not confirmed |
| DET-05 | DNS tunneling or unusual DNS activity | Zeek `dns.log` | High query volume, unusually long or high-entropy subdomains, excessive unique labels, and abnormal query types | Validation pending; ordinary DNS volume alone is insufficient |
| DET-06 | Suspicious TLS destination | Zeek `ssl.log` or `conn.log`, DNS, threat intelligence | Unusual destination, suspicious SNI/domain, certificate context where available, and abnormal connection behavior | Partial telemetry available; encryption alone is not evidence of malicious activity |
| DET-07 | Threat-intelligence IOC match | DNS, HTTP, TLS, connection logs, file hashes | Match observed indicators against dated, attributable intelligence sources | Hash match reported for `runner_ilove.exe`; other intelligence-only indicators must remain clearly labeled |
| DET-08 | Large or anomalous outbound transfer | Zeek `conn.log`, protocol logs | Unusual outbound byte counts, long sessions, rare destinations, and deviation from a known baseline | Candidate sessions require contextual analysis; byte volume alone is not proof of exfiltration |
| DET-09 | Suspicious protocol/port mismatch | Zeek `conn.log`, HTTP/TLS metadata | Application protocol inconsistent with expected service behavior, such as plaintext HTTP on port 443 | HTTP on port 443 observed in the NetSupport-like baseline; investigate context before attribution |
| DET-10 | Correlation of download and follow-on activity | Zeek `http.log`, `files.log`, `conn.log`, DNS/TLS logs; endpoint telemetry if available | Correlate host, timestamps, process/file evidence, destinations, and subsequent connections | Partial network correlation exists; execution and causal attribution require additional evidence |

## 3. Candidate Detection Logic

These are investigation heuristics, not production-ready universal thresholds. Thresholds must be calibrated against the available captures and documented benign traffic.

### DET-01 — Executable Download

Raise an investigation finding when:
- HTTP returns a successful response for a file identified as an executable by file analysis or MIME metadata.
- The destination, URI, client behavior, or threat-intelligence context is unusual.
- The response size and extracted file metadata are consistent across the relevant logs.

Required enrichment:
- Source and destination IP/port.
- Timestamp and timezone.
- HTTP method, host, URI, status, and user agent.
- Zeek connection UID and file identifier, where available.
- SHA-256 of the extracted file.
- Suricata alert signature and signature ID, if present.

**Limitations:** A successful download does not establish that the file was executed or that the endpoint was compromised.

### DET-02 — Periodic Beaconing

For each candidate destination:
1. Group connections by source host and destination IP/port.
2. Sort connection timestamps and calculate consecutive time intervals.
3. Record interval count, median interval, interval spread, total duration, and byte counts.
4. Compare the result with expected software and infrastructure behavior.
5. Investigate recurring patterns alongside DNS, TLS, and endpoint telemetry.

Do not classify traffic as C2 based only on a regular interval. Legitimate management software, update agents, monitoring systems, and remote support tools can also generate periodic connections.

### DET-03 — Suspicious HTTP POST Activity

Prioritize investigation when multiple signals coincide:
- Repeated POST requests to an unusual host or URI.
- Large or repetitive request bodies.
- Unusual user-agent or HTTP header patterns.
- Recurring timing or uncommon destination infrastructure.
- Supporting IDS alerts or threat-intelligence matches.

Record request-body lengths and response-body lengths separately. Do not label request traffic as exfiltration until the direction, payload context, and destination purpose have been assessed.

### DET-04 — Potential DNS Tunneling

Review:
- Query length and label length distributions.
- Number of unique subdomains under each registered domain.
- Query rate per client and time window.
- Unusual record types and response patterns.
- Domain reputation and whether the observed pattern fits known applications.

High entropy, long labels, or high query volume are supporting signals only. DNS tunneling requires corroboration and comparison with normal activity.

### DET-05 — Follow-on Network Activity

When an executable download is observed:
- Build a timeline around the download.
- Identify subsequent connections from the same host.
- Compare destination, protocol, TLS metadata, duration, and byte counts.
- Check DNS and HTTP evidence for links between the destination and the downloaded file.
- Seek endpoint process and file-creation telemetry if available.

Temporal proximity is not proof of causation. Keep observed connections separate from threat-intelligence-only indicators.

## 4. Validation Plan

Each detection should be evaluated against the following:

1. **Positive evidence:** At least one capture contains the behavior the detection is intended to identify.
2. **Benign comparison:** Test against known legitimate traffic and record false positives.
3. **Reproducibility:** Document tool versions, input capture hash, filters, commands, and output location.
4. **Evidence integrity:** Preserve original PCAPs and extracted samples; calculate SHA-256 hashes.
5. **Coverage:** Identify missing telemetry and cases where encryption or packet loss limits visibility.
6. **Limitations:** Record what the detection cannot establish.
7. **Repeatability:** Re-run the same analysis on the same input and compare outputs.

A successful rule execution is not equivalent to a validated detection. Validation requires checking that the rule identifies the intended behavior and does not indiscriminately flag benign traffic.

## 5. Metrics to Track

For each detection use case, record:

- Number of candidate events.
- Number of manually reviewed events.
- Confirmed relevant findings.
- False positives and their causes.
- Required telemetry availability.
- Missed detections identified during review.
- Runtime and reproducibility.
- Known limitations.

Do not report precision, recall, or false-positive rate unless suitable labeled ground truth is available.

## 6. Current Project Evidence

### Suspicious executable download

The 2026-10-01 capture contains a successful HTTP download of `runner_ilove.exe` to host `10.10.1.128` from `107.175.82.242:9000`, path `/wilow/runner_ilove.exe`. The recorded response body is 1,646,592 bytes.

SHA-256:

`b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061`

The sample has a reported threat-intelligence match. Its download is supported by network evidence; execution, persistence, compromise, and exfiltration are not established by the download alone.

### Periodic NetSupport-like traffic

The baseline capture contains repeated HTTP POST traffic to `194.180.191.64:443` with user agent `NetSupport Manager/1.3`. This warrants investigation of the software's authorization and purpose. The observed pattern does not, by itself, establish unauthorized remote access or malicious C2.

### Repeated HTTP POST activity

The 2026-08-09 capture contains repeated POST requests to `www.grinswakebthu.info` at `146.59.71.167:80`. This is a candidate for HTTP behavior analysis. Confirming C2 or exfiltration requires payload and contextual evidence.

## 7. Outstanding Work

- [ ] Implement and test reusable detection queries or scripts.
- [ ] Record exact Zeek and Suricata versions and configuration used for each run.
- [ ] Validate candidate rules against benign and suspicious captures.
- [ ] Establish defensible thresholds from the available data.
- [ ] Export supporting event rows with timestamps and connection identifiers.
- [ ] Document false positives and missed detections.
- [ ] Add controlled test traffic only with clearly documented provenance.
- [ ] Link each final finding to its evidence source and limitations.
- [ ] Review the matrix after each detection is implemented and validated.

## 8. Reporting Standard

Every finding must distinguish:

- **Observed:** Directly present in packet captures or logs.
- **Correlated:** Supported by multiple independent evidence sources.
- **Threat-intelligence match:** Reported by an external source, with source and lookup date documented.
- **Hypothesis:** Plausible explanation requiring further validation.
- **Confirmed conclusion:** Supported by sufficient evidence for the specific claim.

Never promote a hypothesis to a confirmed conclusion solely because an IDS alert fired, a domain looks suspicious, a connection occurred after a download, or a file has high entropy.
