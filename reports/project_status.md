# Project Status and Evidence Register

## 1. Purpose

This document records the verified state of the Network Traffic Analysis
& C2/Exfiltration Detection project. The Flutter Web blocker is resolved as
recorded in Section 14 below; publication and full evidence review remain pending.

It distinguishes observed evidence from interpretations and from work
that has not yet been verified as complete.

## 2. Repository State

- Git branch at the 2026-11-21 review: `feature/unified-detection-pipeline` (one commit ahead of `origin/feature/unified-detection-pipeline`). The repository also has pre-existing tracked modifications and untracked work; see `reports/FINALIZATION_REPORT.md` for the captured inventory.
- Remote: origin
- Canonical report directory: reports/
- The former duplicate incident report was moved to an external review archive.
- The archived report is preserved; the canonical report is reports/incident_report.md.
- The evidence/ directory contains local, currently untracked analysis artifacts.
- Raw PCAP files are excluded from Git by .gitignore.

## 3. Verified Analysis Environment

- TShark: 4.6.4
- Zeek: 8.0.10
- Suricata: 8.0.3
- suricata-update: 1.3.7
- RITA 4.8.2: available at `$HOME/tools/rita-v4.8.2/rita`; baseline Zeek 8.0.10 logs were imported into `soc_baseline_zeek810_20261027`. `show-beacons-sni` returned a score of 0.968 for source `10.11.26.183` and SNI `194.180.191.64` (58 connections). The executable is invoked by explicit path; PATH availability is not assumed.
- MongoDB: reachable and verified on 2026-11-04 through the existing `rita-mongo` container. Direct queries confirmed the stored baseline `beaconSNI` result. The earlier outage affected the original partial lab Beacon run; that dataset has not been re-imported or analyzed.
- NetworkMiner: not found in PATH during this review.
- Wireshark GUI: not found in the current Ubuntu PATH; this does not establish
  whether it is installed on the Windows host.

## 4. Baseline Capture

- Local evidence path: `pcaps/baseline.pcap` (intended to remain local and excluded from Git)
- Recorded SHA-256 reference: `a38267943a7bf3b0e445d7e51cb0a68b3dee797d67081bc9a033f73d079c0f50`
- Capture format: pcap
- Encapsulation: Ethernet
- Packet count (TShark): 26,922
- Capture start: 2024-11-26 04:49:38 UTC (06:49:38 +02:00 local display)
- Capture end: 2024-11-26 05:43:58 UTC (07:43:58 +02:00 local display)
- TShark HTTP request filter count in the existing record: 74

The local file exists and its SHA-256 matches the recorded reference. It is intentionally excluded from Git publication.
## 5. Observed NetSupport-like Traffic

The current incident report and supporting artifacts document:

- Internal host: 10.11.26.183
- External destination: 194.180.191.64:443
- HTTP URI observed: /fakeurl.htm
- User-Agent observed: NetSupport Manager/1.3
- 58 HTTP POST requests were reported in the existing analysis.
- Suricata generated NetSupport remote-access and HTTP POST alerts.
- Repeated timing was reported in the existing timeline analysis.

These observations are suspicious and warrant investigation. They do not,
on their own, prove unauthorized access, malware infection, command execution,
or data exfiltration.

## 6. Additional TLS Observations

The existing evidence records TLS connections from 10.11.26.183 to
193.42.38.139:443 with SNI modandcrackedapk.com.

- Eight distinct TCP stream IDs were returned by the reviewed SNI filter.
- No HTTP requests matching the modandcrackedapk hostname or URI were returned
  by the reviewed HTTP filter.
- The file evidence/modandcrackedapk_http.tsv is empty.

The empty HTTP file must not be interpreted as proof that no application data
was exchanged. TLS payload content is encrypted in the capture, and the reason
for the empty export has not yet been established.

The existing report also documents TLS observations involving classicgrand.com.
Those observations require the same cautious interpretation.

## 7. Evidence Quality Notes

- evidence/pcap_sha256.txt records the verified hash using the
  repository-relative path pcaps/baseline.pcap; the hash matches
  the current repository PCAP.
- evidence/modandcrackedapk_http.tsv is zero bytes. The current review found no matching HTTP requests for this domain; TLS SNI and DNS observations exist. Document the export filter/source command before regenerating it.
- evidence/stream77.txt and evidence/stream77_full.txt were verified
  identical by SHA-256. Both copies are preserved pending a documented decision
  about which file should be canonical.
- evidence/ contains untracked artifacts. The former report/ directory was
  archived after its duplicate report was moved; verify Git status before staging.
- Existing evidence files have not yet undergone a complete content and
  publication-safety review.
- A keyword search for common credential terms returned no matches. This is
  not a guarantee that the artifacts contain no sensitive information.

## 8. Verified Work and Outstanding Items

Verified completed work:
- Core analysis tools were available and used for the reviewed PCAP investigations.
- Baseline Zeek logs were imported into RITA 4.8.2, and the SNI beacon result was recorded.
- A benign local lab simulation was executed and documented.
- A controlled Beacon simulation was partially completed: 87 requests/connections were captured and analyzed with Zeek; RITA analysis of this partial dataset has not been performed. MongoDB was restored later, but the partial dataset has not been re-imported or assessed; its duration is below the configured multi-hour thresholds.
- Detector validation was performed on reviewed captures; this does not represent comprehensive validation of every detection scenario.

Outstanding work:
- Re-import and assess the partial Beacon dataset using the restored MongoDB backend, while documenting that its 87-connection capture is shorter than RITA's configured multi-hour analysis thresholds.
- Perform endpoint/process correlation for the suspicious PCAP findings where endpoint evidence is unavailable.
- Validate DNS tunneling detection with a documented, reproducible test and supporting artifacts.
- Validate controlled data-exfiltration detection with a documented, reproducible test and supporting artifacts.
- Complete cross-tool correlation and review all reports and evidence for publication.
- Do not describe the lab Beacon simulation as real C2, or the benign HTTP transfer as successful malicious exfiltration.

## 9. Next Actions

1. Complete final QA of the project status, evidence inventory, detection coverage matrix, README, and runbook.
2. Review evidence provenance and compare duplicate files without deleting preserved copies.
3. Preserve and re-verify PCAP hashes if captures are moved or replaced.
4. Explain or regenerate the empty HTTP export only after identifying its intended filter and source command.
5. Verify report-to-PCAP mapping and source evidence for each investigation.
6. Reassess the partial Beacon dataset with RITA now that MongoDB is available; do not claim a complete Beacon result unless the configured duration requirements and supporting evidence are satisfied.
7. Complete endpoint correlation and the outstanding DNS tunneling and data-exfiltration validation.
8. Review files for sensitive content and accidental inclusion of PCAPs, executables, or large generated logs before publication.
9. Review the final Git diff before any future staging, commit, or push.

## 10. Assessment Standard

For each finding, record the source PCAP and hash, the tool and relevant
filter or rule, the observed result, the interpretation, and the limitations.
An alert or periodic connection is an indicator for investigation, not proof
of compromise or exfiltration.

## 11. Additional Investigation: runner_ilove.exe

A separate investigation report has been prepared for the
`2026-10-01-traffic-analysis-exercise.pcap` capture.

- Dedicated report: `reports/incident_runner_ilove.md`
- IOC list: `reports/runner_ilove_iocs.csv`
- Evidence checklist: `reports/runner_ilove_evidence_checklist.md`
- Observed transfer: HTTP 200 from `107.175.82.242:9000`, URI
  `/wilow/runner_ilove.exe`, response body `1,646,592` bytes.
- Extracted sample SHA-256:
  `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061`
- Threat-intelligence correlation is documented in the dedicated report.
- The later connection to `195.63.128.106:443` remains under investigation.

### Status and limitations

The packet evidence supports documenting the executable transfer and
prioritizing defensive investigation. It does not independently prove that
the executable ran, that the host was compromised, that the later connection
was initiated by the executable, or that data was exfiltrated.

The following remain outstanding until supported by recorded results:
- Correlate the later connection with endpoint and process telemetry.
- Review the IOC list against the environment and trusted current sources.
- Resolve the provenance of the empty `evidence/modandcrackedapk_http.tsv`.
- Review all proposed Git changes for sensitive information and accidental
  inclusion of PCAPs, executables, or large generated analysis logs.
- Review the reports and staged diff before any commit or push.

## 12. Reviewed Investigation Reports

The following reports and their evidence have been reviewed at different levels of completeness:

- `reports/incident_report.md`: NetSupport-like repeated HTTP POST activity and remote-administration-related alerts; suspicious, but not proof of compromise or exfiltration.
- `reports/formbook_investigation_report.md`: FormBook-related HTTP traffic from `172.16.8.49` (113 POST requests plus GET check-ins) to 15 destination groups, with 18 `FormBook CnC Checkin (GET) M5` Suricata alerts; execution, data theft and exfiltration are not established.
- `reports/incident_runner_ilove.md`: suspicious executable download documented with HTTP response details and extracted sample SHA-256; execution and causal linkage to later traffic remain unconfirmed.
- `reports/incident_webinvestigation.md`: draft investigation of SQL injection, directory enumeration, login, and PHP upload indicators; successful execution, compromise, callback, and exfiltration remain unconfirmed.
- `reports/incident_netmetria.md`: draft investigation of SMB enumeration and file-write observations; service creation/start, lateral movement, C2, and exfiltration are not established.
- `reports/incident_lab_simulation.md`: benign local lab simulation report.
- `reports/scenario_02_beaconing.md`: controlled Beacon simulation report; partial run only.

## 13. Simulation and Validation Boundaries

- The benign lab simulation generated DNS and HTTP activity in a controlled local environment. Its observed outputs and limitations are documented in `reports/incident_lab_simulation.md`.
- The controlled Beacon simulation produced 87 periodic HTTP GET requests/connections at approximately 60-second intervals. This is a scripted lab behavior, not evidence of real-world C2.
- RITA analysis of the partial Beacon dataset was not completed during the original run because MongoDB was unavailable. MongoDB has since been restored, but the partial dataset still requires a separate import and assessment; the baseline SNI result is not a result for the lab simulation. The successful baseline RITA import and SNI result must not be confused with a completed RITA analysis of the Beacon dataset.
- DNS tunneling, real malicious C2, successful data exfiltration, and execution of suspicious downloaded files remain unconfirmed unless separately supported by evidence.

## 14. Flutter Web and Browser QA Update (2026-11-21)

The Flutter Web release build and browser integration checks have been completed in the native Windows QA copy. `flutter analyze` reported no issues, all 12 Flutter tests passed, and `flutter build web --release --dart-define=API_BASE_URL=http://127.0.0.1:8000` succeeded. In a real browser, the dashboard was verified against FastAPI and the local 129-alert dataset: search, combined filters, sorting, pagination, alert details, and backend-unavailable/retry recovery were exercised. See `reports/FINALIZATION_REPORT.md` Section 14 for observed results. These checks were not rerun during this documentation update.

The earlier UNC shader-output failure is resolved by using a native Windows filesystem for the Flutter QA copy. The PCAP, 129-alert generated dataset, raw engine logs, and build output remain local and are excluded from publication. This update does not constitute a complete review or clearance of the entire `evidence/` directory; report and evidence provenance/content review remains a publication task.
