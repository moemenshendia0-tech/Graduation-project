# Project Status and Evidence Register

## 1. Purpose

This document records the verified state of the Network Traffic Analysis
& C2/Exfiltration Detection project at the time of review.

It distinguishes observed evidence from interpretations and from work
that has not yet been verified as complete.

## 2. Repository State

- Git branch: main
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
- RITA: not found in PATH during this review.
- NetworkMiner: not found in PATH during this review.
- Wireshark GUI: not found in the current Ubuntu PATH; this does not establish
  whether it is installed on the Windows host.

## 4. Baseline Capture

- Repository path: pcaps/baseline.pcap
- SHA-256: a38267943a7bf3b0e445d7e51cb0a68b3dee797d67081bc9a033f73d079c0f50
- Capture format: pcap
- Encapsulation: Ethernet
- Approximate packet count reported by capinfos: 26,000
- Capture start: 2024-11-26 06:49:38
- Capture end: 2024-11-26 07:43:58
- TShark HTTP request filter count: 74

The recorded SHA-256 matches the repository PCAP. The evidence hash record uses
the repository-relative path pcaps/baseline.pcap.

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

## 8. Work Not Yet Verified as Complete

The following must not be marked complete without supporting artifacts or
execution records:

- RITA analysis
- Controlled attack simulations
- DNS tunneling detection validation
- Controlled data-exfiltration detection validation
- Full correlation of all investigation results
- Final review of all reports and evidence for publication

## 9. Next Actions

1. Review evidence provenance and compare duplicate files.
2. Preserve and re-verify the PCAP hash if the capture is moved or replaced.
3. Explain or regenerate the empty HTTP export only after identifying its
   intended filter and source command.
4. Prepare a separate FormBook report only when its source PCAP and analysis
   artifacts are available and clearly identified.
5. Update README status items to match verified work.
6. Review files for sensitive content before staging them in Git.
7. Review the staged diff before committing or pushing changes.

## 10. Assessment Standard

For each finding, record the source PCAP and hash, the tool and relevant
filter or rule, the observed result, the interpretation, and the limitations.
An alert or periodic connection is an indicator for investigation, not proof
of compromise or exfiltration.
