# Incident Report: Suspicious Executable Download

## 1. Executive Summary

Traffic analysis of `2026-10-01-traffic-analysis-exercise.pcap` identified
a successful HTTP download of `runner_ilove.exe` by internal host
`10.10.1.128`.

The executable was downloaded from `107.175.82.242:9000` using HTTP GET.
Zeek recorded HTTP status 200 and a transferred response body of 1,646,592
bytes. The downloaded file was extracted for static analysis and was not
executed during this investigation.

The SHA-256 hash matches a ThreatFox entry identifying the sample as
"Unknown malware" and tagging it as an executable, RAT, and shellcode loader.
MalwareBazaar also lists multiple vendor and sandbox results, including
malicious verdicts, alongside some clean or inconclusive results.

Assessment: HIGH PRIORITY suspicious/malicious file transfer.
The capture confirms the download. It does not, by itself, prove execution,
successful host compromise, or data exfiltration.

## 2. Scope and Evidence Sources

- PCAP: `2026-10-01-traffic-analysis-exercise.pcap`
- Network analysis: Zeek logs and Suricata alerts
- Static file analysis: `file`, `objdump`, `strings`, PE section entropy
- Threat intelligence: ThreatFox and MalwareBazaar hash records
- Extracted sample:
  `analysis/extracted_http_2026-10-01/runner_ilove.exe`

The executable was not run. Raw PCAP files and the executable should remain
local and must not be committed to a public repository without authorization.

## 3. Timeline

Times below are those reported in the analyzed capture/logs. Confirm the
capture timezone before presenting them as UTC or local time.

| Time | Observation | Evidence |
|---|---|---|
| 22:30:36 | Host `10.10.1.128` requests `/wilow/runner_ilove.exe` from `107.175.82.242:9000` | Zeek HTTP log |
| 22:30:36 | HTTP response status 200; response body 1,646,592 bytes | Zeek HTTP log |
| 22:30:36–22:30:37 | Suricata raises alerts associated with a PE download, dotted-quad host, and `curl` user agent | Suricata fast.log |
| 22:30:44 | Host connects to `8.8.4.4:443`; Suricata labels associated TLS activity as Google DNS over HTTPS | Zeek connection/TLS logs and Suricata alert |
| After download | Connection to `195.63.128.106:443` lasts approximately 2,233 seconds and transfers substantial response data; server-side retransmissions are reported | Zeek conn.log and Suricata alert |

The temporal proximity of the later connection is suspicious, but the capture
alone does not prove that the downloaded executable initiated it.

## 4. Network Evidence

### HTTP transfer

- Source host: `10.10.1.128`
- Source port: `63723`
- Destination: `107.175.82.242:9000`
- Method: `GET`
- URI: `/wilow/runner_ilove.exe`
- User-Agent: `curl/8.21.0`
- HTTP status: `200 OK`
- Response body: `1,646,592` bytes
- Zeek connection UID: `CoZgiR3oq1ptUtEep6`
- Connection duration: approximately `2.141484` seconds
- Connection state: `SF`
- Missed bytes: `0`

### File extraction evidence

- Zeek file UID: `Fj9Cup2ZicNmN9Gp3`
- Source: HTTP
- Analyzer: PE
- Seen bytes: `1,646,592`
- Total bytes: `1,646,592`
- Missing bytes: `0`
- Timed out: `false`

These records support that the complete executable body was captured and
extracted. They do not establish that the file was executed.

## 5. File Analysis

- File name: `runner_ilove.exe`
- File type: PE32+ Windows executable, x86-64
- SHA-256:
  `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061`
- MD5:
  `cb50fe432a302b85845bc7ea98742c11`
- Whole-file entropy: approximately `5.8383` bits/byte
- `.text` entropy: approximately `6.6004`
- `.rdata` entropy: approximately `5.7987`
- `.rdata` raw size: `1,596,928` bytes

The `.rdata` section is unusually large relative to `.text`. Entropy and
section size are supporting observations only; neither proves packing or
maliciousness.

Static strings contained API names including `VirtualAlloc`, `VirtualProtect`,
and `CreateThread`, plus a `VirtualProtect failed` message. These APIs can
occur in legitimate programs as well, so they are not independently
conclusive. No clear URL, domain, or IP string was found by the basic
ASCII-strings search. This absence does not establish benignness.

## 6. Threat Intelligence Correlation

### ThreatFox

ThreatFox has a record for the exact SHA-256 above:
https://threatfox.abuse.ch/ioc/1956875/

The record labels the sample "Unknown malware", with tags including `exe`,
`RAT`, and `shellcode-loader`. Its accompanying report describes a loader
that places shellcode in memory and runs it using APIs including
`VirtualAlloc`, `VirtualProtect`, and `CreateThread`. It also reports
`lapiscorbel.info` and `195.63.128.106:443` as C2 indicators.

These are third-party threat-intelligence claims, not proof that every
described behavior occurred on the host in this PCAP.

### MalwareBazaar

Hash record:
https://bazaar.abuse.ch/sample/b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061/

The record includes multiple vendor/sandbox results, including malicious
classifications and other clean or inconclusive results. This variation is
documented rather than represented as unanimous consensus.

## 7. Indicators of Compromise

| Indicator | Type | Context | Confidence |
|---|---|---|---|
| `b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061` | SHA-256 | Downloaded executable; matches ThreatFox record | High |
| `cb50fe432a302b85845bc7ea98742c11` | MD5 | Same sample according to MalwareBazaar | High |
| `107.175.82.242:9000` | IP:port | Observed HTTP source for executable download | High for observed transfer |
| `/wilow/runner_ilove.exe` | HTTP URI | Observed download path | High |
| `195.63.128.106:443` | IP:port | Observed long connection after download; also listed by ThreatFox as C2 | Medium; causal link not proven |
| `lapiscorbel.info` | Domain | Reported as C2 by ThreatFox; not confirmed in the observations summarized here | Intelligence-only |

Do not block an IOC solely because it appears in this report without
validating the environment, ownership, and potential business impact.

## 8. Assessment

The combination of a successful executable download, suspicious transfer
context, Suricata alerts, and a matching threat-intelligence hash supports
treating the file as malicious for defensive handling.

Confirmed:
- The executable was transferred in the capture.
- The extracted file's SHA-256 matches a ThreatFox malware record.
- Suricata generated alerts associated with the download.

Not confirmed by this PCAP alone:
- Execution of the file on `10.10.1.128`.
- Persistence or successful code execution.
- A definitive causal relationship between the executable and the later
  `195.63.128.106:443` connection.
- Data exfiltration or the exact data, if any, transferred.

## 9. Recommended Response

1. If this reflects a real environment, isolate `10.10.1.128` according to
   the incident-response policy and preserve volatile evidence where possible.
2. Search endpoint telemetry for the file hash, file path, process creation,
   parent process, command line, and execution time.
3. Hunt across DNS, proxy, firewall, EDR, and network logs for the listed
   IPs, domain, URI, hash, and adjacent time windows.
4. Investigate the `195.63.128.106:443` session, including TLS metadata,
   byte counts, retransmissions, and any available payload/protocol evidence.
5. Review persistence locations and process/memory activity using approved
   endpoint tools in an isolated forensic workflow.
6. Preserve the original PCAP, extracted sample, hashes, tool versions, and
   analysis logs. Do not execute the sample on a normal workstation.
7. Keep PCAPs and the executable out of public Git commits unless licensing
   and release authorization have been reviewed.

## 10. Conclusion

This investigation identified a suspicious executable transfer that is
strongly supported as malicious by hash-based threat intelligence. The
available evidence supports prioritizing host investigation and containment
if this is a live incident. Claims of execution, compromise, C2 causation,
or exfiltration require corroborating endpoint or network evidence.

## References

- ThreatFox:
  https://threatfox.abuse.ch/ioc/1956875/
- MalwareBazaar:
  https://bazaar.abuse.ch/sample/b789adce70c028a6d17be45ec34667aa95586350ee0c4057e75b138b1ad35061/
