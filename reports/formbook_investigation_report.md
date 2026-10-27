# FormBook-Related HTTP Traffic Investigation

## 1. Executive Summary

The capture dated 2026-08-09 contains repeated HTTP activity from
internal host `172.16.8.49` to multiple external destinations.
Suricata generated 18 `ET MALWARE FormBook CnC Checkin (GET) M5`
alert events. Each of these events was correlated with a Zeek HTTP
request using source/destination addresses and ports, hostname, URI
path, and a time window of three seconds.

The traffic also contains repeated HTTP POST requests, including
large request bodies, recurring request-size sequences, and varied
server responses. These observations warrant further investigation.

**Assessment:** The evidence supports classifying this HTTP pattern
as suspicious and consistent with behavior detected by the
FormBook-related signature. The reviewed evidence alone does not
prove malware execution, successful command execution, data theft,
or successful exfiltration.

## 2. Scope and Evidence Identity

- Capture: `2026-08-09-traffic-analysis-exercise.pcap`
- SHA-256:
  `0ea6b597732a9ce6af9a7e3adff4512c9a91b4bce27184c8fdeb746f05cce170`
- Internal host of primary interest: `172.16.8.49`
- Protocol of interest: HTTP over TCP, primarily destination port 80
- Analysis sources: original PCAP, Zeek logs, Suricata EVE/alert output,
  and TShark stream inspection
- Zeek HTTP log: `~/pcap-analysis/formbook/zeek/http.log`
- Zeek connection log: `~/pcap-analysis/formbook/zeek/conn.log`
- Zeek file log: `~/pcap-analysis/formbook/zeek/files.log`
- Suricata EVE log:
  `~/pcap-analysis/formbook/suricata-with-rules/eve.json`

The capture contains 22,473 packets. The existing batch summary records
176 Zeek HTTP transactions and 41 Suricata alert events. Alert events
are not equivalent to distinct incidents.

## 3. Suricata Detection and Zeek Correlation

Suricata generated 18 events for:

`ET MALWARE FormBook CnC Checkin (GET) M5`

All 18 were matched to Zeek HTTP requests within three seconds using
the observed source and destination IP addresses, ports, hostname,
and URI path. The observed time differences ranged from approximately
0.043 to 2.477 seconds.

This is cross-tool correlation by network tuple, HTTP attributes, and
time. It is not a direct equality match between Suricata flow IDs and
Zeek connection UIDs.

Observed destinations included:

| Hostname | Destination IP | URI path |
|---|---|---|
| `www.grinswakebthu.info` | `146.59.71.167` | `/irpw/` |
| `www.taibeinan.cc` | `38.182.168.246` | `/lqjm/` |
| `www.legenda-sochi.com` | `45.130.41.161` | `/8nw8/` |
| `www.amlgames.site` | `89.110.89.25` | `/ll40/` |
| `www.moxom.online` | `81.2.196.19` | `/1l1j/` |
| `www.earthframe.site` | `66.29.149.91` | `/v2r8/` |
| `www.kentmediallc.com` | `199.192.27.50` | `/7qex/` |
| `www.p3x63q.garden` | `183.90.186.205` | `/ttsm/` |
| `www.www-bet456.co` | `172.67.219.130` | `/h3j8/` |
| `www.titanium303.com` | `172.67.162.153` | `/r7l3/` |
| `www.z61gqw.beer` | `156.247.51.39` | `/nxc3/` |
| `www.21207628.shop` | `121.54.163.148` | `/hut9/` |
| `www.thvwzs.com` | `104.21.76.210` | `/tza3/` |
| `www.devinnovationhab.team` | `104.21.42.23` | `/rd80/` |
| `www.independent.ie` | `172.64.155.76` | `/ujvq/` |

The list describes observed alert-associated requests, not a claim that
every listed domain is malicious. The `independent.ie` match is
especially important to validate in context rather than classify from
the signature alone.

## 4. Repeated HTTP POST Activity

Zeek analysis identified 113 POST requests originating from
`172.16.8.49`, with a combined recorded request-body size of
4,529,609 bytes.

- 64 requests had recorded request bodies of at least 60,000 bytes.
- Those large request bodies totalled 4,426,368 bytes.
- Fourteen destination/hostname/path groups contained seven or fourteen POST requests each; one additional group contained a single POST request.
- The fourteen recurring groups totalled 283,087 or 566,174 bytes per group; the additional single-request group totalled 217 bytes.
- Many repeated POST intervals were approximately 2.55–2.77 seconds.
- The examined groups used the same user-agent string:
  `Mozilla/5.0 (Windows NT 6.2; rv:39.0) Gecko/20100101 Firefox/39.0`.

A recurring sequence of request-body sizes was observed:
`69101`, `69181`, `69165`, and `69201` bytes, following smaller
requests in several destination groups.

These measurements describe HTTP request bodies recorded by Zeek.
They do not establish that the bodies contain identical content,
credentials, or stolen data.

## 5. Example: `www.grinswakebthu.info`

For destination `146.59.71.167:80`, the observed POST requests included
paths under `/irpw/`.

Four examined large requests had body sizes of 69,101, 69,181,
69,165, and 69,201 bytes. The corresponding Zeek file records reported
HTTP as the source, `text/plain` as the MIME type, and matching
`seen_bytes` and `total_bytes`, with no reported missing or overflow
bytes for those records. Content hashes and extracted-file paths were
not available in those records.

The examined POST responses were HTTP `404 Not Found`. In the packet
trace for one request, the server's HTTP 404 response preceded a TCP
reset from the internal client. TCP acknowledgements and the observed
response establish network-level exchange; they do not establish
whether the application accepted or stored the request body.

## 6. Example: `www.taibeinan.cc`

The host `38.182.168.246:80` received repeated POST requests under
`/lqjm/`, including bodies of approximately 69 KB. Multiple large
requests received HTTP `500 Internal Server Error`. Other requests
received `200`, `499`, `502`, or no recorded status, depending on
the transaction.

One POST with a 3,225-byte request body received:

`HTTP/1.1 200 OK`

with `Content-Type: application/json` and a 44-byte response body:

`{"code":404,"msg":"404 not found","data":{}}`

This demonstrates that the HTTP status and the application's JSON
status can differ. The HTTP response was 200, while the JSON message
reported `404 not found`. Neither result proves whether the request
data was stored or acted upon.

GET requests to the same hostname used query parameters named
`2kn1` and `kbBSJ`. The observed `2kn1` values were 140 characters
long and Base64-compatible; decoding produced 105 bytes of binary-looking
data with differing hashes across the examined hosts. The `kbBSJ` value
was observed as the same short value in the reviewed requests.

These observations do not establish the payload's meaning or prove
that it is encrypted. The large HTML body returned with an HTTP 404
included JavaScript for device identification, token handling, and
other site functions. Captured page source does not prove that the
browser executed those functions.

## 7. Server Responses and Transfer Limitations

Observed HTTP responses included `200`, `301`, `403`, `404`, `499`,
`500`, `502`, and transactions without a recorded response status.

HTTP status codes must be interpreted in context:
- `200 OK` confirms the HTTP response status, not successful application
  processing or storage.
- `404 Not Found` does not by itself prove that the request body never
  reached the server.
- `500` and `502` indicate reported server/gateway errors, not the
  exact reason for failure.
- `499` requires server-specific interpretation and is not, by itself,
  proof of successful or failed data transfer.
- A missing status in a Zeek transaction is not enough to establish why
  a response was not recorded.

The second GET to `www.taibeinan.cc` had a Zeek response-body length of
50,513 bytes, while the inspected response headers declared a content
length of 156,386 bytes. This discrepancy is consistent with an
incomplete captured response or incomplete transaction observation;
it requires packet-level verification before a stronger conclusion.

## 8. Other Relevant Alerts

Suricata also reported:
- `SURICATA HTTP Unexpected Request body` on three suspicious-looking
  HTTP transactions.
- `SURICATA HTTP Response excessive header repetition` on multiple
  server responses.
- `ET INFO Packed Executable Download` and
  `ET HUNTING SUSPICIOUS Dotted Quad Host MZ Response` for a 383,400-byte
  HTTP 206 response from `173.46.81.201`, with a Windows Delivery
  Optimization user agent and a Windows Update-like URI.

The latter transfer may be related to software/update delivery, but
that explanation has not been confirmed. The alert and MIME information
warrant validation; they do not alone prove the file is malicious.

Suricata also reported Microsoft connection-test traffic and a DNS
query for a `.cc` top-level domain. These are contextual observations
and should not be promoted to confirmed malicious activity without
additional evidence.

## 9. Evidence-Based Assessment

### Observed
- Repeated HTTP POST activity from `172.16.8.49` to multiple external
  destinations.
- Recurring request-body sizes and timing patterns.
- Eighteen FormBook-related Suricata alert events correlated with
  Zeek requests by tuple, hostname, path, and time.
- Multiple server error responses and short application responses.
- GET query values that decode from Base64-compatible strings into
  105-byte binary-looking values.

### Assessment
The combined evidence supports prioritizing the HTTP activity for
incident investigation. The signature matches, repeated multi-destination
requests, consistent user agent, and recurring request-size sequence
are suspicious in combination.

### Not established by the reviewed evidence
- That the host was infected with FormBook.
- That any particular request body contained sensitive data.
- That a remote server stored or acted upon the POST data.
- That successful data exfiltration occurred.
- That the captured HTML JavaScript executed.
- That the executable-download alerts indicate a malicious file.

## 10. Recommended Follow-up

1. Preserve the original PCAP and its SHA-256 hash.
2. Retain exact Zeek and Suricata commands, versions, ruleset state,
   and output paths for reproducibility.
3. If payload inspection is required, extract only selected transactions
   into a separate evidence directory and calculate hashes; do not
   overwrite existing artifacts.
4. Inspect the relevant HTTP response bodies and associated TCP streams
   where the capture contains sufficient data.
5. Validate the FormBook signature against the exact request attributes
   and the rule version used.
6. Review DNS, connection timing, and endpoint telemetry for independent
   corroboration.
7. Do not report confirmed exfiltration or malware execution unless
   additional evidence supports those specific claims.
8. Review this report and all supporting artifacts for sensitive data
   before staging or publishing them.

## 11. Reproducibility and Status

This report summarizes evidence observed in the existing local analysis
outputs and the packet-stream checks described above. It is not a claim
that every follow-up task has been completed. Controlled validation,
full endpoint correlation, and publication-safety review remain
outstanding unless supported by separate execution records.
