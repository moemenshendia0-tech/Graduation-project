# Runbook: WebInvestigation SQL Injection Analysis

## 1. Purpose

This runbook documents a repeatable, read-only workflow for validating the
SQL injection findings in `WebInvestigation.pcap`.

Run the commands from the project root in Ubuntu/WSL. They read existing
artifacts and write any new validation output only to a new directory after
checking that the directory does not already exist.

## 2. Evidence locations

Original PCAP:

`/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap`

Existing evidence summary:

`analysis/batch/WebInvestigation/sql_injection_evidence.txt`

Final report:

`reports/webinvestigation_sqli_report.md`

## 3. Establish the working directory

```bash
cd "$HOME/projects/soc-migration/network-traffic-project" || exit 1
pwd
```

Confirm that the output is the expected project directory before proceeding.

## 4. Verify the original PCAP

```bash
PCAP="/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap"

test -r "$PCAP" || {
  echo "ERROR: PCAP is missing or unreadable."
  exit 1
}

ls -lh "$PCAP"
sha256sum "$PCAP"
```

Expected SHA-256:

`cf31ec09cf2ece5d0a55c750a0fee19af3ab34d4b7125c4781a56025e2721647`

If the hash differs, stop and investigate before relying on the existing
report. Do not modify the original PCAP.

## 5. Verify the evidence summary

```bash
EVIDENCE="analysis/batch/WebInvestigation/sql_injection_evidence.txt"

test -r "$EVIDENCE" || {
  echo "ERROR: Evidence summary is missing or unreadable."
  exit 1
}

wc -l -c "$EVIDENCE"
sha256sum "$EVIDENCE"
less "$EVIDENCE"
```

Expected summary SHA-256:

`55376795ec4fa585c4907e1c13c943d04ffb2f1ffb8c1e7e2fcccafa6720ad33`

Press `q` to exit `less`. A hash mismatch means the summary changed;
inspect the difference before treating it as the same artifact.

## 6. Validate selected packet frames

If `tshark` is installed, inspect the relevant frames directly in the PCAP:

```bash
tshark -r "$PCAP" \
  -Y 'frame.number == 1520 || frame.number == 1525 ||
      frame.number == 1548 || frame.number == 1553 ||
      frame.number == 1576 || frame.number == 1578 ||
      frame.number == 1589 || frame.number == 1591 ||
      frame.number == 1612 || frame.number == 1616 ||
      frame.number == 1622 || frame.number == 1624 ||
      frame.number == 1658 || frame.number == 1663' \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e ip.dst \
  -e http.request.method \
  -e http.host \
  -e http.request.uri \
  -e http.response.code
```

This command lists packet metadata and selected HTTP fields. Some fields may
be blank on packets that are not HTTP request or response packets.

For detailed packet dissection, use:

```bash
tshark -r "$PCAP" -Y 'frame.number == 1520' -V | less
tshark -r "$PCAP" -Y 'frame.number == 1525' -V | less
```

Repeat for other frames as needed. `-V` produces detailed output and can
include sensitive payload content. Keep it local and do not publish raw
customer records or password values.

If the capture uses HTTP compression or packet reassembly affects what is
displayed, inspect the complete relevant stream and the existing Zeek output
rather than assuming a single frame contains the complete application body.

## 7. Review the Zeek HTTP records

The previously used Zeek log is:

`analysis/batch/WebInvestigation/zeek/http.log`

Check that it exists:

```bash
test -r analysis/batch/WebInvestigation/zeek/http.log \
  && echo "Zeek HTTP log found" \
  || echo "Zeek HTTP log not found at the expected path"
```

If Zeek's `zeek-cut` is installed, inspect the relevant HTTP requests:

```bash
zeek-cut ts id.orig_h id.resp_h id.resp_p method host uri user_agent \
  < analysis/batch/WebInvestigation/zeek/http.log \
  | grep -E '111\.224\.250\.131|bookworldstore\.com'
```

This is a broad filter. Review the output carefully and avoid copying
sensitive query strings or returned personal data into public artifacts.

If the log is missing, locate the actual existing log before rerunning Zeek.
Do not overwrite a prior analysis directory.

## 8. Optional fresh Zeek analysis

Only perform this step if Zeek is installed and a fresh independent log set
is required. The command creates a new directory and refuses to overwrite it.

```bash
PCAP="/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap"
OUT="$HOME/pcap-analysis/webinvestigation-validation-$(date +%Y%m%d-%H%M%S)"

if [ -e "$OUT" ]; then
  echo "ERROR: Output directory already exists: $OUT"
  exit 1
fi

mkdir -p "$OUT" || exit 1
cd "$OUT" || exit 1
zeek -r "$PCAP"
```

This step reads the original PCAP and writes Zeek logs in the new output
directory. It does not modify the PCAP. Check the output and exit status
before relying on the generated logs.

## 9. Findings to verify

Confirm that the paired request and response frames support the following:

- 1520 → 1525: schema names including `bookworld_db`.
- 1548 → 1553: table names `admin`, `books`, and `customers`.
- 1576 → 1578: account-table column metadata.
- 1589 → 1591: an account-related record returned in the response.
- 1612 → 1616: customer-table column metadata.
- 1622 → 1624: ten customer-related records returned in the response.
- 1658 → 1663: 23 book records returned in the response.

A successful HTTP status alone is not sufficient. Verify the response content
and its association with the relevant request.

## 10. Detection interpretation

The prior Suricata run reported zero alert events. Do not interpret this as
proof that the traffic was benign. Rule coverage and engine configuration
can affect alert generation.

If rerunning Suricata, use a new output directory and record the exact
configuration, rule set, engine version, command, and results. Do not replace
the existing EVE log or other evidence.

## 11. Handling sensitive data

- Do not paste customer names, addresses, emails, phone numbers, or password
  values into public reports, tickets, repositories, or screenshots.
- Restrict raw PCAP and verbose packet-dissection output to authorized users.
- Redact sensitive values in any evidence extracts used for sharing.
- Preserve original evidence and record hashes before any approved handling
  or transformation.

## 12. Completion checklist

- [ ] Original PCAP hash verified.
- [ ] Evidence-summary hash verified.
- [ ] Request/response frame pairs reviewed.
- [ ] Data-exposure findings documented with redaction.
- [ ] Limitations and uncertainty documented.
- [ ] Recommended remediation communicated to the system owner.
- [ ] Any new analysis outputs stored separately without overwriting prior data.
