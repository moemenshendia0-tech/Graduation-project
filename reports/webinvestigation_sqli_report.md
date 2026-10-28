# Web Investigation Report: SQL Injection

## 1. Executive Summary

Analysis of `WebInvestigation.pcap` identified HTTP requests from
`111.224.250.131` to `73.124.22.98`, targeting
`bookworldstore.com`, including SQL injection payloads submitted to
`/search.php`.

The strongest evidence is a sequence of UNION-based SQL queries whose
corresponding HTTP responses contain database schema names, table names,
column definitions, and records from the `admin`, `customers`, and
`books` tables.

**Assessment:** The captured traffic provides strong evidence of successful
SQL injection-based data retrieval in the observed HTTP responses.

This report describes what is visible in the capture. It does not establish
the identity of the operator, whether the source address identifies a
specific person, whether the application was a production system, whether
exposed credentials were valid, or whether the data was subsequently used.

## 2. Scope and Evidence Integrity

- PCAP filename: `WebInvestigation.pcap`
- PCAP path used for analysis:
  `/mnt/d/DEPI - graduation/PCAPs files/WebInvestigation.pcap`
- PCAP SHA-256:
  `cf31ec09cf2ece5d0a55c750a0fee19af3ab34d4b7125c4781a56025e2721647`
- Reported capture size: 28,629,039 bytes
- Reported frame count: 88,862
- HTTP transactions in the analyzed Zeek log: 41,709
- Evidence summary:
  `analysis/batch/WebInvestigation/sql_injection_evidence.txt`
- Evidence summary SHA-256:
  `55376795ec4fa585c4907e1c13c943d04ffb2f1ffb8c1e7e2fcccafa6720ad33`

The evidence summary records request and response frame pairs. Its hash
identifies that summary file, not the original PCAP.

## 3. Observed Network Activity

The analyzed HTTP records show:

- Source address: `111.224.250.131`
- Destination address: `73.124.22.98`
- HTTP Host: `bookworldstore.com`
- Target endpoint: `/search.php`
- Observed SQL injection user-agent in the broader analysis:
  `sqlmap/1.8.3#stable (https://sqlmap.org)`

The evidence includes UNION-based queries against database metadata and
application tables. SQLmap-related user-agent evidence supports the
assessment that automated SQL injection testing was involved in the
traffic. A user-agent string alone does not prove the identity of the
operator or the exact tool that generated every request.

## 4. Evidence of Data Retrieval

### 4.1 Database schema discovery

**Request frame 1520 → response frame 1525**

The request queries `INFORMATION_SCHEMA.SCHEMATA`. The HTTP 200 response
contains the names `mysql`, `information_schema`, `performance_schema`,
`sys`, and `bookworld_db`.

**Finding:** Database schema names were returned in the HTTP response.

### 4.2 Table discovery

**Request frame 1548 → response frame 1553**

The request queries `INFORMATION_SCHEMA.TABLES` for `bookworld_db`.
The response contains `admin`, `books`, and `customers`.

**Finding:** Table names within the application database were returned.

### 4.3 Account-table structure

**Request frame 1576 → response frame 1578**

The request queries `INFORMATION_SCHEMA.COLUMNS` for the `admin` table.
The response shows the fields `id`, `password`, and `username`, including
their reported SQL data types.

**Finding:** The response reveals the structure of a table apparently
intended to hold account-related records.

### 4.4 Account-related record

**Request frame 1589 → response frame 1591**

The request selects `id`, `password`, and `username` from
`bookworld_db.admin`. The response contains a record with those fields.

**Finding:** An account-related record, including a password field value,
appears in the captured response.

**Caution:** The value is intentionally omitted from this report. The
capture does not establish whether it is a real, current, usable credential.
Treat it as potentially exposed until the system owner verifies otherwise.

### 4.5 Customer-table structure

**Request frame 1612 → response frame 1616**

The request queries the column metadata for `bookworld_db.customers`.
The response lists `address`, `email`, `first_name`, `id`, `last_name`,
and `phone`, along with their reported SQL data types.

**Finding:** The response reveals the structure of a table containing
customer-related fields.

### 4.6 Customer records

**Request frame 1622 → response frame 1624**

The request selects address, email, first name, ID, last name, and phone
fields from `bookworld_db.customers`. The response contains ten records
with values for these fields.

**Finding:** Customer-related records were returned in the HTTP response.

**Privacy note:** Names, addresses, email addresses, and phone numbers are
not reproduced here. Their appearance in the capture should be treated as
potential exposure of personal information, subject to validation by the
system owner.

### 4.7 Book records

**Request frame 1658 → response frame 1663**

The request selects `id` and `title` from `bookworld_db.books`. The response
contains 23 ID/title pairs.

**Finding:** Book records were returned in the HTTP response.

## 5. Technical Assessment

The sequence of requests and responses is consistent with the following
progression:

1. Discovery of database schema names.
2. Discovery of table names.
3. Enumeration of account-table columns.
4. Retrieval of an account-related record.
5. Enumeration of customer-table columns.
6. Retrieval of customer-related records.
7. Retrieval of book records.

The payloads use UNION-based SQL queries and database metadata. The
corresponding HTTP responses contain data matching the requested fields.
Taken together, this is substantially stronger evidence than the presence
of suspicious request strings alone.

The observed HTTP status is 200 for the listed responses. An HTTP 200 status
by itself does not prove exploitation; the returned response content is the
important corroborating evidence.

## 6. Detection and Limitations

The previously recorded Suricata analysis reported zero alert events for
this capture.

This does not negate the packet-level evidence. Detection depends on the
rules enabled, engine configuration, traffic visibility, and rule coverage.
A lack of alerts is not proof that the traffic was benign.

The analysis does not independently establish:

- The real-world identity or intent of the source operator.
- Whether the target was production, staging, or a deliberately vulnerable
  lab environment.
- Whether the exposed account value was valid or reused elsewhere.
- Whether any data was stored or used after retrieval.
- Whether the application was compromised through other methods.
- The exact number of unique real people represented by customer records.

The findings are limited to the supplied capture and derived artifacts.

## 7. Recommended Response

1. Preserve the original PCAP and its verified SHA-256 hash.
2. Restrict access to evidence containing account or customer data.
3. Have the system owner validate the affected endpoint and environment.
4. Review application and database logs for the relevant requests and
   database activity, if those logs are available.
5. Fix the underlying SQL injection vulnerability using parameterized
   queries or prepared statements; do not rely solely on input filtering.
6. Apply least-privilege permissions to the application's database account.
7. If credential exposure is confirmed, rotate affected credentials and
   invalidate relevant sessions as appropriate.
8. Assess the scope of any personal-data exposure and follow applicable
   incident-response and notification requirements.
9. Add or tune detection coverage and test it against approved, controlled
   reproductions of the observed behavior.
10. Re-run validation after remediation and retain the results.

## 8. Conclusion

The paired HTTP request and response frames provide strong evidence that
SQL injection payloads caused database metadata and application records to
be returned to the requesting client in the captured traffic.

The most consequential observed data includes account-related fields and
customer-related records. The evidence warrants investigation and remediation,
while claims about credential validity, production impact, operator identity,
and subsequent misuse require corroboration beyond this PCAP.

## Appendix A: Primary Evidence References

| Request frame | Response frame | Evidence |
|---:|---:|---|
| 1520 | 1525 | Database schema names |
| 1548 | 1553 | Table names |
| 1576 | 1578 | `admin` column metadata |
| 1589 | 1591 | Account-related record |
| 1612 | 1616 | `customers` column metadata |
| 1622 | 1624 | Ten customer-related records |
| 1658 | 1663 | 23 book records |

Primary detailed artifact:
`analysis/batch/WebInvestigation/sql_injection_evidence.txt`
