# Evidence Checklist — runner_ilove.exe

- [x] HTTP GET and successful 200 response documented.
- [x] Downloaded byte count and Zeek connection/file identifiers documented.
- [x] Extracted sample SHA-256 and MD5 documented.
- [x] PE type, section sizes, entropy, and selected API strings documented.
- [x] ThreatFox and MalwareBazaar references documented.
- [x] Confirmed observations separated from intelligence claims and hypotheses.
- [ ] Confirm capture timezone and normalize event timestamps.
- [ ] Preserve SHA-256 of the original PCAP and extracted sample in the evidence inventory.
- [ ] Export relevant Zeek HTTP/conn/files rows and Suricata alert rows to a case evidence folder.
- [ ] Check whether `lapiscorbel.info` appears in the capture's DNS, HTTP Host, TLS SNI, or other logs.
- [ ] Investigate `195.63.128.106:443` session and determine protocol/TLS evidence.
- [ ] Review endpoint telemetry for file creation, process execution, persistence, and child processes.
- [ ] Review all Git changes and confirm PCAPs/executable are not staged.
