# Project Architecture

## Implemented offline path

```text
Authorized PCAP (read-only)
       ├── Zeek ──> Zeek adapter ─────┐
       ├── Suricata ─> EVE adapter ────┼─> unified alert JSON ─> FastAPI ─> Flutter Web
       └── capture metadata builder    │
                                       └─> ProjectDetector evidence-linked findings

Local file ─> bounded static-analysis CLI ─> schema-validated local JSON store ─> API/UI
MalwareBazaar hash metadata lookup ─────────────────────────────────────────────> API/UI
```

The pipeline reuses the project's Zeek/Suricata adapters and merge code. The PCAP intelligence builder wraps that pipeline to capture provenance, metadata, and normalized observations; it does not create a second alert engine. ProjectDetector findings are distinct from native engine alerts.

## Evidence and trust boundaries

- Captures are read-only inputs. The pipeline runs offline and the builder does not extract payloads or transferred files.
- Each record retains its source and evidence reference when available. Capture provenance and publisher labels are recorded separately from observed facts and analyst assessments.
- Engine alerts are rule/tool observations. A publisher scenario label or provider hash match does not prove compromise, execution, C2, or exfiltration.
- The FastAPI MVP serves operator-configured JSON paths and has no authentication. Bind only to loopback.
- The Flutter app uses compile-time `API_BASE_URL`; it does not receive provider credentials.
- Local static metadata parsing is CLI-based. No API upload/job route, live sandbox, curated YARA rules integration, ssdeep, or signature verification is implemented.
- Telemetry can be displayed/imported where available. Correlation is limited to implemented evidence identifiers; time proximity alone does not establish causality.

The isolated malware lab document is design-only. No malware execution environment is part of the shipped workflow. See the Mermaid diagrams in `docs/diagrams/`.
