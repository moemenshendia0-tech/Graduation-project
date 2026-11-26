# Phase 2 PCAP Intelligence Workflow

The workflow adds provenance and normalized observations around the existing offline unified pipeline. It reuses Zeek/Suricata adapters and alert merging; it does not duplicate engine alert generation. Output follows `schemas/pcap_intelligence.schema.json`.

The record distinguishes observed facts, tool alerts, publisher labels, external intelligence, and analyst hypotheses. Every normalized observation carries a source and row-level evidence reference. Unknown source provenance remains `unknown`. Publisher scenario labels and detections are not independent proof of compromise.

## Safety and prerequisites

- Use only a PCAP you are authorized to analyze. This repository does not include captures or establish their publisher provenance.
- Install Zeek, Suricata, and a reviewed local ruleset/configuration separately. TShark/capinfos are optional inspection tools.
- Explicitly verify Suricata `file-store` is disabled.
- The builder supports classic Ethernet PCAP versions listed by its validation logic; malformed, empty, PCAPNG, and unsupported link types are rejected.
- It reads metadata and streams packet bytes for hashing/structure validation; it does not extract payloads or execute transferred files.
- No dataset download or MalwareBazaar request occurs by default. Enrichment is opt-in only for already-observed valid SHA-256 identifiers.
- Use a new output directory outside the repository. Preserve raw logs and manifests as local evidence, not Git content.

## Run

```bash
python scripts/build_pcap_intelligence_dataset.py --help
python scripts/build_pcap_intelligence_dataset.py \
  --pcap /path/to/authorized-capture.pcap \
  --out /path/to/new-output \
  --zeek-bin /path/to/zeek \
  --suricata-bin /path/to/suricata \
  --suricata-config /path/to/suricata.yaml \
  --suricata-rules /path/to/suricata.rules \
  --source-kind unknown \
  --source-verification unknown
```

Choose `publisher` metadata only when the publisher source is independently documented. A filename or scenario resemblance is insufficient. Refer to `docs/phase2_dataset_sources.md` for known source/license uncertainty.

The output contains a normalized `pcap_intelligence.json` and a nested pipeline output. Zeek TSV evidence references use the log path and one-based physical line number; adapter alert references use the source record index or matching Suricata EVE line. The code validates unified alert consistency and the output schema before completion.

## Interpretation

Capture visibility, parser support, ruleset coverage, source authenticity, and timestamps limit interpretation. Alerts, indicators, and external metadata are observations for analyst review. Do not claim C2, exfiltration, execution, or compromise without corroborating evidence.
