# Project Runbook

## Scope and safety

The application supports offline analysis of authorized PCAPs. It is a historical evidence workflow, not live monitoring. Preserve original captures; record their SHA-256 and source/licensing context. Never execute a transferred file or infer compromise/C2/exfiltration from a single tool alert.

Do not download malware or datasets as part of this workflow. Do not use the beacon lab utilities as part of routine release testing. Keep inputs, raw logs, generated alert datasets, local databases, caches, and build output outside Git and outside the source tree.

## Prerequisites

- Python 3.11 or newer; API and test dependencies from `requirements-dev.txt`.
- Zeek and Suricata installed separately. Provide their executable paths.
- An authorized Suricata configuration and rules file; verify `file-store` is explicitly disabled before running.
- Flutter 3.50.1 / Dart 3.14.0 or a compatible SDK for the Web UI.
- Optional: TShark and capinfos for independent capture inspection. They are not required by the pipeline.

The final QA run recorded Python 3.14.4, Zeek 8.0.10, Suricata 8.0.3, and TShark/capinfos 4.6.4. These are the tested environment versions, not a promise that every other version is compatible.

## Python setup and tests

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.lock.txt
python -m pytest -q
```

## Run the offline detection pipeline

First verify the input capture and choose a new, empty output directory outside the repository. Replace every example path below with paths from your own installation; do not assume a particular Linux/Windows mount or tool configuration:

```bash
sha256sum /path/to/authorized-capture.pcap
capinfos /path/to/authorized-capture.pcap
python scripts/run_offline_unified_pipeline.py \
  --pcap /path/to/authorized-capture.pcap \
  --out /path/to/new-output \
  --zeek-bin /path/to/zeek \
  --suricata-bin /path/to/suricata \
  --suricata-config /path/to/suricata.yaml \
  --suricata-rules /path/to/suricata.rules \
  --command-timeout-seconds 900
```

The runner refuses an unsafe/non-empty target, runs Zeek and Suricata offline, then invokes the existing adapters and merger. It does not install tools or rules. Keep Suricata file-store disabled; do not ask Suricata to extract transferred files. The output contains raw tool logs, adapter outputs, unified alerts, and a run manifest; treat the full directory as local evidence.

To build the normalized PCAP intelligence record instead, use `scripts/build_pcap_intelligence_dataset.py --help` and the workflow in `docs/phase2_pcap_workflow.md`. The builder reuses the pipeline and MalwareBazaar enrichment is explicit opt-in; do not enable it without authorization and a protected key.

## Start the API

Use the `unified/alerts.json` from the run you intend to inspect. The API reads the configured alert file and local analysis JSON store; it does not repair or mutate the alert source. Store files outside the source checkout.

```bash
export UNIFIED_ALERTS_PATH="/path/to/new-output/unified/alerts.json"
export MALWARE_ANALYSIS_STORE_PATH="/path/to/private-local-store/analyses.json"
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Check `/health`, `/api/stats`, and `/api/alerts`. If the store has not been initialized, use the static-analysis CLI against an explicitly harmless fixture and a separate QA store, or follow the store schema; never point test data at a real store.

## Start the Flutter Web dashboard

In a second terminal:

```bash
cd frontend
flutter pub get
flutter run -d web-server --web-hostname 127.0.0.1 --web-port 8080 \
  --dart-define=API_BASE_URL=http://127.0.0.1:8000
```

The API permits loopback browser origins; this is not authentication. Do not bind the MVP to a LAN/public interface. For Windows-native Web builds, run Flutter from a Windows-native checkout/output path if the SDK cannot handle WSL ACLs.

## Static local analysis (no execution)

The analyzer is a bounded offline parser. It reads bytes, computes a hash, stores a schema-validated JSON record, and does not execute, extract, or upload the input. It does not create a PCAP upload job.

```bash
python scripts/analyze_local_malware_file.py --help
python scripts/analyze_local_malware_file.py \
  --file /path/to/explicitly-authorized-file \
  --analysis-id local-case-001 \
  --store /path/to/private-local-store/analyses.json \
  --classification synthetic_fixture
```

Use `synthetic_fixture` only for harmless generated test data. Do not label ordinary observations as synthetic or real without support.

## MalwareBazaar and trust limits

The optional hash lookup is metadata-only and uses backend environment configuration; the Flutter build never receives the key. A missing key yields the documented unavailable response. The final QA did not perform a credentialed provider request. See `docs/malwarebazaar_integration.md` for non-echoing setup.

The API has no request authentication. Keep it loopback-only. Local/provider metadata, publisher labels, engine alerts, and analyst hypotheses remain separate evidence classes. No UI PCAP upload, asynchronous sandbox job, curated YARA integration, ssdeep integration, or signature-verification capability is claimed.
