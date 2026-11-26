# Network Traffic Analysis & SOC Dashboard

This project processes authorized PCAPs offline with Zeek and Suricata, combines their adapter alerts with evidence-linked ProjectDetector findings, serves the resulting JSON through a local FastAPI service, and displays historical analysis in a Flutter Web dashboard. It is not live monitoring.

## Capabilities and boundaries

- Offline PCAP pipeline: Zeek + Suricata, existing adapters, ProjectDetector NET-001–NET-012, unified alert output, provenance manifest.
- PCAP intelligence builder: capture metadata/provenance and normalized observations that reuse the existing pipeline. No payload extraction and no file execution.
- FastAPI: alert list/details/stats and local Malware Intelligence metadata/telemetry routes. Bind to loopback; the MVP has no authentication.
- Flutter Web: dashboard, filters, sorting, pagination, details/evidence, Malware Intelligence view, CSV export.
- MalwareBazaar: metadata-only integration. A backend key is required for live lookups; credentialed lookup was not verified for the final QA run.
- Static analysis: offline local-file CLI with bounded metadata parsing. No upload endpoint or asynchronous UI analysis job.

The final QA source used Flutter 3.50.1 / Dart 3.14.0, Python 3.14.4, Zeek 8.0.10, and Suricata 8.0.3. TShark/capinfos 4.6.4 were available for inspection; they are not runtime dependencies of the pipeline. Install OS tools and Suricata rules/configuration separately. Other versions may require validation.

A historical reference bundle and a fresh baseline-PCAP run each contained 137 alerts in QA, but they are separate artifacts. Neither dataset nor generated output is included here. For the fresh run, QA recorded 127 Suricata alerts, 2 Zeek alerts, and 8 ProjectDetector findings (NET-005 ×2, NET-007 ×7, NET-009 ×1). These findings are observations requiring review, not proof of compromise, C2, or exfiltration.

## Clean environment setup

Python 3.11+ is recommended; install test and API dependencies in a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.lock.txt
```

Run the test suite from the repository root:

```bash
python -m pytest -q
```

Install Flutter 3.50.1 or a compatible SDK separately. From `frontend/`:

```bash
flutter pub get
flutter analyze
flutter test
```

## Offline PCAP workflow

Install Zeek, Suricata, and an authorized local Suricata configuration/ruleset. Verify that Suricata file-store is explicitly disabled. Use a PCAP you are authorized to analyze and a new output path outside the repository:

```bash
python scripts/run_offline_unified_pipeline.py \
  --pcap /absolute/path/to/authorized-capture.pcap \
  --out /absolute/path/to/new-output-directory \
  --zeek-bin /path/to/zeek \
  --suricata-bin /path/to/suricata \
  --suricata-config /path/to/suricata.yaml \
  --suricata-rules /path/to/suricata.rules \
  --command-timeout-seconds 900
```

The output directory must be new or empty. The pipeline reads the PCAP; it does not fetch datasets, call MalwareBazaar, or extract/execute transferred files. Reference templates are in `config/`; they are not auto-loaded. See [`docs/project_runbook.md`](docs/project_runbook.md) and [`docs/phase2_pcap_workflow.md`](docs/phase2_pcap_workflow.md).

To start the API against that run:

```bash
export UNIFIED_ALERTS_PATH="/absolute/path/to/new-output-directory/unified/alerts.json"
export MALWARE_ANALYSIS_STORE_PATH="/absolute/path/to/local-analysis-store/analyses.json"
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Start the Web dashboard from `frontend/` in another terminal:

```bash
flutter run -d web-server --web-hostname 127.0.0.1 --web-port 8080 \
  --dart-define=API_BASE_URL=http://127.0.0.1:8000
```

For a release build, use `flutter build web --release --dart-define=API_BASE_URL=http://127.0.0.1:8000` and serve its `build/web` directory on loopback. Configure a browser-reachable API URL and matching CORS policy; do not put secrets in Flutter defines.

## Security and limitations

- Keep API and dashboard on loopback. Authentication, authorization, rate limiting, and multi-user controls are not implemented.
- Keep PCAPs, generated logs, alert bundles, local stores, caches, and builds outside Git.
- PCAP UI upload and async analysis jobs are deferred; the supported workflow is CLI-based.
- No sandbox execution is implemented. Dynamic telemetry is displayed only when supplied by an existing API record.
- YARA executable availability is not project integration; the project has no managed ruleset. ssdeep and digital-signature verification are not integrated.
- MalwareBazaar matches are third-party metadata, not proof of execution or compromise. No provider credential or successful credentialed lookup is included in this release evidence.
- Dataset labels and tool alerts do not independently establish attribution, compromise, C2, or exfiltration. Preserve provenance and uncertainty.

See [`docs/backend_api.md`](docs/backend_api.md), [`docs/malwarebazaar_integration.md`](docs/malwarebazaar_integration.md), and [`docs/phase2_dataset_sources.md`](docs/phase2_dataset_sources.md).
