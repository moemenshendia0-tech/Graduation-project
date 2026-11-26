# Local Unified Alerts API

FastAPI serves alerts from a configured JSON file and provides Malware Intelligence metadata/case routes. The service is unauthenticated and intended for a local loopback demonstration. It does not mutate the unified alert source.

## Install and run

From the repository root, install `requirements-api.txt`, then set the path to a pipeline result. Keep alert files and analysis stores outside Git.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-api.txt
export UNIFIED_ALERTS_PATH="/absolute/path/to/run/unified/alerts.json"
export MALWARE_ANALYSIS_STORE_PATH="/absolute/path/to/private-store/analyses.json"
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
```

`UNIFIED_ALERTS_PATH` has no portable project default; configure it to the intended run. If the alert file is unavailable or invalid, health reports degraded and data endpoints return a sanitized service error. `MALWARE_ANALYSIS_STORE_PATH` must point to the operator-selected JSON store; API requests cannot choose arbitrary filesystem paths.

## Routes

- `GET /health`: API state and alert-file availability.
- `GET /api/alerts`: paginated alert list. Query parameters: `page` (default 1), `page_size` (default 50, maximum 500), `severity`, `source_tool`, `rule_id`, `src_ip`, `dst_ip`, and free-text `q`.
- `GET /api/alerts/{alert_id}`: one alert by response ID. IDs are positional response identifiers and are not written to the source file.
- `GET /api/stats`: total and grouped source, severity, and rule counts.
- `GET /api/malware/intel/{hash}`: validated MD5/SHA1/SHA256 metadata lookup. Requires backend-only `MALWAREBAZAAR_AUTH_KEY` for upstream access; no sample download is offered.
- `GET /api/malware/analyses`: list local analysis records.
- `GET /api/malware/analyses/{analysis_id}`: record detail.
- `GET /api/malware/samples/{sha256}`: records associated with a SHA-256.
- `GET /api/malware/analyses/{analysis_id}/events`: stored telemetry events.
- `GET /api/malware/analyses/{analysis_id}/findings`: evidence-linked finding/correlation output.
- `POST /api/malware/analyses/{analysis_id}/events`: validate and store telemetry for an existing case.

The service permits loopback browser origins for local UI development. CORS is not authentication. Keep both services bound to `127.0.0.1`; do not expose this MVP to a network.

## Tests

```bash
python -m pytest -q tests/test_alerts_api.py tests/test_malware_analysis_api.py tests/test_malwarebazaar.py
```

Provider calls in unit tests are mocked; no API key or external request is needed.
