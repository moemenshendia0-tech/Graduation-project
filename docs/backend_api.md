# Local Unified Alerts API (MVP)

This read-only FastAPI service serves the merged alerts JSON produced by the offline pipeline. It has no database or authentication and does not modify the source JSON. API dependencies are listed in requirements-api.txt. Python 3.10 or newer is required.

## Start the API

Create and activate a virtual environment, then install the API packages. Install pytest separately if you also want to run tests:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-api.txt
python -m pip install pytest
```

From the repository root, point the service at the output from a completed pipeline run and start Uvicorn. This example uses the local validation run; for another run, replace the path with its `unified/alerts.json` file:

```bash
export UNIFIED_ALERTS_PATH="$PWD/analysis/final-demo-run-20261121-v3/unified/alerts.json"
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000
```

The service reads the file for each request, so the pipeline can replace the JSON between API requests. If the path is unset, the service uses unified/alerts.json relative to the current working directory. The service allows HTTP requests from Flutter web development origins on localhost and 127.0.0.1, including arbitrary development ports.

For Flutter web on the same development machine, use http://localhost:8000. For an Android emulator, use http://10.0.2.2:8000 as the API base URL. CORS is a browser policy and does not apply to native Flutter networking.

## Endpoints

- GET /health returns service status and alerts file availability. The API remains available when the file is unavailable; health reports degraded status.
- GET /api/alerts returns alerts and pagination metadata. Pagination uses page (default 1) and page_size (default 50, maximum 500). Optional filters are severity, source_tool, rule_id, src_ip, dst_ip, and q. Exact filters are case-insensitive; q performs a case-insensitive search across alert fields.
- GET /api/alerts/{alert_id} returns one alert. IDs use the source JSON position, such as alert-000001. They are added to responses only and are not written to the source file.
- GET /api/stats returns total alerts and counts grouped by severity, source tool, and rule ID.

Example requests:

```bash
curl http://localhost:8000/health
curl 'http://localhost:8000/api/alerts?page=1&page_size=20&source_tool=Suricata'
curl 'http://localhost:8000/api/alerts?severity=high&src_ip=10.11.26.183&q=POST'
curl http://localhost:8000/api/alerts/alert-000001
curl http://localhost:8000/api/stats
```

The list response contains alerts and pagination fields page, page_size, total, and total_pages. File access or JSON validation failures return HTTP 503 with an error code and message. Invalid alert IDs return HTTP 404.

## Tests

```bash
python3 -m pytest -q tests/test_alerts_api.py
```

The endpoint tests use FastAPI TestClient and therefore require httpx, included in requirements-api.txt.
