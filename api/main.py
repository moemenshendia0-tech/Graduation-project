"""Read-only FastAPI service for unified detection alert output."""

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.malwarebazaar import MalwareIntelEnvelope, MalwareIntelError, lookup_hash
from api.malware_analysis import (
    AnalysisCase,
    AnalysisListResponse,
    AnalysisStore,
    CorrelationResponse,
    MalwareStoreError,
    TelemetryEventInput,
    TelemetryListResponse,
    SampleLookupResponse,
    correlate_telemetry,
    relate_telemetry_events,
    stable_event_id,
)

DEFAULT_ALERTS_PATH = Path("unified/alerts.json")
ALERT_ID_PATTERN = re.compile(r"^alert-(\d{6,})$")


class AlertsDataError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def alerts_path() -> Path:
    return Path(os.environ.get("UNIFIED_ALERTS_PATH", str(DEFAULT_ALERTS_PATH))).expanduser()


def load_alerts() -> list[dict[str, Any]]:
    path = alerts_path()
    try:
        with path.open(encoding="utf-8") as source:
            payload = json.load(source)
    except FileNotFoundError as exc:
        raise AlertsDataError("alerts_file_unavailable", "Alerts file is unavailable") from exc
    except (OSError, UnicodeError) as exc:
        raise AlertsDataError("alerts_file_unavailable", "Alerts file cannot be read") from exc
    except json.JSONDecodeError as exc:
        raise AlertsDataError("alerts_file_invalid", "Alerts file is not valid JSON") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("alerts"), list):
        raise AlertsDataError("alerts_file_invalid", "Expected a JSON object with an alerts list")

    for position, alert in enumerate(payload["alerts"], start=1):
        if not isinstance(alert, dict):
            raise AlertsDataError("alerts_file_invalid", f"Alert at position {position} must be an object")
        for field in ("source_tool", "rule_id"):
            if not isinstance(alert.get(field), str) or not alert[field]:
                raise AlertsDataError(
                    "alerts_file_invalid",
                    f"Alert at position {position} must have a non-empty string {field}",
                )
    return payload["alerts"]


def response_alert(alert: dict[str, Any], position: int) -> dict[str, Any]:
    # Add an ID to a copy only; the source JSON remains unchanged.
    return {**alert, "alert_id": f"alert-{position + 1:06d}"}


def normalized(value: Any) -> str:
    return "" if value is None else str(value).casefold()


def unavailable_response(exc: AlertsDataError) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


app = FastAPI(title="Unified Detection API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.exception_handler(MalwareStoreError)
async def malware_store_error_handler(request: Request, exc: MalwareStoreError):
    return JSONResponse(status_code=503, content={"error": {"code": "malware_store_unavailable", "message": str(exc)}})


@app.exception_handler(AlertsDataError)
async def alerts_data_error_handler(request: Request, exc: AlertsDataError):
    return unavailable_response(exc)


@app.exception_handler(MalwareIntelError)
async def malware_intel_error_handler(request: Request, exc: MalwareIntelError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


@app.get("/health")
def health():
    try:
        load_alerts()
    except AlertsDataError as exc:
        return {
            "status": "degraded",
            "alerts_file_available": False,
            "error": {"code": exc.code, "message": exc.message},
        }
    return {"status": "ok", "alerts_file_available": True}


@app.get("/api/alerts")
def list_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=500),
    severity: str | None = None,
    source_tool: str | None = None,
    rule_id: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    q: str | None = None,
):
    alerts = load_alerts()
    filters = {
        "severity": severity,
        "source_tool": source_tool,
        "rule_id": rule_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
    }
    filtered = []
    for position, alert in enumerate(alerts):
        if any(value is not None and normalized(alert.get(field)) != normalized(value)
               for field, value in filters.items()):
            continue
        if q and q.casefold() not in json.dumps(alert, ensure_ascii=False, sort_keys=True).casefold():
            continue
        filtered.append((position, alert))

    total = len(filtered)
    start = (page - 1) * page_size
    page_alerts = [response_alert(alert, position) for position, alert in filtered[start:start + page_size]]
    return {
        "alerts": page_alerts,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": (total + page_size - 1) // page_size,
        },
    }


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    match = ALERT_ID_PATTERN.fullmatch(alert_id)
    if not match:
        return JSONResponse(status_code=404, content={"error": {"code": "alert_not_found", "message": "Alert not found"}})
    position = int(match.group(1)) - 1
    alerts = load_alerts()
    if position < 0 or position >= len(alerts):
        return JSONResponse(status_code=404, content={"error": {"code": "alert_not_found", "message": "Alert not found"}})
    return {"alert": response_alert(alerts[position], position)}


@app.get("/api/stats")
def stats():
    alerts = load_alerts()
    severity_counts = Counter(normalized(alert.get("severity")) or "unknown" for alert in alerts)
    source_counts = Counter(alert["source_tool"] for alert in alerts)
    rule_counts = Counter(alert["rule_id"] for alert in alerts)
    return {
        "stats": {
            "total_alerts": len(alerts),
            "severity_counts": dict(sorted(severity_counts.items())),
            "source_counts": dict(sorted(source_counts.items())),
            "rule_counts": dict(sorted(rule_counts.items())),
        }
    }


@app.get(
    "/api/malware/intel/{file_hash}",
    response_model=MalwareIntelEnvelope,
    response_model_exclude_unset=True,
)
def malware_intelligence(file_hash: str):
    try:
        return {"intelligence": lookup_hash(file_hash)}
    except ValueError as exc:
        return JSONResponse(
            status_code=422,
            content={"error": {"code": "invalid_hash", "message": str(exc)}},
        )


@app.get("/api/malware/analyses", response_model=AnalysisListResponse)
def list_malware_analyses(page: int = Query(default=1, ge=1), page_size: int = Query(default=20, ge=1, le=100)):
    records = AnalysisStore().list()
    start = (page - 1) * page_size
    selected = records[start:start + page_size]
    return {"analyses": selected, "pagination": {"page": page, "page_size": page_size,
            "total": len(records), "total_pages": (len(records) + page_size - 1) // page_size}}


def _find_analysis(analysis_id: str, records: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((record for record in records if record["analysis_id"] == analysis_id), None)


@app.get("/api/malware/analyses/{analysis_id}", response_model=AnalysisCase)
def get_malware_analysis(analysis_id: str):
    record = _find_analysis(analysis_id, AnalysisStore().list())
    if record is None:
        return JSONResponse(status_code=404, content={"error": {"code": "analysis_not_found", "message": "Analysis not found"}})
    return record


@app.get("/api/malware/samples/{sha256}", response_model=SampleLookupResponse)
def get_malware_sample(sha256: str):
    if not re.fullmatch(r"[a-fA-F0-9]{64}", sha256):
        return JSONResponse(status_code=422, content={"error": {"code": "invalid_hash", "message": "SHA-256 must contain 64 hexadecimal characters"}})
    normalized_hash = sha256.lower()
    matches = [record for record in AnalysisStore().list() if record["sample"]["sha256"] == normalized_hash]
    return {"sha256": normalized_hash, "analyses": [{"analysis_id": record["analysis_id"],
            "hash_status": record["sample"]["hash_status"], "sample": record["sample"]} for record in matches]}


@app.get("/api/malware/analyses/{analysis_id}/events", response_model=TelemetryListResponse)
def list_malware_events(analysis_id: str):
    record = _find_analysis(analysis_id, AnalysisStore().list())
    if record is None:
        return JSONResponse(status_code=404, content={"error": {"code": "analysis_not_found", "message": "Analysis not found"}})
    events = record["observations"].get("telemetry_events", [])
    return {"analysis_id": analysis_id, "events": events, "total": len(events)}


@app.get("/api/malware/analyses/{analysis_id}/findings", response_model=CorrelationResponse)
def get_malware_correlations(analysis_id: str):
    record = _find_analysis(analysis_id, AnalysisStore().list())
    if record is None:
        return JSONResponse(status_code=404, content={"error": {"code": "analysis_not_found", "message": "Analysis not found"}})
    return {"analysis_id": analysis_id, "findings": correlate_telemetry(record, load_alerts()),
            "event_relationships": relate_telemetry_events(record)}


@app.post("/api/malware/analyses/{analysis_id}/events")
def ingest_malware_events(analysis_id: str, payload: list[TelemetryEventInput] = Body(max_length=1000)):
    store = AnalysisStore()
    records = store.list()
    case = _find_analysis(analysis_id, records)
    if case is None:
        return JSONResponse(status_code=404, content={"error": {"code": "analysis_not_found", "message": "Analysis not found"}})
    observations = case["observations"]
    existing = observations.setdefault("telemetry_events", [])
    known_ids = {event["event_id"] for event in existing}
    expected_ids = [stable_event_id(analysis_id, event_input) for event_input in payload]
    if any(event_input.event_id is not None and event_input.event_id != expected
           for event_input, expected in zip(payload, expected_ids)):
        return JSONResponse(status_code=422, content={"error": {"code": "event_id_mismatch",
                                "message": "Telemetry event identifier does not match its content"}})
    accepted = 0
    duplicates = 0
    for event_input, event_id in zip(payload, expected_ids):
        if event_id in known_ids:
            duplicates += 1
            continue
        event = event_input.model_dump(mode="json")
        event["event_id"] = event_id
        existing.append(event)
        known_ids.add(event_id)
        accepted += 1
    if accepted:
        store.save(records)
    return {"analysis_id": analysis_id, "accepted": accepted, "duplicates": duplicates,
            "total_events": len(existing), "sample_hash_association":
            "verified" if case["sample"]["hash_status"] == "verified" else "not_verified"}
