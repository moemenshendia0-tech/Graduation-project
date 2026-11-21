"""Read-only FastAPI service for unified detection alert output."""

import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

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
        raise AlertsDataError("alerts_file_unavailable", f"Alerts file not found: {path}") from exc
    except (OSError, UnicodeError) as exc:
        raise AlertsDataError("alerts_file_unavailable", f"Alerts file cannot be read: {path}") from exc
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
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.exception_handler(AlertsDataError)
async def alerts_data_error_handler(request: Request, exc: AlertsDataError):
    return unavailable_response(exc)


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
