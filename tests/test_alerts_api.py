import json

import pytest
from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture
def def_sample():
    return [
        {"source_tool": "Zeek", "rule_id": "NET-001", "severity": "high",
         "src_ip": "10.0.0.1", "dst_ip": "203.0.113.10", "title": "Executable download"},
        {"source_tool": "Suricata", "rule_id": "SURICATA-7", "severity": "medium",
         "src_ip": "10.0.0.2", "dst_ip": "203.0.113.20", "title": "Suspicious flow"},
        {"source_tool": "Suricata", "rule_id": "SURICATA-8", "severity": "high",
         "src_ip": "10.0.0.1", "dst_ip": "203.0.113.20", "title": "Repeated query"},
    ]


@pytest.fixture
def client(tmp_path, monkeypatch, def_sample):
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps({"alerts": def_sample}), encoding="utf-8")
    monkeypatch.setenv("UNIFIED_ALERTS_PATH", str(path))
    return TestClient(app), path


def test_health_reports_available_alert_file(client):
    response = client[0].get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "alerts_file_available": True}


def test_alerts_pagination_and_stable_response_ids(client):
    response = client[0].get("/api/alerts?page=2&page_size=2")
    body = response.json()
    assert response.status_code == 200
    assert [alert["alert_id"] for alert in body["alerts"]] == ["alert-000003"]
    assert body["pagination"] == {"page": 2, "page_size": 2, "total": 3, "total_pages": 2}
    assert "alert_id" not in json.loads(client[1].read_text())["alerts"][2]


def test_alert_filters_and_free_text(client):
    response = client[0].get("/api/alerts", params={
        "severity": "HIGH", "source_tool": "suricata", "rule_id": "SURICATA-8",
        "src_ip": "10.0.0.1", "dst_ip": "203.0.113.20", "q": "Repeated",
    })
    body = response.json()
    assert body["pagination"]["total"] == 1
    assert body["alerts"][0]["alert_id"] == "alert-000003"


def test_alert_detail_and_not_found(client):
    found = client[0].get("/api/alerts/alert-000002")
    assert found.status_code == 200
    assert found.json()["alert"]["source_tool"] == "Suricata"
    assert found.json()["alert"]["alert_id"] == "alert-000002"
    missing = client[0].get("/api/alerts/alert-999999")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "alert_not_found"
    assert client[0].get("/api/alerts/not-an-id").status_code == 404


def test_stats_counts_total_severity_source_and_rules(client):
    response = client[0].get("/api/stats")
    assert response.status_code == 200
    assert response.json()["stats"] == {
        "total_alerts": 3,
        "severity_counts": {"high": 2, "medium": 1},
        "source_counts": {"Suricata": 2, "Zeek": 1},
        "rule_counts": {"NET-001": 1, "SURICATA-7": 1, "SURICATA-8": 1},
    }


def test_flutter_localhost_origin_is_allowed_by_cors(client):
    response = client[0].options(
        "/api/alerts",
        headers={
            "Origin": "http://localhost:58944",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:58944"


def test_missing_file_is_reported_by_health_and_data_endpoints(tmp_path, monkeypatch):
    monkeypatch.setenv("UNIFIED_ALERTS_PATH", str(tmp_path / "missing.json"))
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["alerts_file_available"] is False
    alerts = client.get("/api/alerts")
    assert alerts.status_code == 503
    assert alerts.json()["error"]["code"] == "alerts_file_unavailable"


def test_invalid_json_and_invalid_structure_are_handled(tmp_path, monkeypatch):
    path = tmp_path / "alerts.json"
    monkeypatch.setenv("UNIFIED_ALERTS_PATH", str(path))
    client = TestClient(app)
    path.write_text("{bad json", encoding="utf-8")
    assert client.get("/api/stats").json()["error"]["code"] == "alerts_file_invalid"
    path.write_text(json.dumps({"alerts": ["bad entry"]}), encoding="utf-8")
    assert client.get("/api/alerts").status_code == 503


def test_unreadable_path_is_handled_as_unavailable(tmp_path, monkeypatch):
    path = tmp_path / "directory"
    path.mkdir()
    monkeypatch.setenv("UNIFIED_ALERTS_PATH", str(path))
    response = TestClient(app).get("/api/stats")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "alerts_file_unavailable"
