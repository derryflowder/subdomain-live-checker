import json
import sqlite3

import src.database as database
from src.models import ResultStatus, SubdomainResult, TechDetection


def test_init_db_creates_table(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)

    database.init_db()

    with sqlite3.connect(db_path) as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'table' "
            "AND name IN ('scans', 'scan_results') "
            "ORDER BY name"
        ).fetchall()

    assert tables == [("scan_results",), ("scans",)]


def test_init_db_creates_index(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)

    database.init_db()

    with sqlite3.connect(db_path) as conn:
        indexes = conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type = 'index' "
            "AND name = 'idx_scan_results_scan_id'"
        ).fetchall()

    assert indexes == [("idx_scan_results_scan_id",)]


def test_save_and_get_previous_results(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)

    results = [
        SubdomainResult(
            hostname="api.example.com",
            status=ResultStatus.LIVE,
            status_code=200,
        ),
        SubdomainResult(
            hostname="admin.example.com",
            status=ResultStatus.FORBIDDEN,
            status_code=403,
        ),
    ]

    database.save_results("example.com", results)

    previous = database.get_previous_results("example.com")

    assert previous == {
        "api.example.com": {
            "hostname": "api.example.com",
            "status_code": 200,
            "status_text": "live",
            "tech": "[]",
            "findings": "[]",
        },
        "admin.example.com": {
            "hostname": "admin.example.com",
            "status_code": 403,
            "status_text": "forbidden",
            "tech": "[]",
            "findings": "[]",
        },
    }


def test_save_results_persists_tech(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)

    results = [
        SubdomainResult(
            hostname="api.example.com",
            status=ResultStatus.LIVE,
            status_code=200,
            technologies=[
                TechDetection(name="nginx", version="1.24.0", category="server"),
            ],
        ),
    ]

    database.save_results("example.com", results)
    previous = database.get_previous_results("example.com")

    tech_list = json.loads(previous["api.example.com"]["tech"])
    assert len(tech_list) == 1
    assert tech_list[0]["name"] == "nginx"
    assert tech_list[0]["version"] == "1.24.0"


def test_save_results_replaces_previous_state(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)

    first_scan = [
        SubdomainResult(
            hostname="old.example.com",
            status=ResultStatus.LIVE,
            status_code=200,
        ),
    ]

    second_scan = [
        SubdomainResult(
            hostname="new.example.com",
            status=ResultStatus.LIVE,
            status_code=200,
        ),
    ]

    database.save_results("example.com", first_scan)
    database.save_results("example.com", second_scan)

    previous = database.get_previous_results("example.com")

    assert "old.example.com" not in previous
    assert "new.example.com" in previous


def test_save_results_keeps_scan_history(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)

    first_scan = [
        SubdomainResult(
            hostname="old.example.com",
            status=ResultStatus.LIVE,
            status_code=200,
        ),
    ]

    second_scan = [
        SubdomainResult(
            hostname="new.example.com",
            status=ResultStatus.FORBIDDEN,
            status_code=403,
        ),
    ]

    database.save_results("example.com", first_scan)
    database.save_results("example.com", second_scan)

    with sqlite3.connect(db_path) as conn:
        scan_count = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE domain = ?",
            ("example.com",),
        ).fetchone()[0]

        result_count = conn.execute(
            """
            SELECT COUNT(*)
            FROM scan_results
            WHERE scan_id IN (
                SELECT id FROM scans WHERE domain = ?
            )
            """,
            ("example.com",),
        ).fetchone()[0]

    assert scan_count == 2
    assert result_count == 2


def test_calculate_diff_detects_new_changed_and_removed():
    previous = {
        "api.example.com": {
            "hostname": "api.example.com",
            "status_code": 200,
            "status_text": "live",
        },
        "dev.example.com": {
            "hostname": "dev.example.com",
            "status_code": 200,
            "status_text": "live",
        },
        "old.example.com": {
            "hostname": "old.example.com",
            "status_code": 200,
            "status_text": "live",
        },
    }

    current = {
        "api.example.com": {
            "hostname": "api.example.com",
            "status_code": 200,
            "status_text": "live",
        },
        "dev.example.com": {
            "hostname": "dev.example.com",
            "status_code": 403,
            "status_text": "forbidden",
        },
        "new.example.com": {
            "hostname": "new.example.com",
            "status_code": 200,
            "status_text": "live",
        },
    }

    diff = database.calculate_diff(previous, current)

    assert diff["new"] == {"new.example.com"}
    assert diff["changed"] == {"dev.example.com"}
    assert diff["removed"] == {"old.example.com"}


def test_calculate_diff_detects_tech_change():
    previous = {
        "api.example.com": {
            "hostname": "api.example.com",
            "status_code": 200,
            "status_text": "live",
            "tech": '[{"name":"nginx","version":"1.24.0"}]',
        },
    }
    current = {
        "api.example.com": {
            "hostname": "api.example.com",
            "status_code": 200,
            "status_text": "live",
            "tech": '[{"name":"nginx","version":"1.25.0"}]',
        },
    }

    diff = database.calculate_diff(previous, current)

    assert diff["changed"] == {"api.example.com"}
    assert diff["new"] == set()
    assert diff["removed"] == set()


def test_calculate_diff_returns_empty_for_identical_scans():
    scan = {
        "api.example.com": {
            "hostname": "api.example.com",
            "status_code": 200,
            "status_text": "live",
        },
    }

    diff = database.calculate_diff(scan, scan)

    assert diff == {"new": set(), "changed": set(), "removed": set()}