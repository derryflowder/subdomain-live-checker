import json
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path

from src.models import SubdomainResult

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "scan_history.db"


class DatabaseError(Exception):
    """Raised when the scan history database cannot be read or written."""


class ScanRepository(ABC):
    """Abstract interface for storing and retrieving scan history."""

    @abstractmethod
    def get_previous_results(self, domain: str) -> dict[str, dict]:
        pass

    @abstractmethod
    def save_results(self, domain: str, results: list[SubdomainResult]) -> None:
        pass

    @abstractmethod
    def clear_history(self) -> None:
        pass


class SQLiteScanRepository(ScanRepository):
    """SQLite implementation of the ScanRepository."""

    def __init__(self, db_path: Path | str = DB_PATH) -> None:
        self.db_path = Path(db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_db(self) -> None:
        """Creates scan history tables if they do not already exist."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    started_at TEXT NOT NULL
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    scan_id INTEGER NOT NULL,
                    hostname TEXT NOT NULL,
                    status_code INTEGER,
                    status_text TEXT,
                    tech TEXT DEFAULT '',
                    findings TEXT DEFAULT '',
                    PRIMARY KEY (scan_id, hostname),
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)

            for column in ("tech", "findings"):
                try:
                    conn.execute(
                        f"ALTER TABLE scan_results ADD COLUMN {column} TEXT DEFAULT ''"
                    )
                except sqlite3.OperationalError:
                    pass

            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_results_scan_id "
                "ON scan_results(scan_id)"
            )

            conn.commit()

    def get_previous_results(self, domain: str) -> dict[str, dict]:
        self.init_db()

        try:
            with self._connect() as conn:
                conn.row_factory = sqlite3.Row

                cursor = conn.execute(
                    """
                    SELECT hostname, status_code, status_text, tech, findings
                    FROM scan_results
                    WHERE scan_id = (
                        SELECT id
                        FROM scans
                        WHERE domain = ?
                        ORDER BY id DESC
                        LIMIT 1
                    )
                    """,
                    (domain,),
                )

                return {
                    row["hostname"]: {
                        "hostname": row["hostname"],
                        "status_code": row["status_code"],
                        "status_text": row["status_text"],
                        "tech": row["tech"] or "",
                        "findings": row["findings"] or "",
                    }
                    for row in cursor.fetchall()
                }
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to read scan history: {exc}") from exc

    def save_results(self, domain: str, results: list[SubdomainResult]) -> None:
        self.init_db()

        try:
            with self._connect() as conn:
                cursor = conn.execute(
                    "INSERT INTO scans (domain, started_at) VALUES (?, ?)",
                    (domain, datetime.now(timezone.utc).isoformat()),
                )

                scan_id = cursor.lastrowid

                data = [
                    (
                        scan_id,
                        r.hostname,
                        r.status_code if r.status_code is not None else -1,
                        r.status.value if r.status else "",
                        _serialize_tech(r),
                        _serialize_findings(r),
                    )
                    for r in results
                ]

                conn.executemany(
                    """
                    INSERT INTO scan_results (
                        scan_id, hostname, status_code, status_text, tech, findings
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    data,
                )

                conn.commit()
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to save scan results: {exc}") from exc

    def clear_history(self) -> None:
        if self.db_path.exists():
            self.db_path.unlink()
        self.init_db()


def _serialize_tech(result: SubdomainResult) -> str:
    return json.dumps(
        [
            {"name": t.name, "version": t.version, "category": t.category}
            for t in result.technologies
        ]
    )


def _serialize_findings(result: SubdomainResult) -> str:
    return json.dumps(
        [
            {
                "path": f.path,
                "status_code": f.status_code,
                "content_length": f.content_length,
                "redirect_url": f.redirect_url,
                "title": f.title,
            }
            for f in result.findings
        ]
    )


def calculate_diff(
    previous: dict[str, dict],
    current: dict[str, dict],
) -> dict[str, set[str]]:
    """Compares two scans and returns NEW, CHANGED and REMOVED."""
    previous_hosts = set(previous)
    current_hosts = set(current)

    new_hosts = current_hosts - previous_hosts
    removed_hosts = previous_hosts - current_hosts

    changed_hosts = {
        hostname
        for hostname in previous_hosts & current_hosts
        if (
            previous[hostname]["status_code"]
            != current[hostname]["status_code"]
            or previous[hostname]["status_text"]
            != current[hostname]["status_text"]
            or previous[hostname].get("tech", "")
            != current[hostname].get("tech", "")
        )
    }

    return {
        "new": new_hosts,
        "changed": changed_hosts,
        "removed": removed_hosts,
    }