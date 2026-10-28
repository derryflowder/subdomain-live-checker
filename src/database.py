import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from src.models import SubdomainResult

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "scan_history.db"


class DatabaseError(Exception):
    """Raised when the scan history database cannot be read or written."""


def init_db():
    """Creates scan history tables if they do not already exist."""
    with sqlite3.connect(DB_PATH) as conn:
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
                PRIMARY KEY (scan_id, hostname),
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)

        conn.commit()


def get_previous_results(domain: str) -> dict[str, dict]:
    """Returns the results of the last completed domain scan."""
    init_db()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row

            cursor = conn.execute(
                """
                SELECT hostname, status_code, status_text
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
                row["hostname"]: dict(row)
                for row in cursor.fetchall()
            }
    except sqlite3.Error as exc:
        raise DatabaseError(f"Failed to read scan history: {exc}") from exc


def save_results(domain: str, results: list[SubdomainResult]):
    """Creates a new scan and saves its results."""
    init_db()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute(
                """
                INSERT INTO scans (domain, started_at)
                VALUES (?, ?)
                """,
                (
                    domain,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

            scan_id = cursor.lastrowid

            data = [
                (
                    scan_id,
                    r.hostname,
                    r.status_code if r.status_code is not None else -1,
                    r.status.value if r.status else "",
                )
                for r in results
            ]

            conn.executemany(
                """
                INSERT INTO scan_results (
                    scan_id, hostname, status_code, status_text
                )
                VALUES (?, ?, ?, ?)
                """,
                data,
            )

            conn.commit()
    except sqlite3.Error as exc:
        raise DatabaseError(f"Failed to save scan results: {exc}") from exc


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
        )
    }

    return {
        "new": new_hosts,
        "changed": changed_hosts,
        "removed": removed_hosts,
    }