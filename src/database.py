import sqlite3
from pathlib import Path

from src.models import SubdomainResult

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "scan_history.db"


def init_db():
    """Создает таблицу, если её нет."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS last_scan (
                domain TEXT,
                hostname TEXT,
                status_code INTEGER,
                status_text TEXT,
                PRIMARY KEY (domain, hostname)
            )
        """)
        conn.commit()


def get_previous_results(domain: str) -> dict[str, dict]:
    """Возвращает результаты предыдущего скана в виде словаря {hostname: {data}}."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT hostname, status_code, status_text FROM last_scan WHERE domain = ?", (domain,)
        )
        return {row["hostname"]: dict(row) for row in cursor.fetchall()}


def save_results(domain: str, results: list[SubdomainResult]):
    """Сохраняет текущий скан, перезаписывая старые данные для этого домена."""
    init_db()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM last_scan WHERE domain = ?", (domain,))
            data = [
                (
                    domain,
                    r.hostname,
                    r.status_code if r.status_code is not None else -1,
                    r.status.value if r.status else "",
                )
                for r in results
            ]
            conn.executemany(
    """
    INSERT INTO last_scan (
        domain, hostname, status_code, status_text
    ) VALUES (?, ?, ?, ?)
    """,
    data,
)
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")  # В будущем заменить на logging
