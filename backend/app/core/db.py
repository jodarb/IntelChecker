import json
import sqlite3
from pathlib import Path
from contextlib import contextmanager

# Query history lives in a SQLite file under backend/data/ — gitignored, and
# mounted as a volume in docker-compose so it survives container recreation.
_DB_PATH = Path(__file__).parent.parent.parent / "data" / "history.db"


@contextmanager
def _connect():
    conn = sqlite3.connect(_DB_PATH)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                type TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                score INTEGER,
                results_json TEXT NOT NULL,
                contributions_json TEXT NOT NULL
            )
        """)


def save_query(indicator: str, type: str, score: int | None, results: dict, contributions: list) -> int:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO history (indicator, type, score, results_json, contributions_json) "
            "VALUES (?, ?, ?, ?, ?)",
            (indicator, type, score, json.dumps(results), json.dumps(contributions)),
        )
        return cur.lastrowid


def list_history(limit: int = 200) -> list[dict]:
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, indicator, type, timestamp, score FROM history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_entry(entry_id: int) -> dict | None:
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM history WHERE id = ?", (entry_id,)).fetchone()
        if not row:
            return None
        entry = dict(row)
        entry["results"] = json.loads(entry.pop("results_json"))
        entry["contributions"] = json.loads(entry.pop("contributions_json"))
        return entry
