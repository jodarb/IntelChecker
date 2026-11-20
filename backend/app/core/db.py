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
        # Two-score verdict migration: entries saved before it keep NULLs here and
        # their `score` column is read as the Risk Score.
        existing = {row[1] for row in conn.execute("PRAGMA table_info(history)")}
        if "knowledge_score" not in existing:
            conn.execute("ALTER TABLE history ADD COLUMN knowledge_score INTEGER")
        if "quadrant" not in existing:
            conn.execute("ALTER TABLE history ADD COLUMN quadrant TEXT")
        # Who ran the lookup — NULL for entries saved before authentication existed.
        if "username" not in existing:
            conn.execute("ALTER TABLE history ADD COLUMN username TEXT")
        # Where the lookup came from: 'ui' (results page) or 'api' (POST /lookup).
        # NULL for entries saved before this column existed — those all came from the UI.
        if "via" not in existing:
            conn.execute("ALTER TABLE history ADD COLUMN via TEXT")


def save_query(
    indicator: str, type: str, score: int | None, knowledge_score: int | None,
    quadrant: str | None, results: dict, contributions: dict | list, username: str | None,
    via: str = "ui",
) -> int:
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO history (indicator, type, score, knowledge_score, quadrant, results_json, contributions_json, username, via) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (indicator, type, score, knowledge_score, quadrant, json.dumps(results), json.dumps(contributions), username, via),
        )
        return cur.lastrowid


def list_history(limit: int = 200, indicator: str | None = None) -> list[dict]:
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        if indicator:
            rows = conn.execute(
                "SELECT id, indicator, type, timestamp, score, knowledge_score, quadrant, username, via FROM history "
                "WHERE indicator = ? COLLATE NOCASE ORDER BY id DESC LIMIT ?",
                (indicator, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, indicator, type, timestamp, score, knowledge_score, quadrant, username, via FROM history ORDER BY id DESC LIMIT ?",
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
        contributions = json.loads(entry.pop("contributions_json"))
        # Pre-migration entries stored a flat list of risk contributions.
        if isinstance(contributions, list):
            contributions = {"risk": contributions, "knowledge": []}
        entry["contributions"] = contributions
        return entry


def get_frequency(indicator: str) -> dict:
    """How many times this exact indicator has been queried in the last 24h/72h/30d —
    timestamps are stored via SQLite's datetime('now'), i.e. UTC, so the comparison
    windows below use the same clock."""
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT
                SUM(CASE WHEN timestamp >= datetime('now', '-1 day')  THEN 1 ELSE 0 END),
                SUM(CASE WHEN timestamp >= datetime('now', '-3 day')  THEN 1 ELSE 0 END),
                SUM(CASE WHEN timestamp >= datetime('now', '-30 day') THEN 1 ELSE 0 END)
            FROM history
            WHERE indicator = ? COLLATE NOCASE
            """,
            (indicator,),
        ).fetchone()
        return {
            "last_24h": row[0] or 0,
            "last_72h": row[1] or 0,
            "last_30d": row[2] or 0,
        }
