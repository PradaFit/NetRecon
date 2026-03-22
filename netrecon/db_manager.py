"""
SQLite-backed scan history.

All queries are parameterized (no string concatenation).
WAL mode is enabled for better concurrent read performance.
The database lives in ~/.netrecon/history.db by default.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path


class DatabaseManager:

    def __init__(self, db_path=None):
        if db_path is None:
            app_dir = Path.home() / ".netrecon"
            app_dir.mkdir(exist_ok=True)
            db_path = app_dir / "history.db"
        self.db_path = str(db_path)
        self._setup()

    def _setup(self):
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type   TEXT NOT NULL,
                    target      TEXT NOT NULL,
                    summary     TEXT,
                    result_data TEXT,
                    timestamp   TEXT NOT NULL,
                    tags        TEXT
                )
            """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_type ON scan_history(scan_type)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_target ON scan_history(target)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ts ON scan_history(timestamp)")

    def _conn(self):
        c = sqlite3.connect(self.db_path, timeout=10)
        c.execute("PRAGMA busy_timeout=5000")
        return c

    # -- CRUD --

    def save(self, scan_type, target, result_data, summary="", tags=None):
        if hasattr(result_data, "to_dict"):
            result_data = result_data.to_dict()
        blob = json.dumps(result_data, default=str)
        tags_blob = json.dumps(tags) if tags else None

        with self._conn() as conn:
            conn.execute(
                "INSERT INTO scan_history "
                "(scan_type, target, summary, result_data, timestamp, tags) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    scan_type,
                    target,
                    summary,
                    blob,
                    datetime.now().isoformat(),
                    tags_blob,
                ),
            )

    def get_history(self, limit=100, scan_type=None, search=None):
        sql = "SELECT id, scan_type, target, summary, timestamp, tags FROM scan_history"
        params = []
        clauses = []

        if scan_type:
            clauses.append("scan_type = ?")
            params.append(scan_type)
        if search:
            clauses.append("(target LIKE ? OR summary LIKE ?)")
            params.extend([f"%{search}%", f"%{search}%"])

        if clauses:
            sql += " WHERE " + " AND ".join(clauses)

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def get_detail(self, scan_id):
        with self._conn() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM scan_history WHERE id = ?", (int(scan_id),)
            ).fetchone()
            if row:
                data = dict(row)
                try:
                    data["result_data"] = json.loads(data["result_data"])
                except (json.JSONDecodeError, TypeError):
                    data["result_data"] = {}
                return data
        return None

    def delete(self, scan_id):
        with self._conn() as conn:
            conn.execute("DELETE FROM scan_history WHERE id = ?", (int(scan_id),))

    def clear(self):
        with self._conn() as conn:
            conn.execute("DELETE FROM scan_history")
            conn.execute("VACUUM")

    def get_stats(self):
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
            by_type = conn.execute(
                "SELECT scan_type, COUNT(*) FROM scan_history GROUP BY scan_type"
            ).fetchall()
            recent = conn.execute(
                "SELECT target, scan_type, timestamp "
                "FROM scan_history ORDER BY timestamp DESC LIMIT 5"
            ).fetchall()
            return {
                "total_scans": total,
                "by_type": {r[0]: r[1] for r in by_type},
                "recent": [
                    {"target": r[0], "type": r[1], "time": r[2]} for r in recent
                ],
            }
