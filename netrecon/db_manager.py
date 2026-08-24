"""
SQLite-backed scan history.

All queries are parameterized (no string concatenation).
WAL mode is enabled for better concurrent read performance.
The database lives in ~/.netrecon/history.db by default.
"""

import sqlite3
import json
from contextlib import closing
from datetime import datetime
from pathlib import Path

from .config import get_section


class DatabaseManager:

    def __init__(self, db_path=None):
        if db_path is None:
            configured_path = get_section("database").get("path")
            if configured_path:
                db_path = Path(str(configured_path)).expanduser()
            else:
                app_dir = Path.home() / ".netrecon"
                app_dir.mkdir(exist_ok=True)
                db_path = app_dir / "history.db"
        resolved_path = Path(db_path).expanduser().resolve()
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = str(resolved_path)
        self._setup()

    def _setup(self):
        with closing(self._conn()) as conn, conn:
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

        with closing(self._conn()) as conn, conn:
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

        with closing(self._conn()) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def get_detail(self, scan_id):
        with closing(self._conn()) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM scan_history WHERE id = ?", (int(scan_id),)
            ).fetchone()
            if row:
                return self._decode_row(row)
        return None

    def get_export_records(self, limit=10000):
        """Return complete history rows, including decoded result payloads."""
        limit = max(1, min(int(limit), 10000))
        with closing(self._conn()) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            return [self._decode_row(row) for row in rows]

    @staticmethod
    def _decode_row(row):
        data = dict(row)
        try:
            data["result_data"] = json.loads(data.get("result_data") or "null")
        except (json.JSONDecodeError, TypeError):
            data["result_data"] = {}
        try:
            data["tags"] = json.loads(data.get("tags") or "null")
        except (json.JSONDecodeError, TypeError):
            data["tags"] = None
        return data

    def delete(self, scan_id):
        with closing(self._conn()) as conn, conn:
            conn.execute("DELETE FROM scan_history WHERE id = ?", (int(scan_id),))

    def clear(self):
        # delete inside a transaction, then VACUUM on a fresh connection
        # (VACUUM cannot run inside an open transaction)
        with closing(self._conn()) as conn, conn:
            conn.execute("DELETE FROM scan_history")
        with closing(self._conn()) as conn:
            conn.isolation_level = None
            conn.execute("VACUUM")

    def get_stats(self):
        with closing(self._conn()) as conn:
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
