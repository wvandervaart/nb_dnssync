"""Guards against out-of-order webhook delivery.

NetBox webhook delivery is at-least-once and unordered (retries can arrive
after a newer event for the same object has already been processed). We keep
the timestamp of the last successfully processed event per (object_type,
object_id) and skip anything older, so BIND always converges toward the
*latest* known NetBox state rather than flapping backward on a stale retry.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path


class EventStateStore:
    def __init__(self, db_path: str | Path):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS object_state (
                object_type TEXT NOT NULL,
                object_id INTEGER NOT NULL,
                last_event_timestamp TEXT NOT NULL,
                PRIMARY KEY (object_type, object_id)
            )
            """
        )
        self._conn.commit()

    def is_stale(self, object_type: str, object_id: int, timestamp: str) -> bool:
        row = self._conn.execute(
            "SELECT last_event_timestamp FROM object_state WHERE object_type = ? AND object_id = ?",
            (object_type, object_id),
        ).fetchone()
        if row is None:
            return False
        return timestamp <= row[0]

    def record(self, object_type: str, object_id: int, timestamp: str) -> None:
        self._conn.execute(
            """
            INSERT INTO object_state (object_type, object_id, last_event_timestamp)
            VALUES (?, ?, ?)
            ON CONFLICT (object_type, object_id)
            DO UPDATE SET last_event_timestamp = excluded.last_event_timestamp
            WHERE excluded.last_event_timestamp > object_state.last_event_timestamp
            """,
            (object_type, object_id, timestamp),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
