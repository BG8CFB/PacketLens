"""SQLite 历史会话管理"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from app.utils.path_helpers import get_db_path

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    start_time TEXT NOT NULL,
    end_time TEXT,
    interface TEXT,
    bpf_filter TEXT,
    mode TEXT DEFAULT 'quick',
    packet_count INTEGER DEFAULT 0,
    flow_count INTEGER DEFAULT 0,
    protocol_dist TEXT,
    pcap_path TEXT,
    report_path TEXT,
    notes TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""

ALLOWED_COLUMNS = frozenset({
    "id", "start_time", "end_time", "interface", "bpf_filter",
    "mode", "packet_count", "flow_count", "protocol_dist",
    "pcap_path", "report_path", "notes", "created_at",
})


class HistoryManager:
    """SQLite 历史会话管理器（线程安全）"""

    def __init__(self, db_path: Path | None = None):
        self._path = db_path or get_db_path()
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self._connect()

    def _connect(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def save_session(self, session_data: dict) -> str:
        """保存会话记录"""
        safe_data = {k: v for k, v in session_data.items() if k in ALLOWED_COLUMNS}
        if not safe_data:
            return ""

        cols = ", ".join(safe_data.keys())
        placeholders = ", ".join("?" for _ in safe_data)
        values = list(safe_data.values())

        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO sessions ({cols}) VALUES ({placeholders})",
                values,
            )
            self._conn.commit()
        logger.info(f"会话已保存: {safe_data.get('id', '?')}")
        return safe_data.get("id", "")

    def list_sessions(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """列出历史会话"""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_session(self, session_id: str) -> dict | None:
        """获取单个会话"""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM sessions WHERE id = ?", (session_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def delete_session(self, session_id: str) -> bool:
        """删除会话"""
        with self._lock:
            cursor = self._conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            self._conn.commit()
            return cursor.rowcount > 0

    def close(self) -> None:
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
