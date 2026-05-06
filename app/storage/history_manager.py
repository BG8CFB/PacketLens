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

# 允许的列名白名单，防止 SQL 注入
ALLOWED_COLUMNS = frozenset({
    "id", "start_time", "end_time", "interface", "bpf_filter",
    "mode", "packet_count", "flow_count", "protocol_dist",
    "pcap_path", "report_path", "notes", "created_at",
})


class _ConnectionClosed(Exception):
    """连接已关闭时抛出的内部异常"""
    pass


class HistoryManager:
    """SQLite 历史会话管理器（线程安全）

    使用 WAL 模式提高并发读写性能。
    所有公开方法在连接已关闭后调用会安全返回默认值而非抛出 AttributeError。
    """

    def __init__(self, db_path: Path | None = None):
        self._path = db_path or get_db_path()
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self._closed = False
        self._connect()

    def _connect(self) -> None:
        """建立数据库连接并初始化 schema"""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # 启用 WAL 模式：提高并发读写性能，避免读写互斥
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(SCHEMA)
        self._conn.commit()
        self._closed = False

    def _ensure_conn(self) -> sqlite3.Connection:
        """确保连接可用，已关闭则抛出内部异常"""
        if self._conn is None or self._closed:
            raise _ConnectionClosed()
        return self._conn

    def save_session(self, session_data: dict) -> str:
        """保存会话记录

        Args:
            session_data: 会话数据字典，仅 ALLOWED_COLUMNS 中的键会被写入

        Returns:
            保存的会话 ID，连接已关闭时返回空字符串
        """
        safe_data = {k: v for k, v in session_data.items() if k in ALLOWED_COLUMNS}
        if not safe_data:
            return ""

        cols = ", ".join(safe_data.keys())
        placeholders = ", ".join("?" for _ in safe_data)
        values = list(safe_data.values())

        try:
            with self._lock:
                conn = self._ensure_conn()
                conn.execute(
                    f"INSERT OR REPLACE INTO sessions ({cols}) VALUES ({placeholders})",
                    values,
                )
                conn.commit()
        except _ConnectionClosed:
            logger.warning("save_session: 连接已关闭，操作被忽略")
            return ""
        except sqlite3.Error as e:
            logger.error(f"save_session 数据库错误: {e}")
            return ""

        logger.info(f"会话已保存: {safe_data.get('id', '?')}")
        return safe_data.get("id", "")

    def list_sessions(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """列出历史会话

        Args:
            limit: 返回条数上限
            offset: 偏移量

        Returns:
            会话字典列表，连接已关闭时返回空列表
        """
        try:
            with self._lock:
                conn = self._ensure_conn()
                cursor = conn.execute(
                    "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                )
                return [dict(row) for row in cursor.fetchall()]
        except _ConnectionClosed:
            logger.warning("list_sessions: 连接已关闭，返回空列表")
            return []
        except sqlite3.Error as e:
            logger.error(f"list_sessions 数据库错误: {e}")
            return []

    def get_session(self, session_id: str) -> dict | None:
        """获取单个会话

        Returns:
            会话字典或 None，连接已关闭时返回 None
        """
        try:
            with self._lock:
                conn = self._ensure_conn()
                cursor = conn.execute(
                    "SELECT * FROM sessions WHERE id = ?", (session_id,)
                )
                row = cursor.fetchone()
                return dict(row) if row else None
        except _ConnectionClosed:
            logger.warning("get_session: 连接已关闭，返回 None")
            return None
        except sqlite3.Error as e:
            logger.error(f"get_session 数据库错误: {e}")
            return None

    def delete_session(self, session_id: str) -> bool:
        """删除会话

        Returns:
            是否成功删除，连接已关闭时返回 False
        """
        try:
            with self._lock:
                conn = self._ensure_conn()
                cursor = conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
                conn.commit()
                return cursor.rowcount > 0
        except _ConnectionClosed:
            logger.warning("delete_session: 连接已关闭，操作被忽略")
            return False
        except sqlite3.Error as e:
            logger.error(f"delete_session 数据库错误: {e}")
            return False

    def close(self) -> None:
        """关闭数据库连接"""
        with self._lock:
            if self._conn is not None and not self._closed:
                try:
                    self._conn.close()
                except Exception as e:
                    logger.warning(f"关闭数据库连接时出错: {e}")
                finally:
                    self._conn = None
                    self._closed = True

    def __del__(self) -> None:
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def purge_old_sessions(self, retention_days: int = 30) -> int:
        """清理超过保留天数的历史会话

        Args:
            retention_days: 保留天数，默认 30 天

        Returns:
            删除的记录数，连接已关闭时返回 0
        """
        if retention_days <= 0:
            logger.warning(f"purge_old_sessions: 保留天数 {retention_days} 无效，跳过清理")
            return 0

        try:
            with self._lock:
                conn = self._ensure_conn()
                cursor = conn.execute(
                    "DELETE FROM sessions WHERE created_at < datetime('now', ?)",
                    (f"-{retention_days} days",),
                )
                conn.commit()
                deleted = cursor.rowcount
        except _ConnectionClosed:
            logger.warning("purge_old_sessions: 连接已关闭，操作被忽略")
            return 0
        except sqlite3.Error as e:
            logger.error(f"purge_old_sessions 数据库错误: {e}")
            return 0

        if deleted > 0:
            logger.info(f"清理了 {deleted} 条过期会话记录 (>{retention_days}天)")
        return deleted
