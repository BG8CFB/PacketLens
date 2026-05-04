"""HistoryManager 真实测试 — 使用真实 SQLite"""

import sqlite3
import tempfile
import time
from datetime import datetime
from pathlib import Path

import pytest

from app.storage.history_manager import HistoryManager


@pytest.fixture
def history(tmp_path):
    """创建临时数据库的 HistoryManager"""
    db = tmp_path / "test_history.db"
    mgr = HistoryManager(db_path=db)
    yield mgr
    mgr.close()


def _make_session(session_id="s001", **overrides):
    """构造测试会话数据"""
    data = {
        "id": session_id,
        "start_time": datetime.now().isoformat(),
        "end_time": datetime.now().isoformat(),
        "interface": "以太网",
        "bpf_filter": "",
        "mode": "quick",
        "packet_count": 100,
        "flow_count": 5,
        "protocol_dist": '{"TCP": 60, "UDP": 30, "ICMP": 10}',
        "pcap_path": "captures/test.pcap",
        "report_path": "reports/test.md",
        "notes": "测试会话",
    }
    data.update(overrides)
    return data


class TestHistoryManagerCRUD:
    """完整 CRUD 测试"""

    def test_save_and_get_session(self, history):
        """保存后能读回"""
        data = _make_session("s001", packet_count=200)
        session_id = history.save_session(data)

        assert session_id == "s001"

        loaded = history.get_session("s001")
        assert loaded is not None
        assert loaded["id"] == "s001"
        assert loaded["packet_count"] == 200
        assert loaded["interface"] == "以太网"
        assert loaded["mode"] == "quick"

    def test_list_sessions(self, history):
        """保存多个会话后能列出"""
        for i in range(5):
            history.save_session(_make_session(f"s{i:03d}"))

        sessions = history.list_sessions()
        assert len(sessions) == 5

        # 按 created_at DESC 排序
        ids = [s["id"] for s in sessions]
        assert "s004" in ids

    def test_list_sessions_pagination(self, history):
        """分页查询"""
        for i in range(10):
            history.save_session(_make_session(f"s{i:03d}"))

        page1 = history.list_sessions(limit=3, offset=0)
        page2 = history.list_sessions(limit=3, offset=3)

        assert len(page1) == 3
        assert len(page2) == 3
        # 两页内容不应重叠
        ids1 = {s["id"] for s in page1}
        ids2 = {s["id"] for s in page2}
        assert ids1.isdisjoint(ids2)

    def test_delete_session(self, history):
        """删除会话"""
        history.save_session(_make_session("s_del"))
        assert history.get_session("s_del") is not None

        result = history.delete_session("s_del")
        assert result is True
        assert history.get_session("s_del") is None

    def test_delete_nonexistent_session(self, history):
        """删除不存在的会话不应崩溃"""
        result = history.delete_session("nonexistent")
        assert isinstance(result, bool)

    def test_get_nonexistent_session(self, history):
        """获取不存在的会话返回 None"""
        assert history.get_session("does_not_exist") is None

    def test_update_session(self, history):
        """使用 INSERT OR REPLACE 更新会话"""
        history.save_session(_make_session("s_upd", packet_count=100))
        history.save_session(_make_session("s_upd", packet_count=500))

        loaded = history.get_session("s_upd")
        assert loaded["packet_count"] == 500

    def test_save_session_with_all_fields(self, history):
        """所有字段都能正确保存和读回"""
        data = _make_session("s_full")
        history.save_session(data)

        loaded = history.get_session("s_full")
        for key, value in data.items():
            assert loaded[key] == value, f"字段 {key} 不匹配: 期望 {value}, 实际 {loaded[key]}"

    def test_save_session_filters_invalid_columns(self, history):
        """save_session 应过滤掉不在白名单中的字段"""
        data = _make_session("s_safe", malicious_column="DROP TABLE sessions; --")
        session_id = history.save_session(data)

        assert session_id == "s_safe"
        loaded = history.get_session("s_safe")
        assert loaded is not None
        assert "malicious_column" not in loaded

    def test_save_empty_data_returns_empty(self, history):
        """空数据应返回空字符串"""
        result = history.save_session({})
        assert result == ""

    def test_save_only_invalid_columns_returns_empty(self, history):
        """仅有无效列名的数据应返回空字符串"""
        result = history.save_session({"invalid_col": "value"})
        assert result == ""


class TestHistoryManagerDatabase:
    """数据库文件和连接测试"""

    def test_creates_db_file(self, tmp_path):
        """初始化时创建数据库文件"""
        db = tmp_path / "new_db.db"
        mgr = HistoryManager(db_path=db)
        assert db.exists()
        mgr.close()

    def test_creates_parent_dirs(self, tmp_path):
        """自动创建父目录"""
        db = tmp_path / "sub" / "dir" / "deep.db"
        mgr = HistoryManager(db_path=db)
        assert db.exists()
        mgr.close()

    def test_multiple_managers_same_db(self, tmp_path):
        """多个 Manager 实例可访问同一个数据库"""
        db = tmp_path / "shared.db"
        mgr1 = HistoryManager(db_path=db)
        mgr1.save_session(_make_session("shared_s1"))
        mgr1.close()

        mgr2 = HistoryManager(db_path=db)
        loaded = mgr2.get_session("shared_s1")
        assert loaded is not None
        assert loaded["id"] == "shared_s1"
        mgr2.close()

    def test_wal_mode_enabled(self, tmp_path):
        """数据库应启用 WAL 模式"""
        db = tmp_path / "wal_test.db"
        mgr = HistoryManager(db_path=db)
        mgr.save_session(_make_session("wal_s1"))

        # 通过直接查询验证 WAL 模式
        conn = sqlite3.connect(str(db))
        cursor = conn.execute("PRAGMA journal_mode")
        mode = cursor.fetchone()[0]
        conn.close()
        mgr.close()

        assert mode.lower() == "wal"


class TestHistoryManagerCloseSafety:
    """连接关闭后的安全性测试 — 核心缺陷 #1 验证"""

    def test_save_after_close_returns_empty(self, tmp_path):
        """关闭后 save_session 安全返回空字符串"""
        db = tmp_path / "closed.db"
        mgr = HistoryManager(db_path=db)
        mgr.close()

        result = mgr.save_session(_make_session("should_fail"))
        assert result == ""

    def test_list_after_close_returns_empty(self, tmp_path):
        """关闭后 list_sessions 安全返回空列表"""
        db = tmp_path / "closed.db"
        mgr = HistoryManager(db_path=db)
        mgr.save_session(_make_session("existing"))
        mgr.close()

        result = mgr.list_sessions()
        assert result == []

    def test_get_after_close_returns_none(self, tmp_path):
        """关闭后 get_session 安全返回 None"""
        db = tmp_path / "closed.db"
        mgr = HistoryManager(db_path=db)
        mgr.save_session(_make_session("existing"))
        mgr.close()

        result = mgr.get_session("existing")
        assert result is None

    def test_delete_after_close_returns_false(self, tmp_path):
        """关闭后 delete_session 安全返回 False"""
        db = tmp_path / "closed.db"
        mgr = HistoryManager(db_path=db)
        mgr.save_session(_make_session("existing"))
        mgr.close()

        result = mgr.delete_session("existing")
        assert result is False

    def test_purge_after_close_returns_zero(self, tmp_path):
        """关闭后 purge_old_sessions 安全返回 0"""
        db = tmp_path / "closed.db"
        mgr = HistoryManager(db_path=db)
        mgr.close()

        result = mgr.purge_old_sessions(30)
        assert result == 0

    def test_double_close_safe(self, tmp_path):
        """多次 close 不应抛出异常"""
        db = tmp_path / "double_close.db"
        mgr = HistoryManager(db_path=db)
        mgr.close()
        mgr.close()  # 不应抛出异常
        mgr.close()

    def test_context_manager(self, tmp_path):
        """上下文管理器应正确关闭连接"""
        db = tmp_path / "ctx.db"
        with HistoryManager(db_path=db) as mgr:
            mgr.save_session(_make_session("ctx_s1"))

        # 退出后操作应安全
        result = mgr.get_session("ctx_s1")
        assert result is None

    def test_del_does_not_raise(self, tmp_path):
        """__del__ 不应抛出异常"""
        db = tmp_path / "del_test.db"
        mgr = HistoryManager(db_path=db)
        mgr.save_session(_make_session("del_s1"))
        # 显式删除触发 __del__
        del mgr


class TestHistoryManagerPurge:
    """purge_old_sessions 测试 — 核心缺陷 #2 覆盖"""

    def test_purge_old_sessions_removes_expired(self, tmp_path):
        """应删除超过保留天数的会话"""
        db = tmp_path / "purge_test.db"
        mgr = HistoryManager(db_path=db)

        # 直接用 SQL 插入一个 60 天前的旧记录
        conn = sqlite3.connect(str(db))
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, start_time, created_at) VALUES (?, ?, datetime('now', '-60 days'))",
            ("old_session", datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()

        # 再通过正常方式插入一个当前记录
        mgr.save_session(_make_session("new_session"))

        deleted = mgr.purge_old_sessions(retention_days=30)
        assert deleted == 1

        # 新记录应保留
        assert mgr.get_session("new_session") is not None
        # 旧记录应已删除
        assert mgr.get_session("old_session") is None
        mgr.close()

    def test_purge_keeps_recent_sessions(self, tmp_path):
        """不应删除保留期内的会话"""
        db = tmp_path / "purge_recent.db"
        mgr = HistoryManager(db_path=db)
        mgr.save_session(_make_session("recent_s1"))
        mgr.save_session(_make_session("recent_s2"))

        deleted = mgr.purge_old_sessions(retention_days=30)
        assert deleted == 0

        assert mgr.get_session("recent_s1") is not None
        assert mgr.get_session("recent_s2") is not None
        mgr.close()

    def test_purge_zero_days_rejected(self, tmp_path):
        """保留天数为 0 或负数应安全返回 0"""
        db = tmp_path / "purge_zero.db"
        mgr = HistoryManager(db_path=db)
        mgr.save_session(_make_session("any"))

        assert mgr.purge_old_sessions(retention_days=0) == 0
        assert mgr.purge_old_sessions(retention_days=-1) == 0
        mgr.close()

    def test_purge_mixed_sessions(self, tmp_path):
        """混合新旧记录，仅删除过期的"""
        db = tmp_path / "purge_mixed.db"
        mgr = HistoryManager(db_path=db)

        # 插入 3 个旧记录（60天前）
        conn = sqlite3.connect(str(db))
        for i in range(3):
            conn.execute(
                "INSERT OR REPLACE INTO sessions (id, start_time, created_at) VALUES (?, ?, datetime('now', '-60 days'))",
                (f"old_{i}", datetime.now().isoformat()),
            )
        conn.commit()
        conn.close()

        # 插入 2 个新记录
        mgr.save_session(_make_session("new_0"))
        mgr.save_session(_make_session("new_1"))

        deleted = mgr.purge_old_sessions(retention_days=30)
        assert deleted == 3

        sessions = mgr.list_sessions()
        assert len(sessions) == 2
        ids = {s["id"] for s in sessions}
        assert ids == {"new_0", "new_1"}
        mgr.close()

    def test_purge_empty_db_returns_zero(self, tmp_path):
        """空数据库清理返回 0"""
        db = tmp_path / "purge_empty.db"
        mgr = HistoryManager(db_path=db)

        deleted = mgr.purge_old_sessions(retention_days=30)
        assert deleted == 0
        mgr.close()

    def test_purge_custom_retention_period(self, tmp_path):
        """自定义保留天数"""
        db = tmp_path / "purge_custom.db"
        mgr = HistoryManager(db_path=db)

        # 插入一个 5 天前的记录
        conn = sqlite3.connect(str(db))
        conn.execute(
            "INSERT OR REPLACE INTO sessions (id, start_time, created_at) VALUES (?, ?, datetime('now', '-5 days'))",
            ("five_days_ago", datetime.now().isoformat()),
        )
        conn.commit()
        conn.close()

        # 7 天保留 — 不应删除
        assert mgr.purge_old_sessions(retention_days=7) == 0

        # 3 天保留 — 应删除
        assert mgr.purge_old_sessions(retention_days=3) == 1
        assert mgr.get_session("five_days_ago") is None
        mgr.close()


class TestHistoryManagerSQLSafety:
    """SQL 安全性测试"""

    def test_column_whitelist_prevents_injection(self, tmp_path):
        """白名单机制防止 SQL 注入"""
        db = tmp_path / "sqli_test.db"
        mgr = HistoryManager(db_path=db)

        # 尝试注入恶意列名
        malicious_data = {
            "id": "sqli_1",
            "start_time": datetime.now().isoformat(),
            "malicious); DROP TABLE sessions; --": "evil",
        }
        session_id = mgr.save_session(malicious_data)
        assert session_id == "sqli_1"

        # 表应仍然存在且正常工作
        mgr.save_session(_make_session("after_injection"))
        assert mgr.get_session("after_injection") is not None
        mgr.close()

    def test_special_characters_in_values(self, tmp_path):
        """特殊字符在值中应安全存储"""
        db = tmp_path / "special_chars.db"
        mgr = HistoryManager(db_path=db)

        data = _make_session(
            "s_special",
            bpf_filter="port 80 and host 192.168.1.1",
            notes="包含'单引号\"双引号;分号--注释",
        )
        mgr.save_session(data)

        loaded = mgr.get_session("s_special")
        assert loaded is not None
        assert loaded["bpf_filter"] == "port 80 and host 192.168.1.1"
        assert "单引号" in loaded["notes"]
        assert "双引号" in loaded["notes"]
        mgr.close()

    def test_large_protocol_dist_json(self, tmp_path):
        """大型 JSON 字符串应安全存储"""
        db = tmp_path / "large_json.db"
        mgr = HistoryManager(db_path=db)

        import json
        large_dist = json.dumps({f"proto_{i}": i for i in range(100)})
        data = _make_session("s_large", protocol_dist=large_dist)
        mgr.save_session(data)

        loaded = mgr.get_session("s_large")
        assert loaded["protocol_dist"] == large_dist
        mgr.close()
