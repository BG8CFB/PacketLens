"""HistoryManager 真实测试 — 使用真实 SQLite"""

import tempfile
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
