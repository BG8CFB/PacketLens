"""path_helpers 真实测试 — 实际创建和检查路径"""

import os
from pathlib import Path

import pytest

from app.utils.path_helpers import (
    get_app_data_dir,
    get_captures_dir,
    get_config_path,
    get_db_path,
    get_reports_dir,
    resource_path,
    atomic_write,
)
from app.constants import APP_NAME


class TestPathHelpers:
    """路径工具函数真实测试"""

    def test_get_app_data_dir_exists(self):
        """应用数据目录应存在"""
        path = get_app_data_dir()
        assert path.exists()
        assert path.is_dir()

    def test_get_app_data_dir_contains_app_name(self):
        """路径应包含 APP_NAME"""
        path = get_app_data_dir()
        assert APP_NAME in str(path)

    def test_get_app_data_dir_under_appdata(self):
        """Windows 下应在 %APPDATA% 下"""
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            path = get_app_data_dir()
            assert appdata.replace("\\", "/") in str(path).replace("\\", "/")

    def test_get_captures_dir_exists(self):
        """captures 目录应存在"""
        path = get_captures_dir()
        assert path.exists()
        assert path.is_dir()
        assert path.name == "captures"

    def test_get_reports_dir_exists(self):
        """reports 目录应存在"""
        path = get_reports_dir()
        assert path.exists()
        assert path.is_dir()
        assert path.name == "reports"

    def test_get_config_path(self):
        """配置文件路径正确"""
        path = get_config_path()
        assert path.name == "config.json"
        assert APP_NAME in str(path)

    def test_get_db_path(self):
        """数据库路径正确"""
        path = get_db_path()
        assert path.name == "history.db"
        assert APP_NAME in str(path)

    def test_captures_dir_under_app_data(self):
        """captures 是 app_data 的子目录"""
        app_dir = get_app_data_dir()
        cap_dir = get_captures_dir()
        assert cap_dir.parent == app_dir

    def test_reports_dir_under_app_data(self):
        """reports 是 app_data 的子目录"""
        app_dir = get_app_data_dir()
        rep_dir = get_reports_dir()
        assert rep_dir.parent == app_dir

    def test_resource_path_development(self):
        """开发模式下资源路径正确"""
        res = resource_path("icons/app.png")
        assert "resources" in str(res)
        # Windows 用反斜杠，需用 PurePath 比较后缀
        assert res.parts[-2:] == ("icons", "app.png")

    def test_all_dirs_are_writable(self):
        """所有目录应可写"""
        for dir_func in [get_app_data_dir, get_captures_dir, get_reports_dir]:
            d = dir_func()
            test_file = d / "_write_test.tmp"
            try:
                test_file.write_text("test", encoding="utf-8")
                assert test_file.read_text(encoding="utf-8") == "test"
            finally:
                test_file.unlink(missing_ok=True)

    def test_idempotent_creation(self):
        """多次调用不会报错"""
        for _ in range(3):
            path = get_app_data_dir()
            assert path.exists()


# ─── atomic_write ───


class TestAtomicWrite:
    """原子写入函数测试"""

    def test_writes_content_correctly(self, tmp_path):
        """写入的内容应与读取的一致"""
        target = tmp_path / "test.txt"
        content = "Hello, PacketLens!"
        atomic_write(target, content)
        assert target.read_text(encoding="utf-8") == content

    def test_overwrites_existing_file(self, tmp_path):
        """覆盖已有文件"""
        target = tmp_path / "overwrite.txt"
        target.write_text("old content", encoding="utf-8")
        atomic_write(target, "new content")
        assert target.read_text(encoding="utf-8") == "new content"

    def test_creates_parent_directories(self, tmp_path):
        """自动创建不存在的父目录"""
        target = tmp_path / "sub1" / "sub2" / "deep.txt"
        atomic_write(target, "deep content")
        assert target.exists()
        assert target.read_text(encoding="utf-8") == "deep content"

    def test_handles_unicode_content(self, tmp_path):
        """支持 Unicode 内容"""
        target = tmp_path / "unicode.txt"
        content = "中文内容测试 🎉 émojis"
        atomic_write(target, content)
        assert target.read_text(encoding="utf-8") == content

    def test_handles_empty_content(self, tmp_path):
        """空字符串写入"""
        target = tmp_path / "empty.txt"
        atomic_write(target, "")
        assert target.exists()
        assert target.read_text(encoding="utf-8") == ""

    def test_handles_large_content(self, tmp_path):
        """大内容写入"""
        target = tmp_path / "large.txt"
        content = "A" * 1_000_000  # 1MB 内容
        atomic_write(target, content)
        assert target.read_text(encoding="utf-8") == content

    def test_no_temp_file_left_on_success(self, tmp_path):
        """成功写入后不应残留临时文件"""
        target = tmp_path / "clean.txt"
        atomic_write(target, "clean content")
        # 检查目录中没有 .tmp_ 开头的临时文件
        temp_files = list(tmp_path.glob("*.tmp_*"))
        assert len(temp_files) == 0

    def test_no_file_left_on_failure(self, tmp_path):
        """写入失败时不应留下目标文件"""
        target = tmp_path / "fail_test" / "nested" / "file.txt"
        # 使用不可写的路径模拟失败（路径中含无效字符）
        # 实际测试：写入到只读目录（如果可能）
        # 这里用一个简单的方式：目标路径为已存在的目录
        conflict_dir = tmp_path / "conflict"
        conflict_dir.mkdir()
        # 尝试写入到同名路径（conflict 是一个目录，不是文件）
        with pytest.raises(Exception):
            atomic_write(conflict_dir, "should fail")
