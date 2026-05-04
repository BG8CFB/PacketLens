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
