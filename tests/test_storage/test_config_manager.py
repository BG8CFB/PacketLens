"""ConfigManager 单元测试"""

import json
import tempfile
from pathlib import Path

from app.storage.config_manager import ConfigManager, DEFAULT_CONFIG


class TestConfigManager:

    def test_load_defaults_when_no_file(self, tmp_path: Path):
        config_path = tmp_path / "nonexistent" / "config.json"
        mgr = ConfigManager(config_path=config_path)

        # 应该用默认值初始化
        assert mgr.get("theme") == "dark"
        assert mgr.get("default_capture_duration") == 60
        assert mgr.get("auto_analyze") is True
        assert mgr.get("nonexistent_key", "fallback") == "fallback"

    def test_save_and_reload(self, tmp_path: Path):
        config_path = tmp_path / "config.json"

        # 创建并保存
        mgr1 = ConfigManager(config_path=config_path)
        mgr1.set("theme", "light")
        mgr1.set("custom_key", "custom_val")
        mgr1.save()

        # 确认文件存在
        assert config_path.exists()

        # 重新加载
        mgr2 = ConfigManager(config_path=config_path)
        assert mgr2.get("theme") == "light"
        assert mgr2.get("custom_key") == "custom_val"

    def test_config_property_returns_copy(self, tmp_path: Path):
        config_path = tmp_path / "config.json"
        mgr = ConfigManager(config_path=config_path)

        config_copy = mgr.config
        config_copy["new_key"] = "new_val"

        # 原始配置不应该被修改
        assert mgr.get("new_key") is None

    def test_overwrite_existing(self, tmp_path: Path):
        """已有配置文件应被正确读取而不是覆盖"""
        config_path = tmp_path / "config.json"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps({"theme": "custom", "extra": 42}))

        mgr = ConfigManager(config_path=config_path)
        assert mgr.get("theme") == "custom"
        assert mgr.get("extra") == 42
        # 不在文件中的 key 应返回 None
        assert mgr.get("default_capture_duration") is None
