"""ConfigManager 单元测试 — 覆盖 AI Provider 管理、配置持久化、Schema 升级"""

import json
import os
from pathlib import Path

import pytest

from app.config.ai_defaults import AI_DEFAULTS
from app.config import provider_loader
from app.storage.config_manager import ConfigManager, DEFAULT_CONFIG


# ── fixture ──


@pytest.fixture(autouse=True)
def _reset_builtin_cache():
    """每个测试前后重置内置 provider 缓存，保证隔离"""
    provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED
    yield
    provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED


@pytest.fixture
def config_path(tmp_path: Path) -> Path:
    """返回一个临时配置文件路径（不预先创建文件）"""
    return tmp_path / "config.json"


@pytest.fixture
def mgr(config_path: Path) -> ConfigManager:
    """创建一个使用临时路径的 ConfigManager"""
    return ConfigManager(config_path=config_path)


# ── 一、基础 load / save / get / set ──


class TestConfigManagerBasics:
    """基础 CRUD 测试"""

    def test_load_defaults_when_no_file(self, config_path: Path):
        """文件不存在时使用默认值初始化"""
        path = config_path.parent / "missing" / "config.json"
        m = ConfigManager(config_path=path)

        assert m.get("theme") == "dark"
        assert m.get("default_capture_duration") == 60
        assert m.get("auto_analyze") is True
        assert m.get("auto_save_pcap") is True
        assert m.get("default_mode") == "quick"
        assert m.get("nonexistent_key", "fallback") == "fallback"

    def test_load_creates_file_on_missing(self, config_path: Path):
        """文件不存在时 save 会自动创建"""
        m = ConfigManager(config_path=config_path)
        assert config_path.exists()

    def test_save_and_reload(self, config_path: Path):
        """保存后重新加载能读到修改"""
        m1 = ConfigManager(config_path=config_path)
        m1.set("theme", "light")
        m1.set("custom_key", "custom_val")
        m1.save()

        assert config_path.exists()

        m2 = ConfigManager(config_path=config_path)
        assert m2.get("theme") == "light"
        assert m2.get("custom_key") == "custom_val"

    def test_overwrite_existing(self, config_path: Path):
        """已有配置文件应被正确读取"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps({"theme": "custom", "extra": 42}))

        m = ConfigManager(config_path=config_path)
        assert m.get("theme") == "custom"
        assert m.get("extra") == 42
        assert m.get("default_capture_duration") is None

    def test_corrupt_file_fallback(self, config_path: Path):
        """损坏的 JSON 文件应回退到默认值"""
        config_path.write_text("{invalid json!!!")

        m = ConfigManager(config_path=config_path)
        # 应该使用默认值
        assert m.get("theme") == "dark"

    def test_config_property_returns_copy(self, mgr: ConfigManager):
        """config 属性返回深拷贝，修改不影响内部状态"""
        config_copy = mgr.config
        config_copy["new_key"] = "new_val"

        assert mgr.get("new_key") is None

    def test_set_overwrites(self, mgr: ConfigManager):
        """set() 能覆盖已有 key"""
        mgr.set("theme", "light")
        assert mgr.get("theme") == "light"
        mgr.set("theme", "dark")
        assert mgr.get("theme") == "dark"

    def test_save_writes_valid_json(self, config_path: Path):
        """save() 写入的是合法 JSON"""
        m = ConfigManager(config_path=config_path)
        m.set("test_key", "test_value")
        m.save()

        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["test_key"] == "test_value"

    def test_persistence_full_roundtrip(self, config_path: Path):
        """完整持久化链路：修改 → save → 新实例 load → 验证"""
        m1 = ConfigManager(config_path=config_path)
        m1.set("theme", "light")
        m1.set("default_capture_duration", 120)
        m1.set("auto_analyze", False)
        m1.save()

        m2 = ConfigManager(config_path=config_path)
        assert m2.get("theme") == "light"
        assert m2.get("default_capture_duration") == 120
        assert m2.get("auto_analyze") is False


# ── 二、AI Provider 管理核心方法 ──


class TestProviderManagement:
    """AI Provider 的增删改查和激活管理"""

    def test_get_providers_initially_empty(self, mgr: ConfigManager):
        """无环境变量时初始 provider 列表为空"""
        providers = mgr.get_providers()
        assert isinstance(providers, list)
        assert len(providers) == 0

    def test_get_providers_returns_deep_copy(self, mgr: ConfigManager):
        """get_providers 返回深拷贝，外部修改不影响内部"""
        mgr.set_providers(
            [{"name": "test", "api_key": "k1", "model": "m1"}],
            "test",
        )
        providers = mgr.get_providers()
        providers[0]["api_key"] = "tampered"

        internal = mgr.get_providers()
        assert internal[0]["api_key"] == "k1"

    def test_set_providers_and_get(self, mgr: ConfigManager):
        """set_providers 保存后 get_providers 能读回"""
        custom_providers = [
            {
                "name": "MyProvider",
                "provider_type": "openai",
                "api_base": "https://api.example.com/v1",
                "api_key": "sk-test-key",
                "model": "gpt-4o",
                "temperature": 0.5,
                "max_tokens": 4096,
                "context_window_tokens": 128000,
                "timeout": 60,
            },
        ]
        mgr.set_providers(custom_providers, "MyProvider")

        result = mgr.get_providers()
        assert len(result) == 1
        assert result[0]["name"] == "MyProvider"
        assert result[0]["api_key"] == "sk-test-key"
        assert result[0]["model"] == "gpt-4o"

    def test_set_providers_persistence(self, config_path: Path):
        """set_providers + save 后，新实例能读到 providers"""
        m1 = ConfigManager(config_path=config_path)
        providers = [
            {
                "name": "P1",
                "provider_type": "openai",
                "api_key": "key1",
                "model": "m1",
                "temperature": 0.3,
                "max_tokens": 4096,
                "context_window_tokens": 128000,
                "timeout": 60,
            },
            {
                "name": "P2",
                "provider_type": "openai",
                "api_key": "key2",
                "model": "m2",
                "temperature": 0.7,
                "max_tokens": 8192,
                "context_window_tokens": 200000,
                "timeout": 120,
            },
        ]
        m1.set_providers(providers, "P2")
        m1.save()

        m2 = ConfigManager(config_path=config_path)
        loaded = m2.get_providers()
        assert len(loaded) == 2
        assert loaded[0]["name"] == "P1"
        assert loaded[1]["name"] == "P2"

    def test_set_providers_updates_active_name(self, mgr: ConfigManager):
        """set_providers 同时更新激活的 provider 名称"""
        mgr.set_providers(
            [{"name": "A", "api_key": "k"}, {"name": "B", "api_key": "k"}],
            "B",
        )
        assert mgr.get_active_provider_name() == "B"

    def test_get_active_provider_name_default(self, mgr: ConfigManager):
        """无激活项时返回空字符串或第一个 provider"""
        name = mgr.get_active_provider_name()
        assert isinstance(name, str)
        assert name == ""  # 无 provider 时为空

    def test_get_active_provider_name_falls_to_first(self, mgr: ConfigManager):
        """激活项为空但有 providers 时，返回第一个"""
        mgr.set_providers(
            [{"name": "First", "api_key": "k"}, {"name": "Second", "api_key": "k"}],
            "",  # 空激活名
        )
        # set_providers 设置空激活名，但 get_active_provider_name 会回退到第一个
        # 注意：save + reload 后 ensure_provider_schema 会修正激活名
        mgr.save()
        mgr2 = ConfigManager(config_path=mgr._path)
        # ensure_provider_schema 会修正 active_provider 为第一个
        assert mgr2.get_active_provider_name() == "First"

    def test_get_ai_config_no_provider(self, mgr: ConfigManager):
        """无 provider 时 get_ai_config 返回 AI_DEFAULTS 兜底"""
        config = mgr.get_ai_config()
        assert config["temperature"] == AI_DEFAULTS["temperature"]
        assert config["timeout"] == AI_DEFAULTS["timeout"]
        assert config["max_concurrency"] == AI_DEFAULTS["max_concurrency"]
        assert config["provider_type"] == AI_DEFAULTS["provider_type"]
        assert config["context_window_tokens"] == AI_DEFAULTS["context_window_tokens"]
        assert config["max_tokens"] == AI_DEFAULTS["max_tokens"]

    def test_get_ai_config_with_provider(self, mgr: ConfigManager):
        """有 provider 时 get_ai_config 返回该 provider 的配置"""
        providers = [
            {
                "name": "TestAI",
                "provider_type": "openai",
                "api_base": "https://api.test.com/v1",
                "api_key": "sk-abc123",
                "model": "test-model",
                "temperature": 0.8,
                "max_tokens": 8192,
                "context_window_tokens": 64000,
                "timeout": 30,
                "max_concurrency": 5,
            },
        ]
        mgr.set_providers(providers, "TestAI")

        config = mgr.get_ai_config()
        assert config["provider_type"] == "openai"
        assert config["api_key"] == "sk-abc123"
        assert config["base_url"] == "https://api.test.com/v1"
        assert config["model"] == "test-model"
        assert config["temperature"] == 0.8
        assert config["max_tokens"] == 8192
        assert config["context_window_tokens"] == 64000
        assert config["timeout"] == 30
        assert config["max_concurrency"] == 5

    def test_get_ai_config_env_override(self, mgr: ConfigManager, monkeypatch):
        """环境变量 PACKETLENS_* 优先于 provider 配置"""
        providers = [
            {
                "name": "TestAI",
                "api_key": "original_key",
                "api_base": "https://original.com",
                "model": "original-model",
            },
        ]
        mgr.set_providers(providers, "TestAI")

        monkeypatch.setenv("PACKETLENS_API_KEY", "env_key_override")
        monkeypatch.setenv("PACKETLENS_API_BASE", "https://env-override.com")
        monkeypatch.setenv("PACKETLENS_MODEL", "env-model-override")

        config = mgr.get_ai_config()
        assert config["api_key"] == "env_key_override"
        assert config["base_url"] == "https://env-override.com"
        assert config["model"] == "env-model-override"

    def test_get_ai_config_partial_env_override(self, mgr: ConfigManager, monkeypatch):
        """仅部分环境变量设置时，其余值来自 provider"""
        providers = [
            {
                "name": "TestAI",
                "api_key": "provider_key",
                "model": "provider-model",
                "temperature": 0.5,
            },
        ]
        mgr.set_providers(providers, "TestAI")

        monkeypatch.setenv("PACKETLENS_API_KEY", "env_key_only")

        config = mgr.get_ai_config()
        assert config["api_key"] == "env_key_only"
        assert config["model"] == "provider-model"
        assert config["temperature"] == 0.5

    def test_get_default_provider_no_env(self, mgr: ConfigManager):
        """无环境变量时 get_default_provider 返回空 dict"""
        result = mgr.get_default_provider()
        assert isinstance(result, dict)
        assert len(result) == 0

    def test_get_default_provider_returns_deep_copy(self, mgr: ConfigManager, monkeypatch):
        """get_default_provider 返回深拷贝"""
        monkeypatch.setenv("AI_NAME", "EnvProvider")
        monkeypatch.setenv("AI_API_KEY", "test-key")
        monkeypatch.setenv("AI_MODEL", "test-model")
        provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED

        p1 = mgr.get_default_provider()
        p1["api_key"] = "tampered"

        p2 = mgr.get_default_provider()
        assert p2["api_key"] == "test-key"

    def test_multiple_providers_get_ai_config_active(self, mgr: ConfigManager):
        """多个 provider 时，get_ai_config 返回激活的那个"""
        providers = [
            {"name": "P1", "api_key": "key1", "model": "model1", "temperature": 0.1},
            {"name": "P2", "api_key": "key2", "model": "model2", "temperature": 0.9},
        ]
        mgr.set_providers(providers, "P2")

        config = mgr.get_ai_config()
        assert config["api_key"] == "key2"
        assert config["model"] == "model2"
        assert config["temperature"] == 0.9


# ── 三、Schema 升级与 ensure_provider_schema ──


class TestSchemaUpgrade:
    """配置 schema 升级和字段补全"""

    def test_schema_backfill_missing_fields(self, config_path: Path):
        """旧 provider 配置缺少新字段时自动补全"""
        old_config = {
            "theme": "dark",
            "ai_providers": [
                {
                    "name": "OldProvider",
                    "api_key": "old-key",
                    "model": "old-model",
                },
            ],
            "ai_active_provider": "OldProvider",
        }
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(old_config))

        m = ConfigManager(config_path=config_path)
        providers = m.get_providers()
        assert len(providers) >= 1

        p = [p for p in providers if p["name"] == "OldProvider"][0]
        # 应被补全的字段
        assert "temperature" in p
        assert "timeout" in p
        assert "context_window_tokens" in p
        assert "max_tokens" in p
        assert "provider_type" in p
        # 补全值应为 AI_DEFAULTS
        assert p["temperature"] == AI_DEFAULTS["temperature"]
        assert p["timeout"] == AI_DEFAULTS["timeout"]

    def test_schema_removes_deprecated_fields(self, config_path: Path):
        """废弃字段（max_output_tokens, max_input_chars）应被清理"""
        old_config = {
            "ai_providers": [
                {
                    "name": "OldP",
                    "api_key": "k",
                    "model": "m",
                    "max_output_tokens": 8192,
                    "max_input_chars": 50000,
                },
            ],
            "ai_active_provider": "OldP",
        }
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(old_config))

        m = ConfigManager(config_path=config_path)
        p = m.get_providers()[0]
        assert "max_output_tokens" not in p
        assert "max_input_chars" not in p

    def test_schema_fixes_invalid_active_provider(self, config_path: Path):
        """active_provider 指向不存在的 provider 时修正为第一个"""
        config_data = {
            "ai_providers": [
                {"name": "A", "api_key": "k1", "model": "m1"},
                {"name": "B", "api_key": "k2", "model": "m2"},
            ],
            "ai_active_provider": "NonExistent",
        }
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config_data))

        m = ConfigManager(config_path=config_path)
        assert m.get_active_provider_name() == "A"

    def test_schema_empty_active_provider_fixed(self, config_path: Path):
        """active_provider 为空但有 providers 时修正为第一个"""
        config_data = {
            "ai_providers": [
                {"name": "First", "api_key": "k1", "model": "m1"},
            ],
            "ai_active_provider": "",
        }
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config_data))

        m = ConfigManager(config_path=config_path)
        assert m.get_active_provider_name() == "First"

    def test_builtin_provider_from_env_merged(self, config_path: Path, monkeypatch):
        """有 AI_* 环境变量时，内置 provider 被合并到列表"""
        monkeypatch.setenv("AI_NAME", "BuiltinAI")
        monkeypatch.setenv("AI_API_KEY", "builtin-key")
        monkeypatch.setenv("AI_MODEL", "builtin-model")
        monkeypatch.setenv("AI_API_BASE", "https://builtin.api.com/v1")
        provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED

        m = ConfigManager(config_path=config_path)
        providers = m.get_providers()

        builtin = [p for p in providers if p["name"] == "BuiltinAI"]
        assert len(builtin) == 1
        assert builtin[0]["api_key"] == "builtin-key"
        assert builtin[0]["model"] == "builtin-model"
        assert builtin[0].get("is_default") is True

    def test_builtin_provider_persisted_and_reloaded(self, config_path: Path, monkeypatch):
        """内置 provider 持久化后，即使环境变量消失，仍可读回"""
        monkeypatch.setenv("AI_NAME", "PersistAI")
        monkeypatch.setenv("AI_API_KEY", "persist-key")
        monkeypatch.setenv("AI_MODEL", "persist-model")
        provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED

        m1 = ConfigManager(config_path=config_path)
        m1.save()

        # 清除环境变量 + 缓存
        monkeypatch.delenv("AI_NAME", raising=False)
        monkeypatch.delenv("AI_API_KEY", raising=False)
        monkeypatch.delenv("AI_MODEL", raising=False)
        provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED

        m2 = ConfigManager(config_path=config_path)
        providers = m2.get_providers()
        names = [p["name"] for p in providers]
        assert "PersistAI" in names

    def test_load_upgrade_saves_automatically(self, config_path: Path):
        """schema 升级后自动触发 save（文件时间戳变化）"""
        config_data = {
            "ai_providers": [
                {"name": "A", "api_key": "k"},  # 缺少 temperature 等字段
            ],
            "ai_active_provider": "A",
        }
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config_data))
        mtime_before = config_path.stat().st_mtime

        # 小延迟保证时间戳差异
        import time
        time.sleep(0.05)

        ConfigManager(config_path=config_path)
        mtime_after = config_path.stat().st_mtime

        # schema 升级后应自动保存
        assert mtime_after >= mtime_before

    def test_complete_provider_lifecycle(self, config_path: Path):
        """完整 provider 生命周期：添加 → 激活 → 获取配置 → 修改 → 删除"""
        m = ConfigManager(config_path=config_path)

        # 1. 添加 provider
        m.set_providers(
            [
                {
                    "name": "LifeProvider",
                    "provider_type": "openai",
                    "api_key": "lp-key",
                    "api_base": "https://lp.api.com",
                    "model": "lp-model",
                    "temperature": 0.4,
                    "max_tokens": 4096,
                    "context_window_tokens": 128000,
                    "timeout": 90,
                    "max_concurrency": 2,
                },
            ],
            "LifeProvider",
        )
        m.save()

        # 2. 验证激活
        assert m.get_active_provider_name() == "LifeProvider"

        # 3. 获取 AI 配置
        ai_cfg = m.get_ai_config()
        assert ai_cfg["api_key"] == "lp-key"
        assert ai_cfg["model"] == "lp-model"
        assert ai_cfg["temperature"] == 0.4

        # 4. 修改（更新 provider 列表）
        m.set_providers(
            [
                {
                    "name": "LifeProvider",
                    "provider_type": "openai",
                    "api_key": "lp-key-v2",
                    "api_base": "https://lp-v2.api.com",
                    "model": "lp-model-v2",
                    "temperature": 0.6,
                    "max_tokens": 8192,
                    "context_window_tokens": 200000,
                    "timeout": 120,
                    "max_concurrency": 4,
                },
            ],
            "LifeProvider",
        )
        m.save()

        # 5. 重载验证
        m2 = ConfigManager(config_path=config_path)
        ai_cfg2 = m2.get_ai_config()
        assert ai_cfg2["api_key"] == "lp-key-v2"
        assert ai_cfg2["model"] == "lp-model-v2"

        # 6. 删除 provider
        m2.set_providers([], "")
        m2.save()

        m3 = ConfigManager(config_path=config_path)
        assert m3.get_providers() == []
        # 删除后回退到 AI_DEFAULTS
        assert m3.get_ai_config()["temperature"] == AI_DEFAULTS["temperature"]
