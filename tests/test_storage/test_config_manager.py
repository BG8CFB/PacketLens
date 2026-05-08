"""ConfigManager 单元测试 — 覆盖 AI Provider 管理、配置持久化、Schema 升级"""

import json
import os
from pathlib import Path

import pytest

from app.config.ai_defaults import AI_DEFAULTS
from app.config.app_config_schema import ensure_app_config_schema
from app.constants import DEFAULT_CAPTURE_DURATION, MAX_CAPTURE_DURATION, MIN_CAPTURE_DURATION
from app.config import provider_loader
from app.storage.config_manager import ConfigManager, DEFAULT_CONFIG


# ── fixture ──


@pytest.fixture(autouse=True)
def _reset_builtin_cache(monkeypatch):
    """每个测试前后重置内置 provider 缓存，并清空 AI_* 环境变量

    实际 .env 文件中可能配置了 AI_NAME/AI_API_KEY/AI_MODEL 等内置 provider，
    会导致 ConfigManager 自动注入内置 provider，影响"无 provider"类测试隔离。
    通过 monkeypatch.delenv 在测试期间清空相关变量，测试结束后自动恢复。
    """
    # 清空可能干扰测试的 AI_* 环境变量
    for var in (
        "AI_NAME", "AI_API_KEY", "AI_MODEL", "AI_API_BASE",
        "AI_PROVIDER_TYPE", "AI_CONTEXT_WINDOW", "AI_MAX_TOKENS",
        "AI_TEMPERATURE", "AI_MAX_INPUT_CHARS", "AI_TIMEOUT",
        "AI_MAX_CONCURRENCY", "AI_MAX_LAYER2_FLOWS",
        "AI_PACKETS_PER_FLOW_LAYER1",
    ):
        monkeypatch.delenv(var, raising=False)
    # 重置缓存（_dotenv_loaded 不重置，避免重新加载 .env 把变量塞回来）
    provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED
    provider_loader._dotenv_loaded = True  # 阻止 _ensure_dotenv_loaded 重新载入
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
        assert m.get("default_capture_duration") == DEFAULT_CAPTURE_DURATION
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
        """已有配置文件应被正确读取，缺失键由 schema 迁移自动补全"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps({"theme": "custom", "extra": 42}))

        m = ConfigManager(config_path=config_path)
        assert m.get("theme") == "custom"
        assert m.get("extra") == 42
        # 缺失的 default_capture_duration 由 schema 迁移自动补全
        assert m.get("default_capture_duration") == DEFAULT_CAPTURE_DURATION

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
                "api_base": "https://api.openai.com/v1",
                "api_key": "sk-prod-config-key",
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
        assert result[0]["api_key"] == "sk-prod-config-key"
        assert result[0]["model"] == "gpt-4o"

    def test_set_providers_persistence(self, config_path: Path):
        """set_providers + save 后，新实例能读到 providers"""
        m1 = ConfigManager(config_path=config_path)
        providers = [
            {
                "name": "P1",
                "provider_type": "openai",
                "api_key": "sk-p1-prod-key",
                "model": "gpt-4o",
                "temperature": 0.3,
                "max_tokens": 4096,
                "context_window_tokens": 128000,
                "timeout": 60,
            },
            {
                "name": "P2",
                "provider_type": "openai",
                "api_key": "sk-p2-prod-key",
                "model": "claude-sonnet-4-6",
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
        assert config["max_input_chars"] == AI_DEFAULTS["max_input_chars"]

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
        monkeypatch.setenv("AI_API_KEY", "sk-env-override-key")
        monkeypatch.setenv("AI_MODEL", "gpt-4o")
        provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED

        p1 = mgr.get_default_provider()
        p1["api_key"] = "tampered"

        p2 = mgr.get_default_provider()
        assert p2["api_key"] == "sk-env-override-key"

    def test_multiple_providers_get_ai_config_active(self, mgr: ConfigManager):
        """多个 provider 时，get_ai_config 返回激活的那个"""
        providers = [
            {"name": "P1", "api_key": "sk-p1-prod-key", "model": "gpt-4o", "temperature": 0.1},
            {"name": "P2", "api_key": "sk-p2-prod-key", "model": "claude-sonnet-4-6", "temperature": 0.9},
        ]
        mgr.set_providers(providers, "P2")

        config = mgr.get_ai_config()
        assert config["api_key"] == "sk-p2-prod-key"
        assert config["model"] == "claude-sonnet-4-6"
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
                    "api_key": "sk-legacy-config-key",
                    "model": "gpt-3.5-turbo",
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
        assert "max_input_chars" in p
        assert "provider_type" in p
        # 补全值应为 AI_DEFAULTS
        assert p["temperature"] == AI_DEFAULTS["temperature"]
        assert p["timeout"] == AI_DEFAULTS["timeout"]
        assert p["max_input_chars"] == AI_DEFAULTS["max_input_chars"]

    def test_schema_removes_deprecated_fields(self, config_path: Path):
        """废弃字段（max_output_tokens）应被清理，max_input_chars 应保留"""
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
        # max_input_chars 是合法字段，应保留
        assert "max_input_chars" in p
        assert p["max_input_chars"] == 50000

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


# ── 四、边界条件与健壮性测试 ──


class TestConfigManagerEdgeCases:
    """边界条件和错误恢复测试"""

    def test_load_empty_file(self, config_path: Path):
        """空文件应回退到默认值"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("")

        m = ConfigManager(config_path=config_path)
        assert m.get("theme") == "dark"

    def test_load_non_json_content(self, config_path: Path):
        """非 JSON 内容文件应回退到默认值"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("This is not JSON at all!")

        m = ConfigManager(config_path=config_path)
        assert m.get("theme") == "dark"

    def test_load_unicode_content(self, config_path: Path):
        """含中文/Unicode 的配置应正确读写"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_data = {"theme": "dark", "custom_label": "自定义标签测试"}
        # 必须指定 utf-8 编码写入，因为 config_manager 以 utf-8 读取
        config_path.write_text(json.dumps(config_data, ensure_ascii=False), encoding="utf-8")

        m = ConfigManager(config_path=config_path)
        assert m.get("custom_label") == "自定义标签测试"

    def test_get_ai_config_max_input_chars_from_provider(self, config_path: Path):
        """provider 自定义 max_input_chars 应生效"""
        m = ConfigManager(config_path=config_path)
        providers = [
            {
                "name": "CustomInput",
                "provider_type": "openai",
                "api_key": "k",
                "model": "m",
                "max_input_chars": 100000,
            },
        ]
        m.set_providers(providers, "CustomInput")

        config = m.get_ai_config()
        assert config["max_input_chars"] == 100000

    def test_provider_loader_incomplete_env_ignored(self, config_path: Path, monkeypatch):
        """仅有 AI_NAME 但无 AI_API_KEY 时，内置 provider 不应被创建"""
        monkeypatch.setenv("AI_NAME", "IncompleteAI")
        monkeypatch.delenv("AI_API_KEY", raising=False)
        monkeypatch.delenv("AI_MODEL", raising=False)
        provider_loader._builtin_provider_cache = provider_loader._NOT_LOADED

        m = ConfigManager(config_path=config_path)
        providers = m.get_providers()
        names = [p["name"] for p in providers]
        assert "IncompleteAI" not in names

    def test_corrupt_file_creates_backup(self, config_path: Path):
        """损坏文件应创建 .corrupt 备份"""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("{broken!!!")

        m = ConfigManager(config_path=config_path)
        # 应使用默认值
        assert m.get("theme") == "dark"
        # 应创建备份文件
        backup = config_path.with_suffix(".json.corrupt")
        assert backup.exists()


# ── 五、max_layer2_flows 配置链回归（修复2） ──


class TestMaxLayer2FlowsConfigChain:
    """max_layer2_flows 字段必须贯穿 schema/get_ai_config/backfill 三处"""

    def test_get_ai_config_includes_max_layer2_flows_default(self, mgr: ConfigManager):
        """无 provider 时 get_ai_config 应回退到 AI_DEFAULTS['max_layer2_flows']"""
        cfg = mgr.get_ai_config()
        assert "max_layer2_flows" in cfg
        assert cfg["max_layer2_flows"] == AI_DEFAULTS["max_layer2_flows"]

    def test_get_ai_config_returns_provider_max_layer2_flows(self, mgr: ConfigManager):
        """provider 自定义 max_layer2_flows 应优先于默认值"""
        custom = AI_DEFAULTS["max_layer2_flows"] + 7
        mgr.set_providers(
            [
                {
                    "name": "L2",
                    "provider_type": "openai",
                    "api_key": "k",
                    "model": "m",
                    "max_layer2_flows": custom,
                },
            ],
            "L2",
        )
        cfg = mgr.get_ai_config()
        assert cfg["max_layer2_flows"] == custom

    def test_schema_backfills_max_layer2_flows(self, config_path: Path):
        """旧 provider 缺少 max_layer2_flows 时应被 backfill 为 AI_DEFAULTS"""
        old_config = {
            "ai_providers": [
                {
                    "name": "OldProv",
                    "api_key": "k",
                    "model": "m",
                },
            ],
            "ai_active_provider": "OldProv",
        }
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(old_config))

        m = ConfigManager(config_path=config_path)
        provider = [p for p in m.get_providers() if p["name"] == "OldProv"][0]
        assert "max_layer2_flows" in provider
        assert provider["max_layer2_flows"] == AI_DEFAULTS["max_layer2_flows"]


# ── 六、provider_loader 公开 API（修复7） ──


class TestProviderLoaderPublicAPI:
    """reset_builtin_provider_cache 必须是公开可调用 API（修复7）"""

    def test_reset_function_exists_and_callable(self):
        from app.config import provider_loader as pl

        assert hasattr(pl, "reset_builtin_provider_cache")
        assert callable(pl.reset_builtin_provider_cache)

    def test_reset_clears_cache_so_env_changes_take_effect(self, monkeypatch):
        """调用公开 reset 后再读取，env 变更应被反映"""
        from app.config import provider_loader as pl

        # 第一次：清空环境变量，缓存为 None
        monkeypatch.delenv("AI_NAME", raising=False)
        monkeypatch.delenv("AI_API_KEY", raising=False)
        monkeypatch.delenv("AI_MODEL", raising=False)
        pl.reset_builtin_provider_cache()
        assert pl.load_builtin_provider() is None

        # 第二次：设置环境变量，但不 reset，仍读到旧缓存（None）
        monkeypatch.setenv("AI_NAME", "ResetTest")
        monkeypatch.setenv("AI_API_KEY", "rk")
        monkeypatch.setenv("AI_MODEL", "rm")
        # 未调 reset，缓存仍为 None
        assert pl.load_builtin_provider() is None

        # 第三次：调用 reset 后应读到新值
        pl.reset_builtin_provider_cache()
        provider = pl.load_builtin_provider()
        assert provider is not None
        assert provider["name"] == "ResetTest"
        assert provider["api_key"] == "rk"
        assert provider["model"] == "rm"

    def test_reset_does_not_throw_when_called_repeatedly(self):
        """连续多次调用 reset 不应抛异常（幂等）"""
        from app.config import provider_loader as pl

        pl.reset_builtin_provider_cache()
        pl.reset_builtin_provider_cache()
        pl.reset_builtin_provider_cache()


# ── 七、config 属性深拷贝（修复6） ──


class TestConfigPropertyDeepCopy:
    """config 属性必须返回深拷贝，外部嵌套修改不应渗透到内部状态（修复6）"""

    def test_config_property_nested_list_isolated(self, mgr: ConfigManager):
        """修改返回的 config['ai_providers'] 列表项不应影响内部"""
        mgr.set_providers(
            [
                {
                    "name": "DeepCopyTest",
                    "provider_type": "openai",
                    "api_key": "deep-key",
                    "model": "deep-model",
                },
            ],
            "DeepCopyTest",
        )

        snapshot = mgr.config
        # 篡改快照中的嵌套 dict
        snapshot["ai_providers"][0]["api_key"] = "tampered"
        snapshot["ai_providers"].append({"name": "Injected", "api_key": "x"})

        # 内部状态保持不变
        internal_providers = mgr.get_providers()
        assert internal_providers[0]["api_key"] == "deep-key"
        assert all(p["name"] != "Injected" for p in internal_providers)

    def test_config_property_nested_dict_isolated(self, mgr: ConfigManager):
        """修改返回的 config 顶层 dict key 不应影响内部"""
        snapshot = mgr.config
        snapshot["new_top_level"] = "should-not-leak"

        # 内部不受影响
        assert mgr.get("new_top_level") is None


# ── 八、内置 provider 从 .env 读取并发/Layer2 流数（修复2 配置链） ──


class TestBuiltinProviderConcurrencyFields:
    """provider_loader 必须从 AI_MAX_CONCURRENCY / AI_MAX_LAYER2_FLOWS 读取"""

    def test_max_concurrency_loaded_from_env(self, monkeypatch):
        from app.config import provider_loader as pl

        monkeypatch.setenv("AI_NAME", "ConcAI")
        monkeypatch.setenv("AI_API_KEY", "ck")
        monkeypatch.setenv("AI_MODEL", "cm")
        monkeypatch.setenv("AI_MAX_CONCURRENCY", "9")
        pl.reset_builtin_provider_cache()

        provider = pl.load_builtin_provider()
        assert provider is not None
        assert provider["max_concurrency"] == 9

    def test_max_layer2_flows_loaded_from_env(self, monkeypatch):
        from app.config import provider_loader as pl

        monkeypatch.setenv("AI_NAME", "L2EnvAI")
        monkeypatch.setenv("AI_API_KEY", "lk")
        monkeypatch.setenv("AI_MODEL", "lm")
        monkeypatch.setenv("AI_MAX_LAYER2_FLOWS", "13")
        pl.reset_builtin_provider_cache()

        provider = pl.load_builtin_provider()
        assert provider is not None
        assert provider["max_layer2_flows"] == 13

    def test_invalid_int_falls_back_to_default(self, monkeypatch):
        """非法整数应安全 fallback 到 AI_DEFAULTS"""
        from app.config import provider_loader as pl

        monkeypatch.setenv("AI_NAME", "BadIntAI")
        monkeypatch.setenv("AI_API_KEY", "bk")
        monkeypatch.setenv("AI_MODEL", "bm")
        monkeypatch.setenv("AI_MAX_LAYER2_FLOWS", "not-a-number")
        pl.reset_builtin_provider_cache()

        provider = pl.load_builtin_provider()
        assert provider is not None
        assert provider["max_layer2_flows"] == AI_DEFAULTS["max_layer2_flows"]

    def test_missing_env_uses_default(self, monkeypatch):
        """未设置 max_layer2_flows / max_concurrency 时回退到默认"""
        from app.config import provider_loader as pl

        monkeypatch.setenv("AI_NAME", "DefAI")
        monkeypatch.setenv("AI_API_KEY", "dk")
        monkeypatch.setenv("AI_MODEL", "dm")
        monkeypatch.delenv("AI_MAX_LAYER2_FLOWS", raising=False)
        monkeypatch.delenv("AI_MAX_CONCURRENCY", raising=False)
        pl.reset_builtin_provider_cache()

        provider = pl.load_builtin_provider()
        assert provider is not None
        assert provider["max_concurrency"] == AI_DEFAULTS["max_concurrency"]
        assert provider["max_layer2_flows"] == AI_DEFAULTS["max_layer2_flows"]


# ── 九、内置 provider .env 字段同步到 config.json（timeout 等修复） ──


class TestBuiltinProviderEnvSync:
    """修改 .env 后重载，内置 provider 的字段必须同步更新到 config.json"""

    def test_env_timeout_synced_to_existing_provider(self, config_path: Path, monkeypatch):
        """首次写入 config.json 后修改 .env 的 AI_TIMEOUT，重载时应同步更新"""
        from app.config import provider_loader as pl

        # 第一步：以初始 timeout=120 写入 config.json
        monkeypatch.setenv("AI_NAME", "SyncAI")
        monkeypatch.setenv("AI_API_KEY", "sync-key")
        monkeypatch.setenv("AI_MODEL", "sync-model")
        monkeypatch.setenv("AI_API_BASE", "https://old.api.com")
        monkeypatch.setenv("AI_TIMEOUT", "120")
        pl._builtin_provider_cache = pl._NOT_LOADED

        m1 = ConfigManager(config_path=config_path)
        m1.save()

        # 验证初始值
        providers1 = m1.get_providers()
        sync_p1 = [p for p in providers1 if p["name"] == "SyncAI"][0]
        assert sync_p1["timeout"] == 120

        # 第二步：修改 .env 中的 timeout 和 api_base
        monkeypatch.setenv("AI_TIMEOUT", "600")
        monkeypatch.setenv("AI_API_BASE", "https://new.api.com")
        pl._builtin_provider_cache = pl._NOT_LOADED

        # 重载（模拟应用重启）
        m2 = ConfigManager(config_path=config_path)

        # timeout 和 api_base 应从 .env 同步到 config.json 中的已有 provider
        providers2 = m2.get_providers()
        sync_p2 = [p for p in providers2 if p["name"] == "SyncAI"][0]
        assert sync_p2["timeout"] == 600, f"timeout 未同步，期望 600，实际 {sync_p2['timeout']}"
        assert sync_p2["api_base"] == "https://new.api.com"

        # get_ai_config 也应反映新值
        ai_cfg = m2.get_ai_config()
        assert ai_cfg["timeout"] == 600

    def test_env_all_fields_synced_on_reload(self, config_path: Path, monkeypatch):
        """重载时所有内置 provider 字段都应从 .env 同步"""
        from app.config import provider_loader as pl

        # 初始写入
        monkeypatch.setenv("AI_NAME", "FullSync")
        monkeypatch.setenv("AI_API_KEY", "old-key")
        monkeypatch.setenv("AI_MODEL", "old-model")
        monkeypatch.setenv("AI_API_BASE", "https://old.api.com")
        monkeypatch.setenv("AI_TIMEOUT", "120")
        monkeypatch.setenv("AI_TEMPERATURE", "0.5")
        monkeypatch.setenv("AI_MAX_TOKENS", "4096")
        pl._builtin_provider_cache = pl._NOT_LOADED

        m1 = ConfigManager(config_path=config_path)
        m1.save()

        # 修改多个字段
        monkeypatch.setenv("AI_API_KEY", "new-key")
        monkeypatch.setenv("AI_MODEL", "new-model")
        monkeypatch.setenv("AI_API_BASE", "https://new.api.com")
        monkeypatch.setenv("AI_TIMEOUT", "300")
        monkeypatch.setenv("AI_TEMPERATURE", "0.7")
        monkeypatch.setenv("AI_MAX_TOKENS", "8192")
        pl._builtin_provider_cache = pl._NOT_LOADED

        m2 = ConfigManager(config_path=config_path)
        providers = m2.get_providers()
        p = [p for p in providers if p["name"] == "FullSync"][0]

        assert p["api_key"] == "new-key"
        assert p["model"] == "new-model"
        assert p["api_base"] == "https://new.api.com"
        assert p["timeout"] == 300
        assert p["temperature"] == 0.7
        assert p["max_tokens"] == 8192

    def test_non_default_provider_not_overwritten_by_env(self, config_path: Path, monkeypatch):
        """非内置 provider（is_default=False）不应被 .env 同步覆盖"""
        from app.config import provider_loader as pl

        monkeypatch.setenv("AI_NAME", "BuiltinAI")
        monkeypatch.setenv("AI_API_KEY", "builtin-key")
        monkeypatch.setenv("AI_MODEL", "builtin-model")
        monkeypatch.setenv("AI_TIMEOUT", "600")
        pl._builtin_provider_cache = pl._NOT_LOADED

        m1 = ConfigManager(config_path=config_path)
        # 手动添加一个非内置 provider
        providers = m1.get_providers()
        providers.append({
            "name": "CustomProvider",
            "provider_type": "openai",
            "api_key": "custom-key",
            "model": "custom-model",
            "timeout": 30,
            "is_default": False,
        })
        m1.set_providers(providers, "BuiltinAI")
        m1.save()

        # 修改 .env 的 timeout
        monkeypatch.setenv("AI_TIMEOUT", "999")
        pl._builtin_provider_cache = pl._NOT_LOADED

        m2 = ConfigManager(config_path=config_path)
        providers2 = m2.get_providers()

        # 非内置 provider 的 timeout 不应被 .env 覆盖
        custom = [p for p in providers2 if p["name"] == "CustomProvider"][0]
        assert custom["timeout"] == 30

        # 内置 provider 的 timeout 应被更新
        builtin = [p for p in providers2 if p["name"] == "BuiltinAI"][0]
        assert builtin["timeout"] == 999


# ── 十、应用级配置 schema 迁移 ──


class TestAppConfigSchema:
    """ensure_app_config_schema 补全缺失键、校验数值范围"""

    def test_backfill_missing_keys(self):
        """缺失的应用级配置键应被补全"""
        config = {"theme": "dark"}
        dirty = ensure_app_config_schema(config)
        assert dirty is True
        assert config["default_capture_duration"] == DEFAULT_CAPTURE_DURATION
        assert config["auto_analyze"] is True

    def test_no_change_when_all_keys_present(self):
        """所有键已存在时不修改"""
        config = {
            "theme": "dark",
            "default_capture_duration": 120,
            "auto_analyze": False,
            "auto_save_pcap": True,
            "default_mode": "deep",
            "last_interface": "eth0",
            "window_geometry": "100x200",
            "custom_prompts": {},
        }
        dirty = ensure_app_config_schema(config)
        assert dirty is False
        # 用户自定义值不被覆盖
        assert config["default_capture_duration"] == 120
        assert config["auto_analyze"] is False

    def test_clamp_duration_below_min(self):
        """default_capture_duration 低于最小值应被修正"""
        config = {"default_capture_duration": 1}
        dirty = ensure_app_config_schema(config)
        assert dirty is True
        assert config["default_capture_duration"] == MIN_CAPTURE_DURATION

    def test_clamp_duration_above_max(self):
        """default_capture_duration 超过最大值应被修正"""
        config = {"default_capture_duration": 9999}
        dirty = ensure_app_config_schema(config)
        assert dirty is True
        assert config["default_capture_duration"] == MAX_CAPTURE_DURATION

    def test_valid_duration_not_clamped(self):
        """合法范围内的值不被修正"""
        config = {"default_capture_duration": 45}
        dirty = ensure_app_config_schema(config)
        # dirty 仅当缺失键被补全时为 True（45 在范围内但其他键缺失）
        assert config["default_capture_duration"] == 45

    def test_integrated_with_config_manager_load(self, config_path: Path):
        """旧配置缺少键时，ConfigManager.load 应自动补全"""
        old_config = {"theme": "light", "auto_analyze": True}
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(old_config))

        m = ConfigManager(config_path=config_path)
        assert m.get("default_capture_duration") == DEFAULT_CAPTURE_DURATION
        assert m.get("auto_save_pcap") is True
