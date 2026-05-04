"""JSON 配置文件管理 — AI 多 provider + 应用设置"""

from __future__ import annotations

import copy
import json
import logging
import os
from pathlib import Path

from app.config.ai_defaults import AI_DEFAULTS
from app.config.provider_loader import load_builtin_provider
from app.config.provider_schema import ensure_provider_schema
from app.utils.path_helpers import atomic_write, get_config_path

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "theme": "dark",
    "default_capture_duration": 60,
    "auto_analyze": True,
    "auto_save_pcap": True,
    "default_mode": "quick",
    "last_interface": "",
    "window_geometry": "",
    # AI 多 provider 配置
    "ai_providers": [],
    "ai_active_provider": "",
}


class ConfigManager:
    """JSON 配置文件管理器"""

    def __init__(self, config_path: Path | None = None):
        self._path = config_path or get_config_path()
        self._config: dict = {}
        self.load()

    def load(self) -> dict:
        """加载配置"""
        if self._path.exists():
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    self._config = json.load(f)
                logger.info(f"配置已加载: {self._path}")
            except json.JSONDecodeError as e:
                backup_path = self._path.with_suffix(".json.corrupt")
                logger.warning(f"配置文件损坏: {e}，备份至 {backup_path}")
                try:
                    import shutil
                    shutil.copy2(str(self._path), str(backup_path))
                except OSError:
                    pass
                self._config = DEFAULT_CONFIG.copy()
                self.save()
            except Exception as e:
                logger.warning(f"配置加载失败，使用默认值: {e}")
                self._config = DEFAULT_CONFIG.copy()
        else:
            self._config = DEFAULT_CONFIG.copy()
            self.save()

        # Provider schema 升级（补全字段、清理旧字段、校验激活项）
        if ensure_provider_schema(self._config):
            self.save()
        return self._config

    def save(self) -> None:
        """保存配置（原子写入）"""
        content = json.dumps(self._config, ensure_ascii=False, indent=2)
        atomic_write(self._path, content)
        logger.info(f"配置已保存: {self._path}")

    def get(self, key: str, default=None):
        return self._config.get(key, default)

    def set(self, key: str, value) -> None:
        self._config[key] = value

    @property
    def config(self) -> dict:
        return self._config.copy()

    # ── AI Provider 管理 ──

    def get_default_provider(self) -> dict:
        """返回内置 provider 配置（深拷贝），无内置时返回空 dict"""
        builtin = load_builtin_provider()
        return copy.deepcopy(builtin) if builtin else {}

    def get_providers(self) -> list[dict]:
        """返回所有 provider 列表（深拷贝）"""
        return copy.deepcopy(self._config.get("ai_providers", []))

    def get_active_provider_name(self) -> str:
        """返回当前激活的 provider 名称"""
        name = self._config.get("ai_active_provider", "")
        if not name:
            providers = self._config.get("ai_providers", [])
            if providers:
                name = providers[0]["name"]
        return name

    def get_ai_config(self) -> dict:
        """获取当前激活 provider 的完整配置

        优先级：环境变量 (PACKETLENS_*) > 激活 provider > AI_DEFAULTS 兜底
        """
        providers = self._config.get("ai_providers", [])
        active_name = self.get_active_provider_name()

        active = None
        for p in providers:
            if p["name"] == active_name:
                active = p
                break

        if not active:
            builtin = load_builtin_provider()
            active = builtin if builtin else {}

        return {
            "provider_type": active.get("provider_type", AI_DEFAULTS["provider_type"]),
            "api_key": os.environ.get("PACKETLENS_API_KEY") or active.get("api_key", ""),
            "base_url": os.environ.get("PACKETLENS_API_BASE") or active.get("api_base", ""),
            "model": os.environ.get("PACKETLENS_MODEL") or active.get("model", ""),
            "context_window_tokens": active.get("context_window_tokens", AI_DEFAULTS["context_window_tokens"]),
            "max_tokens": active.get("max_tokens", AI_DEFAULTS["max_tokens"]),
            "max_input_chars": active.get("max_input_chars", AI_DEFAULTS["max_input_chars"]),
            "temperature": active.get("temperature", AI_DEFAULTS["temperature"]),
            "timeout": active.get("timeout", AI_DEFAULTS["timeout"]),
            "max_concurrency": active.get("max_concurrency", AI_DEFAULTS["max_concurrency"]),
        }

    def set_providers(self, providers: list[dict], active_name: str) -> None:
        """保存 provider 列表和激活项"""
        self._config["ai_providers"] = providers
        self._config["ai_active_provider"] = active_name
