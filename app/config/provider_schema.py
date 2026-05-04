"""Provider Schema 迁移 — 补全字段、清理旧字段名、校验激活项

从 config_manager 中提取的 Provider schema 管理逻辑。
ConfigManager 的 load() 调用 ensure_provider_schema() 完成配置升级。
"""

from __future__ import annotations

import logging

from app.config.ai_defaults import AI_DEFAULTS
from app.config.provider_loader import load_builtin_provider

logger = logging.getLogger(__name__)

# Provider schema 中所有需要补全的默认字段
_PROVIDER_SCHEMA_FIELDS = (
    "provider_type",
    "context_window_tokens",
    "max_tokens",
    "temperature",
    "timeout",
    "max_concurrency",
)

# 需要清理的旧字段名
_DEPRECATED_FIELDS = ("max_output_tokens", "max_input_chars")


def ensure_provider_schema(config: dict) -> bool:
    """确保 config 中的 ai_providers 列表符合当前 schema

    执行以下操作：
    1. 将内置 provider（来自 .env）插入列表头部
    2. 为所有 provider 补全缺失字段
    3. 清理已废弃的旧字段名
    4. 校验 ai_active_provider 指向有效的 provider

    Args:
        config: 完整的配置 dict（就地修改）

    Returns:
        是否有变更需要持久化
    """
    dirty = False
    providers = config.get("ai_providers", [])
    builtin = load_builtin_provider()

    # 1. 插入或更新内置 provider
    if builtin:
        dirty |= _merge_builtin_provider(providers, builtin)
        config["ai_providers"] = providers

    # 2. 为所有 provider 补全缺失字段
    dirty |= _backfill_schema_fields(providers)

    # 3. 清理废弃字段
    dirty |= _remove_deprecated_fields(providers)

    # 4. 校验 active_provider 引用
    dirty |= _validate_active_provider(config, providers)

    return dirty


def _merge_builtin_provider(providers: list[dict], builtin: dict) -> bool:
    """将内置 provider 合并到列表中（按 name 匹配）"""
    dirty = False
    name = builtin["name"]
    found = False
    for p in providers:
        if p["name"] == name:
            if not p.get("is_default"):
                p["is_default"] = True
                dirty = True
            found = True
            break
    if not found:
        import copy
        providers.insert(0, copy.deepcopy(builtin))
        dirty = True
    return dirty


def _backfill_schema_fields(providers: list[dict]) -> bool:
    """为所有 provider 补全 schema 中定义的默认字段"""
    dirty = False
    for p in providers:
        for key in _PROVIDER_SCHEMA_FIELDS:
            if key not in p:
                p[key] = AI_DEFAULTS.get(key, "openai") if key == "provider_type" else AI_DEFAULTS[key]
                dirty = True
    return dirty


def _remove_deprecated_fields(providers: list[dict]) -> bool:
    """清理已废弃的旧字段"""
    dirty = False
    for p in providers:
        for field in _DEPRECATED_FIELDS:
            if field in p:
                p.pop(field, None)
                dirty = True
    return dirty


def _validate_active_provider(config: dict, providers: list[dict]) -> bool:
    """校验 ai_active_provider 是否指向有效 provider"""
    active = config.get("ai_active_provider", "")
    names = {p["name"] for p in providers}
    if not active or active not in names:
        if providers:
            config["ai_active_provider"] = providers[0]["name"]
        else:
            config["ai_active_provider"] = ""
        return True
    return False
